"""Code to verify signatures."""
import hashlib
from binascii import hexlify

import cryptography.exceptions
import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules.rfc2315 import ContentInfo, SignedData, SignerInfo
from pyasn1_modules.rfc3161 import TSTInfo
from pyasn1_modules.rfc3852 import SignedData as CMSSignedData

from winsign.asn1 import (
    SpcIndirectDataContent,
    calc_signerinfo_digest,
    calc_spc_digest,
    id_counterSignature,
    id_messageDigest,
    id_sha1,
    id_sha256,
    id_timestampSignature,
    make_spc,
)
from winsign.pefile import calc_authenticode_digest, calc_checksum, pefile


class VerifyStatus:
    """Object to represent signature verification status."""

    def __init__(self):
        """Create a new VerifyStatus object."""
        self.result = True
        self.results = []

    def __bool__(self):
        """Evaluate this object as a boolean.

        Evaluates as True if all checks have passed
        Evaluates as False if one or more checks have failed.

        """
        return self.result

    def __repr__(self):
        """Return a string representation of the verification status."""
        failing_results = [r for r in self.results if not r[1]]
        return f"<VerifyStatus {self.result}: {failing_results}>"

    def add_result(self, name, value, message):
        """Add a new result to the verificatoin status."""
        self.results.append((name, value, message))
        if not value:
            self.result = False


def strip_pkcs1_padding(b):
    """Removes PKCS1 padding from a byte string.

    e.g. 00 01 FF FF FF FF 00 12 34 -> 12 34

    """
    # Remove leading 00 01 FF .. .. FF 00 from a byte string
    if not b.startswith(b"\x00\x01\xff"):
        raise ValueError("wrong padding")

    for i in range(2, len(b)):
        if b[i] == 0:
            break
        if b[i] != 0xFF:
            raise ValueError("wrong padding")

    return b[i + 1 :]


def verify_signer_info(signer_info, x509_certs_by_serial):
    """Verifies a SignerInfo object from a signature."""
    # Convert into the type of SignerInfo (RFC2315) we support
    signer_info = der_decode(der_encode(signer_info), SignerInfo())[0]

    # RFC 2315 (PKCSv7)
    cert_serial = signer_info["issuerAndSerialNumber"]["serialNumber"]
    issuer = asn1_name_to_cryptography_name(
        signer_info["issuerAndSerialNumber"]["issuer"][""]
    )
    x509_cert = x509_certs_by_serial[issuer, cert_serial]
    pkey = x509_cert.public_key()

    signature = signer_info["encryptedDigest"].asOctets()
    digest_oid = signer_info["digestAlgorithm"]["algorithm"]
    crypto_digest = CRYPTO_DIGEST_BY_OID[digest_oid]
    digest_algo = DIGEST_NAME_BY_OID[digest_oid]
    message = calc_signerinfo_digest(signer_info, digest_algo)

    try:
        pkey.verify(
            signature, message, padding.PKCS1v15(), utils.Prehashed(crypto_digest)
        )
        # GOOD!
        return True, f"{x509_cert.subject}: OK"
    except cryptography.exceptions.InvalidSignature:
        # Failed to verify as a regular signature
        # Try verifying as a bare encrypted digest with PKCS1 padding
        rsa_numbers = pkey.public_numbers()
        rsa_pub_key = rsa.PublicKey(rsa_numbers.n, rsa_numbers.e)
        rsa_keylength = rsa.common.byte_size(rsa_pub_key.n)
        rsa_encrypted = rsa.transform.bytes2int(signature)
        rsa_decrypted = rsa.core.decrypt_int(
            rsa_encrypted, rsa_pub_key.e, rsa_pub_key.n
        )
        rsa_clearsig = rsa.transform.int2bytes(rsa_decrypted, rsa_keylength)
        rsa_clearsig = strip_pkcs1_padding(rsa_clearsig)
        if rsa_clearsig == message:
            return True, f"{x509_cert.subject}: OK"

        return False, f"{x509_cert.subject}: BAD"


def verify_pefile_checksum(f, pe):
    """Verifies the PE file checksum."""
    cur_checksum = pe.optional_header.checksum
    new_checksum = calc_checksum(f, pe.optional_header.checksum_offset)
    if cur_checksum == new_checksum:
        return True, f"Checksum OK: {cur_checksum}"
    else:
        return False, f"Checksums differ: {cur_checksum} != {new_checksum}"


def asn1_name_to_cryptography_name(asn1_name):
    """Convert an ASN1 name to a x509 name."""
    attributes = []
    for rdn in asn1_name:
        oid = x509.ObjectIdentifier(str(rdn[0]["type"]))
        val = str(der_decode(rdn[0]["value"])[0])
        attributes.append(x509.NameAttribute(oid, val))
    return x509.Name(attributes)


def get_x509_certificates(pe):
    """Returns a mapping of (issuer, serial) to x509 certificates."""
    certificates = pe.certificates
    x509_certs_by_serial = {}
    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())
        for cert in signed_data["certificates"]:
            cert = der_encode(cert["certificate"])
            x509_cert = x509.load_der_x509_certificate(cert, default_backend())
            x509_certs_by_serial[x509_cert.issuer, x509_cert.serial_number] = x509_cert

    return x509_certs_by_serial


def get_attribute(attributes, type_):
    """Return the first attribute with the given type from a sequence of attributes."""
    for a in attributes:
        if a["type"] == type_:
            return a["values"]


CRYPTO_DIGEST_BY_OID = {id_sha1: hashes.SHA1(), id_sha256: hashes.SHA256()}

DIGEST_NAME_BY_OID = {id_sha1: "sha1", id_sha256: "sha256"}


def verify_pefile_signature(f, pe):
    """Verifies that the signature in this PE file is valid."""
    # TODO: Check that the message being signed refers to something.
    # e.g. the authenticatedAttributes' digest is our hash
    certificates = pe.certificates
    if not certificates:
        return True, "No certificates present"

    messages = []

    x509_certs_by_serial = get_x509_certificates(pe)

    passed = True
    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())

        spc = der_decode(
            signed_data["contentInfo"]["content"], SpcIndirectDataContent()
        )[0]
        digest_algo_oid = spc["messageDigest"]["digestAlgorithm"]["algorithm"]
        digest_algo = DIGEST_NAME_BY_OID[digest_algo_oid]
        a_digest = calc_authenticode_digest(f, digest_algo)
        e_spc = der_encode(make_spc(digest_algo, a_digest))
        spc_digest = calc_spc_digest(e_spc, digest_algo)

        for info in signed_data["signerInfos"]:
            # Check that the signature is on the right hash
            info_digest = der_decode(
                get_attribute(info["authenticatedAttributes"], id_messageDigest)[0]
            )[0].asOctets()
            if info_digest != spc_digest:
                passed = False
                messages.append(
                    f"Wrong digest: {hexlify(info_digest)} != {hexlify(spc_digest)}"
                )
                continue
            t_passed, message = verify_signer_info(info, x509_certs_by_serial)
            passed = passed and t_passed
            messages.append(message)

    return passed, "\n".join(messages)


def verify_pefile_digest(f, pe):
    """Verifies that the authenticode digest in this PE file is valid."""
    certificates = pe.certificates
    if not certificates:
        return True, "No certificates present"

    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())

        spc = der_decode(
            signed_data["contentInfo"]["content"], SpcIndirectDataContent()
        )[0]
        file_digest = spc["messageDigest"]["digest"].asOctets()
        digest_algo_oid = spc["messageDigest"]["digestAlgorithm"]["algorithm"]
        a_digest = calc_authenticode_digest(f, DIGEST_NAME_BY_OID[digest_algo_oid])

        if file_digest != a_digest:
            return (
                False,
                f"authenticode digests don't match: {hexlify(file_digest)} != {hexlify(a_digest)}",
            )

    return True, "authenticode digests match"


def verify_signed_data(signed_data, x509_certs_by_serial):
    """Verify a SignedData object."""
    # TODO: Handle v1, v3 separately
    # TODO: Use this function everywhere applicable
    passed = True
    messages = []
    for cert in signed_data["certificates"]:
        cert = der_encode(cert["certificate"])
        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
        x509_certs_by_serial[x509_cert.issuer, x509_cert.serial_number] = x509_cert

    for info in signed_data["signerInfos"]:
        i_passed, message = verify_signer_info(info, x509_certs_by_serial)
        passed = passed and i_passed
        messages.append(message)
    return passed, "\n".join(messages)


def verify_pefile_rfc3161_timestamp(f, pe):
    """Verifies that the timestamp in this PE file is valid."""
    certificates = pe.certificates
    if not certificates:
        return True, "No certificates present"

    messages = []

    x509_certs_by_serial = get_x509_certificates(pe)

    passed = True
    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())

        for info in signed_data["signerInfos"]:
            # Check if there are any timestamps in unauthenticatedAttributes
            for a in info["unauthenticatedAttributes"]:
                if a["type"] == id_timestampSignature:  # RFC3161 timestamps
                    # Calculate the hash of our signature
                    # TODO: don't hardcode the digest algorithm
                    digest_algo = DIGEST_NAME_BY_OID[
                        info["digestAlgorithm"]["algorithm"]
                    ]
                    signature_digest = hashlib.new(
                        digest_algo, info["encryptedDigest"].asOctets()
                    ).digest()
                    counter_sig = der_decode(a["values"][0], ContentInfo())[0]
                    counter_sig = der_decode(counter_sig["content"], CMSSignedData())[0]

                    tst_info = der_decode(
                        counter_sig["encapContentInfo"]["eContent"], TSTInfo()
                    )[0]
                    message_digest = tst_info["messageImprint"][
                        "hashedMessage"
                    ].asOctets()
                    if message_digest != signature_digest:
                        passed = False
                        messages.append(
                            f"counter signature is over the wrong data (hash: {hexlify(signature_digest)})"
                        )
                    t_passed, message = verify_signed_data(
                        counter_sig, x509_certs_by_serial
                    )
                    passed = passed and t_passed
                    messages.append(message)

    return passed, "\n".join(messages)


def verify_pefile_old_timestamp(f, pe):
    """Verifies that the timestamp in this PE file is valid."""
    certificates = pe.certificates
    if not certificates:
        return True, "No certificates present"

    messages = []

    x509_certs_by_serial = get_x509_certificates(pe)

    passed = True
    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())

        for info in signed_data["signerInfos"]:
            # Check if there are any timestamps in unauthenticatedAttributes
            for a in info["unauthenticatedAttributes"]:
                if a["type"] == id_counterSignature:  # Old timestamps
                    # Calculate the hash of our signature
                    # These timestamps are always sha1
                    signature_digest = hashlib.new(
                        "sha1", info["encryptedDigest"].asOctets()
                    ).digest()
                    counter_sig = der_decode(a["values"][0], SignerInfo())[0]
                    counter_sig_digest = der_decode(
                        get_attribute(
                            counter_sig["authenticatedAttributes"], id_messageDigest
                        )[0]
                    )[0].asOctets()
                    # Check that the counter signature is of the right data
                    if counter_sig_digest != signature_digest:
                        passed = False
                        messages.append(
                            f"counter signature is over the wrong data (hash: {hexlify(signature_digest)})"
                        )
                    # Check that the timestamp signature itself is valid
                    t_passed, message = verify_signer_info(
                        counter_sig, x509_certs_by_serial
                    )
                    passed = passed and t_passed
                    messages.append(message)

    return passed, "\n".join(messages)


def verify_pefile(f):
    """Verifies the given pefile.

    Arguments:
        f (file object): open pefile. This must be open in binary mode.

    Returns:
        A VerifyStatus object, which evaluates to True if all checks pass, or
        False if one or more checks fail. A list of checks and their statuses
        can be found in the .results attribute.

    """
    retval = VerifyStatus()
    f.seek(0)
    pe = pefile.parse_stream(f)

    # First, check the checksum
    retval.add_result("checksum", *verify_pefile_checksum(f, pe))
    retval.add_result("authenticode_digest", *verify_pefile_digest(f, pe))
    retval.add_result("signature", *verify_pefile_signature(f, pe))
    retval.add_result("timestamp", *verify_pefile_rfc3161_timestamp(f, pe))
    retval.add_result("timestamp", *verify_pefile_old_timestamp(f, pe))

    return retval

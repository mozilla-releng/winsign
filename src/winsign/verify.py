"""
Code to verify signatures
"""
from binascii import hexlify

import cryptography.exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules.rfc2315 import ContentInfo, SignedData, SignerInfo
from pyasn1_modules.rfc3852 import SignedData as CMSSignedData
from winsign.asn1 import (
    SpcIndirectDataContent,
    id_counterSignature,
    id_messageDigest,
    id_sha1,
    id_sha256,
    id_timestampSignature,
)
from winsign.pefile import (
    calc_authenticode_digest,
    calc_checksum,
    get_certificates,
    pefile,
)
from winsign.sign import calc_signer_digest, calc_spc_digest, make_spc


class VerifyStatus:
    def __init__(self):
        self.result = True
        self.results = []

    def __bool__(self):
        return self.result

    def __repr__(self):
        failing_results = [r for r in self.results if not r[1]]
        return f"<VerifyStatus {self.result}: {failing_results}>"

    def add_result(self, name, value, message):
        self.results.append((name, value, message))
        if not value:
            self.result = False


def verify_signer_info(signer_info, x509_certs_by_serial):
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
    message = calc_signer_digest(signer_info, digest_algo)
    try:
        pkey.verify(
            signature, message, padding.PKCS1v15(), utils.Prehashed(crypto_digest)
        )
        # GOOD!
        return True, f"{x509_cert.subject}: OK"
    except cryptography.exceptions.InvalidSignature as exc:
        # BAD :(
        print("BAD!", exc)
        print("message hash is:", hexlify(message))
        print("signature is:", hexlify(signature))
        return False, f"{x509_cert.subject}: BAD"


def verify_pefile_checksum(f, pe):
    cur_checksum = pe.optional_header.checksum
    new_checksum = calc_checksum(f, pe.optional_header.checksum_offset)
    if cur_checksum == new_checksum:
        return True, f"Checksum OK: {cur_checksum}"
    else:
        return False, f"Checksums differ: {cur_checksum} != {new_checksum}"


def asn1_name_to_cryptography_name(asn1_name):
    attributes = []
    for rdn in asn1_name:
        oid = x509.ObjectIdentifier(str(rdn[0]["type"]))
        val = str(der_decode(rdn[0]["value"])[0])
        attributes.append(x509.NameAttribute(oid, val))
    return x509.Name(attributes)


def get_x509_certificates(pe):
    "Returns a mapping of (issuer, serial) to x509 certificates."
    certificates = get_certificates(pe)
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
    for a in attributes:
        if a["type"] == type_:
            return a["values"]


CRYPTO_DIGEST_BY_OID = {id_sha1: hashes.SHA1(), id_sha256: hashes.SHA256()}

DIGEST_NAME_BY_OID = {id_sha1: "sha1", id_sha256: "sha256"}


def verify_pefile_signature(f, pe):
    """Verifies that the signature in this PE file is valid."""
    # TODO: Check that the message being signed refers to something.
    # e.g. the authenticatedAttributes' digest is our hash
    certificates = get_certificates(pe)
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
    certificates = get_certificates(pe)
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
    certificates = get_certificates(pe)
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
                    val, _ = der_decode(a["values"][0], ContentInfo())
                    val = der_decode(val["content"], CMSSignedData())[0]
                    t_passed, message = verify_signed_data(val, x509_certs_by_serial)
                    passed = passed and t_passed
                    messages.append(message)

    return passed, "\n".join(messages)


def verify_pefile_old_timestamp(f, pe):
    """Verifies that the timestamp in this PE file is valid."""
    certificates = get_certificates(pe)
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
                    val = der_decode(a["values"][0], SignerInfo())[0]
                    t_passed, message = verify_signer_info(val, x509_certs_by_serial)
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
    # retval.add_result("timestamp", *verify_pefile_old_timestamp(f, pe))

    return retval

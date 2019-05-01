"""
Code to verify signatures
"""
import cryptography.exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1_modules.rfc2315 import ContentInfo, SignedData
from winsign.asn1 import id_sha1, id_sha256
from winsign.pefile import calc_checksum, get_certificates, pefile
from winsign.sign import calc_signer_hash


class VerifyStatus:
    def __init__(self):
        self.result = True
        self.results = []

    def __bool__(self):
        return self.result

    def __repr__(self):
        return f"<VerifyStatus {self.result}: {self.results}>"

    def add_result(self, name, value, message):
        self.results.append((name, value, message))
        if not value:
            self.result = False


def verify_pefile_checksum(f, pe):
    cur_checksum = pe.optional_header.checksum
    new_checksum = calc_checksum(f, pe.optional_header.checksum_offset)
    if cur_checksum == new_checksum:
        return True, f"Checksum OK: {cur_checksum}"
    else:
        return False, f"Checksums differ: {cur_checksum} != {new_checksum}"


def asn1_name_to_cryptography_name(asn1_name):
    attributes = []
    for rdn in asn1_name[""]:
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


CRYPTO_DIGEST_BY_OID = {id_sha1: hashes.SHA1(), id_sha256: hashes.SHA256()}

DIGEST_NAME_BY_OID = {id_sha1: "sha1", id_sha256: "sha256"}


# TODO: Factor out useful parts of this function
def verify_pefile_signature(f, pe):
    """Verifies that the signature in this PE file is valid."""
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
            cert_serial = info["issuerAndSerialNumber"]["serialNumber"]
            issuer = asn1_name_to_cryptography_name(
                info["issuerAndSerialNumber"]["issuer"]
            )
            x509_cert = x509_certs_by_serial[issuer, cert_serial]
            pkey = x509_cert.public_key()

            signature = info["encryptedDigest"].asOctets()
            digest_oid = info["digestAlgorithm"]["algorithm"]
            crypto_digest = CRYPTO_DIGEST_BY_OID[digest_oid]
            digest_algo = DIGEST_NAME_BY_OID[digest_oid]
            message = calc_signer_hash(info, digest_algo)
            try:
                pkey.verify(
                    signature,
                    message,
                    padding.PKCS1v15(),
                    utils.Prehashed(crypto_digest),
                )
                # GOOD!
                messages.append(f"{x509_cert.subject}: OK")
            except cryptography.exceptions.InvalidSignature:
                # BAD :(
                messages.append(f"{x509_cert.subject}: BAD")
                passed = False

    return passed, "\n".join(messages)


def verify_pefile_timestamp(f, pe):
    """Verifies that the timestamp in this PE file is valid."""
    certificates = get_certificates(pe)
    if not certificates:
        return True, "No certificates present"

    messages = []

    # x509_certs_by_serial = get_x509_certificates(pe)

    passed = True
    for pe_cert in certificates:
        content_info, _ = der_decode(pe_cert.data, ContentInfo())
        signed_data, _ = der_decode(content_info["content"], SignedData())

        for info in signed_data["signerInfos"]:
            info
            pass

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
    retval.add_result("signature", *verify_pefile_signature(f, pe))

    return retval

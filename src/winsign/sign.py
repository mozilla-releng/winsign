"""
Create signatures for Authenticode files
"""
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import tag, univ, useful
from pyasn1_modules.rfc2315 import (
    Attribute,
    ContentInfo,
    ExtendedCertificateOrCertificate,
    SignedData,
    SignerInfo,
)
from winsign.asn1 import (
    ASN_DIGEST_ALGO_MAP,
    SpcIndirectDataContent,
    SpcSpOpusInfo,
    der_header_length,
    id_contentType,
    id_individualCodeSigning,
    id_messageDigest,
    id_rsaEncryption,
    id_signedData,
    id_signingTime,
    id_spcIndirectDataContext,
    id_spcSpOpusInfo,
    id_spcStatementType,
)
from winsign.pkcs7 import x509_to_pkcs7
from winsign.timestamp import get_old_timestamp, get_rfc3161_timestamp


def calc_spc_hash(encoded_content, digest_algo):
    hlen = der_header_length(encoded_content)
    digest = hashlib.new(digest_algo, encoded_content[hlen:]).digest()
    return digest


def make_spc(digest_algo, authenticode_digest):
    spc = SpcIndirectDataContent()
    spc["data"]["type"] = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.15")
    spc["data"]["value"]["flags"] = ""
    spc["data"]["value"]["file"]["file"]["unicode"] = "<<<Obsolete>>>"
    spc["messageDigest"]["digestAlgorithm"] = ASN_DIGEST_ALGO_MAP[digest_algo]
    spc["messageDigest"]["digest"] = authenticode_digest
    return spc


def make_signer_info(
    pkcs7_cert, digest_algo, timestamp, spc_hash, opus_info=None, opus_url=None
):
    signer_info = SignerInfo()
    signer_info["version"] = 1
    signer_info["issuerAndSerialNumber"]["issuer"] = pkcs7_cert["tbsCertificate"][
        "issuer"
    ]
    signer_info["issuerAndSerialNumber"]["serialNumber"] = pkcs7_cert["tbsCertificate"][
        "serialNumber"
    ]
    signer_info["digestAlgorithm"] = ASN_DIGEST_ALGO_MAP[digest_algo]
    signer_info["digestEncryptionAlgorithm"]["algorithm"] = id_rsaEncryption
    signer_info["digestEncryptionAlgorithm"]["parameters"] = univ.Null("")
    signer_info["authenticatedAttributes"][0]["type"] = id_contentType
    signer_info["authenticatedAttributes"][0]["values"][0] = id_spcIndirectDataContext
    signer_info["authenticatedAttributes"][1]["type"] = id_signingTime
    signer_info["authenticatedAttributes"][1]["values"][0] = timestamp
    signer_info["authenticatedAttributes"][2]["type"] = id_spcStatementType
    signer_info["authenticatedAttributes"][2]["values"][0] = univ.Sequence()
    signer_info["authenticatedAttributes"][2]["values"][0][0] = id_individualCodeSigning
    i = 3
    if opus_info or opus_url:
        opus = SpcSpOpusInfo()
        if opus_info:
            opus["programName"]["ascii"] = opus_info
        if opus_url:
            opus["moreInfo"]["url"] = opus_url
        signer_info["authenticatedAttributes"][3]["type"] = id_spcSpOpusInfo
        signer_info["authenticatedAttributes"][3]["values"][0] = opus
        i = 4

    signer_info["authenticatedAttributes"][i]["type"] = id_messageDigest
    signer_info["authenticatedAttributes"][i]["values"][0] = univ.OctetString(spc_hash)
    return signer_info


def calc_signer_hash(signer_info, digest_algo):
    auth_attrs = univ.SetOf(componentType=Attribute())
    for i, v in enumerate(signer_info["authenticatedAttributes"]):
        auth_attrs[i] = v
    auth_attrs_encoded = der_encode(auth_attrs)

    return hashlib.new(digest_algo, auth_attrs_encoded).digest()


def sign_signer_hash(priv_key, digest_algo, signer_hash):
    crypto_digest = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[  # nosec
        digest_algo
    ]
    signature = priv_key.sign(
        signer_hash, padding.PKCS1v15(), utils.Prehashed(crypto_digest)
    )
    return signature


def get_authenticode_signature(
    cert,
    priv_key,
    authenticode_digest,
    digest_algo,
    timestamp=None,
    opus_info=None,
    opus_url=None,
):
    """
    Creates a SignedData object containing the signature for content using the
    given certificate and private key.

    Arguments:
        cert (X509):        public certificate used for signing
        priv_key (RSA):     private key corresponding to the certificate
        authenticode_digest (bytes): Authenticode digest of PE file to sign
                                     NB. This is not simply the hash of the file!
        timestamp (UTCTime): optional. timestamp to include in the signature.
                             If not provided, the current time is used.
        opus_info (string):  Additional information to include in the signature
        opus_url (string):   URL to include in the signature

    Returns:
        A ContentInfo ASN1 object
    """
    if not timestamp:
        timestamp = useful.UTCTime.fromDateTime(datetime.now())

    asn_digest_algo = ASN_DIGEST_ALGO_MAP[digest_algo]

    spc = make_spc(digest_algo, authenticode_digest)

    encoded_spc = der_encode(spc)

    pkcs7_cert = x509_to_pkcs7(cert)

    signer_info = make_signer_info(
        pkcs7_cert, digest_algo, timestamp, calc_spc_hash(encoded_spc, digest_algo)
    )

    signer_hash = calc_signer_hash(signer_info, digest_algo)
    signer_info["encryptedDigest"] = sign_signer_hash(
        priv_key, digest_algo, signer_hash
    )

    sig = SignedData()
    sig["version"] = 1
    sig["digestAlgorithms"][0] = asn_digest_algo
    sig["certificates"][0]["certificate"] = pkcs7_cert
    sig["contentInfo"]["contentType"] = id_spcIndirectDataContext
    sig["contentInfo"]["content"] = encoded_spc
    sig["signerInfos"][0] = signer_info

    ci = ContentInfo()
    ci["contentType"] = id_signedData
    ci["content"] = sig

    return ci


def add_rfc3161_timestamp(sig, digest_algo, timestamp_url=None):
    """
    Adds an RFC3161 timestamp to a SignedData signature

    Arguments:
        sig (SignedData): signature to add timestamp
        digest_algo (str): digest algorithm to use ('sha1' or 'sha256')
        timestamp_url (str): URL to fetch timestamp from. A default is used if
                             None is set.

    Returns:
        sig with the timestamp added
    """
    signature = der_encode(sig["signerInfos"][0]["encryptedDigest"])
    ts = get_rfc3161_timestamp(digest_algo, signature, timestamp_url)
    i = len(sig["signerInfos"][0]["unauthenticatedAttributes"])
    sig["signerInfos"][0]["unauthenticatedAttributes"][i][
        "type"
    ] = univ.ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")
    sig["signerInfos"][0]["unauthenticatedAttributes"][i]["values"][0] = ts
    return sig


def add_old_timestamp(sig, timestamp_url=None):
    """
    Adds an old style timestamp to a SignedData signature

    Arguments:
        sig (SignedData): signature to add timestamp
        timestamp_url (str): URL to fetch timestamp from. A default is used if
                             None is set.

    Returns:
        sig with the timestamp added
    """
    signature = der_encode(sig["signerInfos"][0]["encryptedDigest"])
    ts = get_old_timestamp(signature, timestamp_url)
    # Use SequenceOf here to force the order to what we want
    # Assuming this should be in the order of the validity
    # TODO: Not sure if this is correct, but seems to work
    certificates = univ.SequenceOf(ExtendedCertificateOrCertificate()).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )
    certificates.extend(sig["certificates"])
    for cert in sorted(
        ts["certificates"],
        key=lambda c: c["certificate"]["tbsCertificate"]["validity"]["notBefore"],
    ):
        certificates.append(cert)
    sig["certificates"] = certificates

    i = len(sig["signerInfos"][0]["unauthenticatedAttributes"])
    sig["signerInfos"][0]["unauthenticatedAttributes"][i][
        "type"
    ] = univ.ObjectIdentifier("1.2.840.113549.1.9.6")
    sig["signerInfos"][0]["unauthenticatedAttributes"][i]["values"][0] = ts[
        "signerInfos"
    ][0]

    return sig


def get_signatures_from_certificates(certificates):
    retval = []
    for cert in certificates:
        ci, _ = der_decode(cert["data"], ContentInfo())
        signed_data, _ = der_decode(ci["content"], SignedData())
        spc, _ = der_decode(
            signed_data["contentInfo"]["content"], SpcIndirectDataContent()
        )
        signed_data["contentInfo"]["content"] = spc
        retval.append(signed_data)
    return retval

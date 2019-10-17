"""ASN.1 structures and methods specific for windows signing."""
import hashlib
import logging
from binascii import hexlify
from datetime import datetime

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import char, namedtype, namedval, tag, univ, useful
from pyasn1_modules.rfc2315 import (
    Attribute,
    Certificate,
    ContentInfo,
    DigestAlgorithmIdentifier,
    DigestInfo,
    SignedData,
    SignerInfo,
    TBSCertificate,
)

log = logging.getLogger(__name__)

id_contentType = univ.ObjectIdentifier("1.2.840.113549.1.9.3")
id_counterSignature = univ.ObjectIdentifier("1.2.840.113549.1.9.6")
id_individualCodeSigning = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.21")
id_messageDigest = univ.ObjectIdentifier("1.2.840.113549.1.9.4")
id_rsaEncryption = univ.ObjectIdentifier("1.2.840.113549.1.1.1")
id_sha1 = univ.ObjectIdentifier("1.3.14.3.2.26")
id_sha256 = univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
id_signedData = univ.ObjectIdentifier("1.2.840.113549.1.7.2")
id_signingTime = univ.ObjectIdentifier("1.2.840.113549.1.9.5")
id_spcIndirectDataContext = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.4")
id_spcSpOpusInfo = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.12")
id_spcStatementType = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.11")
id_timestampSignature = univ.ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")


algo_sha1 = (
    DigestAlgorithmIdentifier()
    .setComponentByName("algorithm", id_sha1)
    .setComponentByName("parameters", univ.Null(""))
)

algo_sha256 = (
    DigestAlgorithmIdentifier()
    .setComponentByName("algorithm", id_sha256)
    .setComponentByName("parameters", univ.Null(""))
)

ASN_DIGEST_ALGO_MAP = {"sha1": algo_sha1, "sha256": algo_sha256}


class SpcString(univ.Choice):
    """SPC String class represetning unicode or ascii strings."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "unicode",
            char.BMPString(encoding="utf-16-be").subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "ascii",
            char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class SpcLink(univ.Choice):
    """SPC Link class for holding references to URLs or files."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "url",
            char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "moniker",
            univ.Any().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
        namedtype.NamedType(
            "file",
            SpcString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            ),
        ),
    )


class SpcSpOpusInfo(univ.Sequence):
    """SPC Information class for holding additional information about a signature."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "programName",
            SpcString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "moreInfo",
            SpcLink().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
    )


class SpcPeImageFlags(univ.BitString):
    """SPC PE Image Flags."""

    namedValues = namedval.NamedValues(
        ("includeResources", 0),
        ("includeDebugInfo", 1),
        ("includeImportAddressTable", 2),
    )


class SpcPeImageData(univ.Sequence):
    """SPC PE Image Data."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("flags", SpcPeImageFlags()),
        namedtype.OptionalNamedType(
            "file",
            SpcLink().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
    )


class SpcAttributeTypeAndOptionalValue(univ.Sequence):
    """SPC type/value attributes."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("value", SpcPeImageData()),
    )


class SpcIndirectDataContent(univ.Sequence):
    """SPC Indirect Data Content."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("data", SpcAttributeTypeAndOptionalValue()),
        namedtype.NamedType("messageDigest", DigestInfo()),
    )


def calc_signerinfo_digest(signer_info, digest_algo):
    """Calcuate the digest of authenticatedAttributes.

    Args:
        signer_info (SignerInfo object): object with authenticatedAttributes
                                         over which we will calculate the digest.
        digest_algo (str): digest algorithm to use. e.g. 'sha256'

    Returns:
        digest as a byte string

    """
    auth_attrs = univ.SetOf(componentType=Attribute())
    for i, v in enumerate(signer_info["authenticatedAttributes"]):
        auth_attrs[i] = v
    auth_attrs_encoded = der_encode(auth_attrs)

    return hashlib.new(digest_algo, auth_attrs_encoded).digest()


def x509_to_pkcs7(cert):
    """Convert an x509 certificate to a PKCS7 TBSCertificate.

    Args:
        cert (x509 object): x509 certificate to convert

    Returns:
        TBSCertificate that represents the same x509 cert

    """
    tbsCert, _ = der_decode(cert.tbs_certificate_bytes, TBSCertificate())
    retval = Certificate()
    retval["tbsCertificate"] = tbsCert
    retval["signatureAlgorithm"][
        "algorithm"
    ] = cert.signature_algorithm_oid.dotted_string
    retval["signatureAlgorithm"]["parameters"] = univ.Null("")
    retval["signatureValue"] = univ.BitString.fromHexString(hexlify(cert.signature))
    return retval


def copy_signer_info(old_si, pkcs7_cert):
    """Copy SignerInfo object, replacing the certificate information.

    Args:
        old_si (SignerInfo object): original SignerInfo to copy
        pkcs7_cert (TBSCertificate object): certificate to inject

    Returns:
        New SignerInfo object.

    """
    si = SignerInfo()
    si["authenticatedAttributes"] = old_si["authenticatedAttributes"]
    si["version"] = old_si["version"]
    si["digestAlgorithm"] = old_si["digestAlgorithm"]
    si["digestEncryptionAlgorithm"] = old_si["digestEncryptionAlgorithm"]

    si["issuerAndSerialNumber"]["issuer"] = pkcs7_cert["tbsCertificate"]["issuer"]
    si["issuerAndSerialNumber"]["serialNumber"] = pkcs7_cert["tbsCertificate"][
        "serialNumber"
    ]
    return si


def get_signeddata(s):
    """Gets the SignedData from an encoded ContentInfo object."""
    ci = der_decode(s, ContentInfo())[0]
    sd = der_decode(ci["content"], SignedData())[0]
    return sd


def get_signatures_from_certificates(certificates):
    """Retrieve the signatures from a list of certificates."""
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


async def resign(old_sig, certs, signer):
    """Resigns an old signature with a new certificate.

    Replaces the encrypted signature digest in the given signature with new one
    generated with the given signer function.

    Args:
        old_sig (SignedData): the original signature as a SignedData object
        certs (list of x509 certificates): certificates to attach to the new signature
        signer (function): function to call to generate the new encrypted
                           digest. The function is passed two arguments: (signer_digest,
                           digest_algo)

    Returns:
        ContentInfo object with the new signature embedded

    """
    new_sig = SignedData()
    new_sig["version"] = old_sig["version"]
    new_sig["contentInfo"] = old_sig["contentInfo"]

    new_sig["digestAlgorithms"] = old_sig["digestAlgorithms"]

    for i, cert in enumerate(certs):
        pkcs7_cert = x509_to_pkcs7(cert)
        new_sig["certificates"][i]["certificate"] = pkcs7_cert

    new_si = copy_signer_info(
        old_sig["signerInfos"][0], new_sig["certificates"][0]["certificate"]
    )
    if new_si["digestAlgorithm"]["algorithm"] == id_sha1:
        digest_algo = "sha1"
    elif new_si["digestAlgorithm"]["algorithm"] == id_sha256:
        digest_algo = "sha256"
    signer_digest = calc_signerinfo_digest(new_si, digest_algo)
    log.debug("Digest to sign is: %s", hexlify(signer_digest))
    new_si["encryptedDigest"] = await signer(signer_digest, digest_algo)
    new_sig["signerInfos"][0] = new_si

    ci = ContentInfo()
    ci["contentType"] = id_signedData
    ci["content"] = new_sig
    sig = der_encode(ci)

    return sig


def der_header_length(encoded):
    """Returns the length of the header of a DER encoded object.

    Arguments:
        encoded (bytes): DER encoded bytestring

    Returns:
        length (int)

    """
    hlen = 1
    i = 0
    tag = encoded[i]
    # If the tag isn't universal, it may take more than one byte
    if tag & 0b11000000 != 0 and tag & 0b11111 == 0b11111:
        hlen += 1
        i += 1
        while encoded[i] & 0b10000000:
            hlen += 1
            i += 1

    length = encoded[i]
    hlen += 1
    if length & 0b10000000:
        hlen += int(length & 0b01111111)

    return hlen


def calc_spc_digest(encoded_content, digest_algo):
    """Calculate the digest of an encoded SPC object."""
    hlen = der_header_length(encoded_content)
    digest = hashlib.new(digest_algo, encoded_content[hlen:]).digest()
    return digest


def make_spc(digest_algo, authenticode_digest):
    """Create a new SPC object."""
    spc = SpcIndirectDataContent()
    spc["data"]["type"] = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.15")
    spc["data"]["value"]["flags"] = ""
    spc["data"]["value"]["file"]["file"]["unicode"] = "<<<Obsolete>>>"
    spc["messageDigest"]["digestAlgorithm"] = ASN_DIGEST_ALGO_MAP[digest_algo]
    spc["messageDigest"]["digest"] = authenticode_digest
    return spc


def make_signer_info(
    pkcs7_cert, digest_algo, timestamp, spc_digest, opus_info=None, opus_url=None
):
    """Create a SignerInfo object representing an Authenticode signature."""
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
    signer_info["authenticatedAttributes"][i]["values"][0] = univ.OctetString(
        spc_digest
    )
    return signer_info


async def make_authenticode_signeddata(
    cert,
    signer,
    authenticode_digest,
    digest_algo,
    timestamp=None,
    opus_info=None,
    opus_url=None,
):
    """Creates a SignedData object containing the signature for a PE file.

    Arguments:
        cert (X509):        public certificate used for signing
        signer (function):  signing function
        authenticode_digest (bytes): Authenticode digest of PE file to sign
                                     NB. This is not simply the hash of the file!
        digest_algo (str): digest algorithm to use. e.g. 'sha256'
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
        pkcs7_cert, digest_algo, timestamp, calc_spc_digest(encoded_spc, digest_algo)
    )

    signer_digest = calc_signerinfo_digest(signer_info, digest_algo)
    signer_info["encryptedDigest"] = await signer(signer_digest, digest_algo)

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

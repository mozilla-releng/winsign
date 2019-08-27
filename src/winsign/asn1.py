import hashlib
import logging
from binascii import hexlify

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import char, namedtype, namedval, tag, univ
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

id_sha1 = univ.ObjectIdentifier("1.3.14.3.2.26")
id_sha256 = univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
id_signedData = univ.ObjectIdentifier("1.2.840.113549.1.7.2")
id_timestampSignature = univ.ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")
id_counterSignature = univ.ObjectIdentifier("1.2.840.113549.1.9.6")


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
    namedValues = namedval.NamedValues(
        ("includeResources", 0),
        ("includeDebugInfo", 1),
        ("includeImportAddressTable", 2),
    )


class SpcPeImageData(univ.Sequence):
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
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("value", SpcPeImageData()),
    )


class SpcIndirectDataContent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("data", SpcAttributeTypeAndOptionalValue()),
        namedtype.NamedType("messageDigest", DigestInfo()),
    )


def calc_signerinfo_digest(signer_info, digest_algo):
    auth_attrs = univ.SetOf(componentType=Attribute())
    for i, v in enumerate(signer_info["authenticatedAttributes"]):
        auth_attrs[i] = v
    auth_attrs_encoded = der_encode(auth_attrs)

    return hashlib.new(digest_algo, auth_attrs_encoded).digest()


def x509_to_pkcs7(cert):
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
    """Gets the SignedData from an encoded ContentInfo object"""
    ci = der_decode(s, ContentInfo())[0]
    sd = der_decode(ci["content"], SignedData())[0]
    return sd


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


def resign(old_sig, certs, signer):
    """
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
    new_si["encryptedDigest"] = signer(signer_digest, digest_algo)
    new_sig["signerInfos"][0] = new_si

    ci = ContentInfo()
    ci["contentType"] = id_signedData
    ci["content"] = new_sig
    sig = der_encode(ci)

    return sig

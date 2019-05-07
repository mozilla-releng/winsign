from pyasn1.type import char, namedtype, namedval, tag, univ
from pyasn1_modules.rfc2315 import DigestAlgorithmIdentifier, DigestInfo

id_sha1 = univ.ObjectIdentifier("1.3.14.3.2.26")
algo_sha1 = (
    DigestAlgorithmIdentifier()
    .setComponentByName("algorithm", id_sha1)
    .setComponentByName("parameters", univ.Null(""))
)

id_sha256 = univ.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
algo_sha256 = (
    DigestAlgorithmIdentifier()
    .setComponentByName("algorithm", id_sha256)
    .setComponentByName("parameters", univ.Null(""))
)

ASN_DIGEST_ALGO_MAP = {"sha1": algo_sha1, "sha256": algo_sha256}

id_contentType = univ.ObjectIdentifier("1.2.840.113549.1.9.3")
id_messageDigest = univ.ObjectIdentifier("1.2.840.113549.1.9.4")
id_signingTime = univ.ObjectIdentifier("1.2.840.113549.1.9.5")
id_counterSignature = univ.ObjectIdentifier("1.2.840.113549.1.9.6")
id_spcIndirectDataContext = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.4")
id_spcStatementType = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.11")
id_individualCodeSigning = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.21")
id_signedData = univ.ObjectIdentifier("1.2.840.113549.1.7.2")
id_spcSpOpusInfo = univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.12")
id_rsaEncryption = univ.ObjectIdentifier("1.2.840.113549.1.1.1")
id_timestampSignature = univ.ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")


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


class SpcContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "contentType", univ.ObjectIdentifier("1.3.6.1.4.1.311.2.1.4")
        ),
        namedtype.OptionalNamedType(
            "spc",
            SpcIndirectDataContent().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
    )


def der_header_length(encoded):
    """
    Returns the length of the header of a DER encoded object.

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

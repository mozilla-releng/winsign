#!/usr/bin/env python
import base64
import hashlib

import requests
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, tag, univ
from pyasn1_modules.rfc2315 import (
    ContentInfo,
    DigestInfo,
    ExtendedCertificateOrCertificate,
    SignedData,
)
from pyasn1_modules.rfc4210 import PKIStatusInfo
from winsign.asn1 import ASN_DIGEST_ALGO_MAP, id_counterSignature, id_timestampSignature


class TSAPolicyId(univ.ObjectIdentifier):
    pass


class TimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer(1)),
        namedtype.NamedType("messageImprint", DigestInfo()),
        namedtype.OptionalNamedType("reqPolicy", TSAPolicyId()),
        namedtype.OptionalNamedType("nonce", univ.Integer()),
        namedtype.NamedType("certReq", univ.Boolean(False)),
        namedtype.OptionalNamedType(
            "extensions",
            univ.Any().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
    )


class TimeStampResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("status", PKIStatusInfo()),
        namedtype.OptionalNamedType("timeStampToken", univ.Any()),
    )


# For old style timestamps
class OldTimeStampReqBlob(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier("1.2.840.113549.1.7.1")),
        namedtype.OptionalNamedType(
            "signature",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
    )


class OldTimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier("1.3.6.1.4.1.311.3.2.1")),
        namedtype.NamedType("blob", OldTimeStampReqBlob()),
    )


def get_rfc3161_timestamp(digest_algo, message, timestamp_url=None):
    asn_digest_algo = ASN_DIGEST_ALGO_MAP[digest_algo]
    req = TimeStampReq()
    req["messageImprint"]["digestAlgorithm"] = asn_digest_algo
    req["messageImprint"]["digest"] = hashlib.new(digest_algo, message).digest()
    encoded_req = der_encode(req)

    url = timestamp_url or "http://timestamp.digicert.com"

    resp = requests.post(
        url, data=encoded_req, headers={"Content-Type": "application/timestamp-query"}
    )
    ts, _ = der_decode(resp.content, TimeStampResp())
    if ts["status"]["status"] != 0:
        raise IOError("Failed to get timestamp: {}".format(ts["status"]))

    return der_encode(ts["timeStampToken"])


def get_old_timestamp(signature, timestamp_url=None):
    req = OldTimeStampReq()
    req["blob"]["signature"] = signature
    encoded_req = der_encode(req)
    b64_req = base64.b64encode(encoded_req)

    url = timestamp_url or "http://timestamp.digicert.com"

    resp = requests.post(
        url, data=b64_req, headers={"Content-Type": "application/octet-stream"}
    )
    ci, _ = der_decode(base64.b64decode(resp.content), ContentInfo())
    ts, _ = der_decode(ci["content"], SignedData())
    return ts


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
    ] = id_timestampSignature
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
    sig["signerInfos"][0]["unauthenticatedAttributes"][i]["type"] = id_counterSignature
    sig["signerInfos"][0]["unauthenticatedAttributes"][i]["values"][0] = ts[
        "signerInfos"
    ][0]

    return sig

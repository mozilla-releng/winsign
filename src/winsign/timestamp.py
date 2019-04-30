#!/usr/bin/env python
import base64
import hashlib

import requests
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, tag, univ
from pyasn1_modules.rfc2315 import ContentInfo, DigestInfo, SignedData
from pyasn1_modules.rfc4210 import PKIStatusInfo
from winsign.asn1 import ASN_DIGEST_ALGO_MAP


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
    # url = "http://timestamp.digicert.com"

    resp = requests.post(
        url, data=b64_req, headers={"Content-Type": "application/octet-stream"}
    )
    # sig = hexlify(signature)
    # open(f"ts-old-{sig[:10]}.dat", "wb").write(resp.content)
    ci, _ = der_decode(base64.b64decode(resp.content), ContentInfo())
    ts, _ = der_decode(ci["content"], SignedData())
    return ts

"""Timestamp functions for windows signing."""
import base64
import hashlib

import aiohttp
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, tag, univ
from pyasn1_modules.rfc2315 import (
    ContentInfo,
    ExtendedCertificateOrCertificate,
    SignedData,
)
from pyasn1_modules.rfc3161 import TimeStampReq, TimeStampResp

from winsign.asn1 import ASN_DIGEST_ALGO_MAP, id_counterSignature, id_timestampSignature


# For old style timestamps
class OldTimeStampReqBlob(univ.Sequence):
    """Old style Timestamp request blob."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType(
            "signature",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
    )


class OldTimeStampReq(univ.Sequence):
    """Old style Timestamp request."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("blob", OldTimeStampReqBlob()),
    )


async def get_rfc3161_timestamp(digest_algo, message, timestamp_url=None):
    """Retrieve an RFC3161 timestamp countersignature.

    Args:
        digest_algo (str): digest algorithm to use. e.g. 'sha1' or 'sha256'
        message (str): the message to get a counter signature for. This is
                       usally the encryptedDigest of our file's signerInfo section.
        timestamp_url (str): what service to use to fetch the timestamp countersignature from.
                             defaults to 'http://timestamp.digicert.com'.

    Returns:
        DER encoded timestamp token

    """
    asn_digest_algo = ASN_DIGEST_ALGO_MAP[digest_algo]
    req = TimeStampReq()
    req["version"] = 1
    req["messageImprint"]["hashAlgorithm"] = asn_digest_algo
    req["messageImprint"]["hashedMessage"] = hashlib.new(digest_algo, message).digest()
    req["certReq"] = True
    encoded_req = der_encode(req)

    url = timestamp_url or "http://timestamp.digicert.com"

    async with aiohttp.request(
        "POST",
        url,
        data=encoded_req,
        headers={"Content-Type": "application/timestamp-query"},
    ) as resp:
        # Uncomment below to capture a real response
        # open('new-ts.dat', 'wb').write(resp.content)
        ts, _ = der_decode(await resp.read(), TimeStampResp())
        if ts["status"]["status"] != 0:
            raise IOError("Failed to get timestamp: {}".format(ts["status"]))

        return der_encode(ts["timeStampToken"])


async def get_old_timestamp(signature, timestamp_url=None):
    """Retrieve an old style timestamp countersignature.

    Args:
        signature (str): the signature to get a counter signature for. This is
                         usally the encryptedDigest of our file's signerInfo section.
        timestamp_url (str): what service to use to fetch the timestamp countersignature from.
                             defaults to 'http://timestamp.digicert.com'.

    Returns:
        SignedData object

    """
    req = OldTimeStampReq()
    req["type"] = univ.ObjectIdentifier("1.3.6.1.4.1.311.3.2.1")
    req["blob"]["signature"] = signature
    req["blob"]["type"] = univ.ObjectIdentifier("1.2.840.113549.1.7.1")

    encoded_req = der_encode(req)
    b64_req = base64.b64encode(encoded_req)

    url = timestamp_url or "http://timestamp.digicert.com"

    async with aiohttp.request(
        "POST", url, data=b64_req, headers={"Content-Type": "application/octet-stream"}
    ) as resp:
        # Uncomment below to capture a real response
        # open('old-ts.dat', 'wb').write(resp.content)
        ci, _ = der_decode(base64.b64decode(await resp.read()), ContentInfo())
        ts, _ = der_decode(ci["content"], SignedData())
        return ts


async def add_rfc3161_timestamp(sig, digest_algo, timestamp_url=None):
    """Adds an RFC3161 timestamp to a SignedData signature.

    Arguments:
        sig (SignedData): signature to add timestamp
        digest_algo (str): digest algorithm to use ('sha1' or 'sha256')
        timestamp_url (str): URL to fetch timestamp from. A default is used if
                             None is set.

    Returns:
        sig with the timestamp added

    """
    signature = sig["signerInfos"][0]["encryptedDigest"].asOctets()
    ts = await get_rfc3161_timestamp(digest_algo, signature, timestamp_url)
    i = len(sig["signerInfos"][0]["unauthenticatedAttributes"])
    sig["signerInfos"][0]["unauthenticatedAttributes"][i][
        "type"
    ] = id_timestampSignature
    sig["signerInfos"][0]["unauthenticatedAttributes"][i]["values"][0] = ts
    return sig


async def add_old_timestamp(sig, timestamp_url=None):
    """Adds an old style timestamp to a SignedData signature.

    Arguments:
        sig (SignedData): signature to add timestamp
        timestamp_url (str): URL to fetch timestamp from. A default is used if
                             None is set.

    Returns:
        sig with the timestamp added

    """
    signature = sig["signerInfos"][0]["encryptedDigest"].asOctets()
    ts = await get_old_timestamp(signature, timestamp_url)
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

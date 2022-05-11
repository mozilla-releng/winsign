"""Timestamp functions for windows signing."""
import base64
import hashlib
import io

import aiohttp
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import namedtype, tag, univ
from pyasn1_modules.pem import readPemFromFile
from pyasn1_modules.rfc2315 import (
    ContentInfo,
    DigestInfo,
    ExtendedCertificateOrCertificate,
    SignedData,
)
from pyasn1_modules.rfc5280 import id_at_commonName, X520CommonName
from pyasn1_modules.rfc4210 import PKIStatusInfo
from winsign.asn1 import ASN_DIGEST_ALGO_MAP, id_counterSignature, id_timestampSignature


class TSAPolicyId(univ.ObjectIdentifier):
    """TSA Policy Id."""

    pass


class TimeStampReq(univ.Sequence):
    """RFC3161 Timestamp Request."""

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
    """RFC3161 Timestamp Response."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("status", PKIStatusInfo()),
        namedtype.OptionalNamedType("timeStampToken", univ.Any()),
    )


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
    req["messageImprint"]["digestAlgorithm"] = asn_digest_algo
    req["messageImprint"]["digest"] = hashlib.new(digest_algo, message).digest()
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
        # XXX hack
        if url == "http://timestamp.digicert.com":
            # If the returned timestamp signature only chains up to "DigiCert
            # Trusted Root G4", add the "DigiCert Global Root CA" cross-sign
            # for win7's benefit
            for cert in ts["certificates"]:
                issuer = cert["certificate"]["tbsCertificate"]["issuer"]
                cn = [rdn[0]["value"] for rdn in issuer[0] if rdn[0]["type"] == id_at_commonName][0]
                if str(der_decode(cn, X520CommonName())[0].getComponent()) == "DigiCert Global Root CA":
                    break
            else:
                chain_length = len(ts["certificates"])
                crosscert_der = readPemFromFile(io.StringIO(digicert_cross_sign))
                ts["certificates"].append(der_decode(crosscert_der, ExtendedCertificateOrCertificate())[0])
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


digicert_cross_sign = """\
-----BEGIN CERTIFICATE-----
MIIFqTCCBJGgAwIBAgIQAmpTRVzHABL6I856gPheRzANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0xMzA3MDExMjAwMDBaFw0yMzEwMjIxMjAwMDBaMGIxCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK
2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/G
nhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJ
IB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4M
K7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN
2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I
11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KIS
G2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9
HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4
pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpy
FiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS31
2amyHeUbAgMBAAGjggFaMIIBVjASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB
/wQEAwIBhjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
LmRpZ2ljZXJ0LmNvbTB7BgNVHR8EdDByMDegNaAzhjFodHRwOi8vY3JsNC5kaWdp
Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290Q0EuY3JsMDegNaAzhjFodHRwOi8v
Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290Q0EuY3JsMD0GA1Ud
IAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
dC5jb20vQ1BTMB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSME
GDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3RVTANBgkqhkiG9w0BAQsFAAOCAQEATX3N
y6uAw4zUl+/AucL89ywo2jUgqiSUZxRK5rHg/OBvM9q9kh99ZJSVlUpxw7s3G6Iv
OcFh1yCvwkYhzOnHpVlJ2jZA+MuIjufnAr7jJMj7iw0HiW9Jair1lplPO9z6JSL/
ifT+C2xl9gkv9bwG2j0u/BLGvLJApOFj/S/HoVg33gQJeqFZwmZER4sxGCcj26xx
JvjZsepf4cP2U2n+CQZoA1M5rbuprg/8SgAmgINP7Yl7GRe/TlyUOKsx9klkn9Uy
6QGeHZIvoQ1dylT6hXwWeiagZGPE1wlpHs+8ah7WhSG0a+P1sn0QSopUfZyV59Ow
Sx2Q1FL4934+qkh0Hg==
-----END CERTIFICATE-----
"""

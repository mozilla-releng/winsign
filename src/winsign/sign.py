#!/usr/bin/env python
"""Functions for signing PE and MSI files."""
import logging
from binascii import hexlify
from pathlib import Path

import winsign.makemsix
import winsign.timestamp
from winsign.asn1 import (
    ContentInfo,
    SignedData,
    der_decode,
    der_encode,
    get_signeddata,
    id_signedData,
    resign,
)
from winsign.crypto import load_pem_certs, sign_signer_digest
from winsign.osslsigncode import get_dummy_signature, write_signature

log = logging.getLogger(__name__)


def key_signer(priv_key):
    """Create a signer function that signs with a private key.

    Args:
        priv_key (key object): A
            `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` instance

    Returns:
        A signer function with signature
        `signer(digest: bytes, digest_algo: str) -> bytes`

    """
    # noqa:D202

    async def signer(digest, digest_algo):
        log.debug(
            "signing %s with %s",
            hexlify(digest),
            priv_key.public_key().public_numbers(),
        )
        return sign_signer_digest(priv_key, digest_algo, digest)

    return signer


async def sign_file(
    infile,
    outfile,
    digest_algo,
    certs,
    signer,
    cafile=None,
    timestampfile=None,
    url=None,
    comment=None,
    crosscert=None,
    timestamp_style=None,
    timestamp_url=None,
):
    """Sign a PE or MSI file.

    Args:
        infile (str): Path to the unsigned file
        outfile (str): Path to where the signed file will be written
        digest_algo (str): Which digest algorithm to use. Generally 'sha1' or 'sha256'
        certs (list of x509 certificates): certificates to attach to the new signature
        cafile (str): path to cafile of the cert we use to sign
        timestampfile (str): path to the ca for verifying the timestamp
        signer (function): Function that takes (digest, digest_algo) and
                           returns bytes of the signature. Normally this will
                           be using a private key object to sign the digest.
        url (str): A URL to embed into the signature
        comment (str): A string to embed into the signature
        crosscert (str): Extra certificates to attach to the signature
        timestamp_style (str): What kind of signed timestamp to include in the
                               signature. Can be None, 'old', or 'rfc3161'.
        timestamp_url (str): URL for the timestamp server to use. Required if
                             timestamp_style is set.


    Returns:
        True on success
        False otherwise

    """
    infile = Path(infile)
    outfile = Path(outfile)

    is_msix = winsign.makemsix.is_msixfile(infile)
    if not is_msix and (cafile is None or not Path(cafile).is_file()):
        log.error(
            "CAfile is required while writing signatures for non msix files, expected path to file, found '%s'"
            % cafile
        )
        return False

    try:
        log.debug("Generating dummy signature")
        if is_msix:
            old_sig = winsign.makemsix.dummy_sign(infile, outfile)
        else:
            old_sig = get_dummy_signature(
                infile, digest_algo, url=url, comment=comment, crosscert=crosscert
            )
    except OSError:
        log.error("Couldn't generate dummy signature")
        log.debug("Exception:", exc_info=True)
        return False

    try:
        log.debug("Re-signing with real keys")
        old_sig = get_signeddata(old_sig)
        if crosscert:
            crosscert = Path(crosscert)
            certs.extend(load_pem_certs(crosscert.read_bytes()))
        newsig = await resign(old_sig, certs, signer)
    except Exception:
        log.error("Couldn't re-sign")
        log.debug("Exception:", exc_info=True)
        return False

    if timestamp_style == "old":
        ci = der_decode(newsig, ContentInfo())[0]
        sig = der_decode(ci["content"], SignedData())[0]
        sig = await winsign.timestamp.add_old_timestamp(sig, timestamp_url)
        ci = ContentInfo()
        ci["contentType"] = id_signedData
        ci["content"] = sig
        newsig = der_encode(ci)
    elif timestamp_style == "rfc3161":
        ci = der_decode(newsig, ContentInfo())[0]
        sig = der_decode(ci["content"], SignedData())[0]
        sig = await winsign.timestamp.add_rfc3161_timestamp(
            sig, digest_algo, timestamp_url
        )
        ci = ContentInfo()
        ci["contentType"] = id_signedData
        ci["content"] = sig
        newsig = der_encode(ci)

    try:
        log.debug("Attaching new signature")
        if is_msix:
            winsign.makemsix.attach_signature(outfile, outfile, newsig)
        else:
            write_signature(infile, outfile, newsig, certs, cafile, timestampfile)
    except Exception:
        log.error("Couldn't write new signature")
        log.error("Exception:", exc_info=True)
        return False

    log.debug("Done!")
    return True

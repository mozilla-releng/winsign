#!/usr/bin/env python
"""Functions for signing PE and MSI files."""
import logging
from binascii import hexlify

from winsign.crypto import sign_signer_digest
from winsign.osslsigncode import sign_file as ossl_sign_file
from winsign.pefile import is_pefile
from winsign.pefile import sign_file as pe_sign_file

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

    def signer(digest, digest_algo):
        log.debug(
            "signing %s with %s",
            hexlify(digest),
            priv_key.public_key().public_numbers(),
        )
        return sign_signer_digest(priv_key, digest_algo, digest)

    return signer


def sign_file(
    infile,
    outfile,
    digest_algo,
    certs,
    signer,
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
        certs (str): Path to where the PEM encoded public certificate(s) are located
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
    args = (
        infile,
        outfile,
        digest_algo,
        certs,
        signer,
        url,
        comment,
        crosscert,
        timestamp_style,
        timestamp_url,
    )
    if is_pefile(infile):
        return pe_sign_file(*args)
    else:
        return ossl_sign_file(*args)

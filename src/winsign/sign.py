#!/usr/bin/env python
"""Functions for signing PE and MSI files."""
import logging
import os
import subprocess
import sys
import tempfile
from argparse import ArgumentParser
from binascii import hexlify
from pathlib import Path

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
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.pefile import certificate, is_pefile

log = logging.getLogger(__name__)

# These dummy key/cert are used to generate the initial signature for the file
DUMMY_KEY = """\
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUc78I6NKAGZlH8eD4Y1DumwxxzaIwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKRHVtbXkgQ2VydDAeFw0xOTA1MjMxNTE5NDNaFw0xOTA2
MjIxNTE5NDNaMBUxEzARBgNVBAMMCkR1bW15IENlcnQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDmC1Doj8oLID1YcQqPfB6nD3tr+43QcFKH21QBV3yV
fVKv5ztDh52EpP6SLpYlvyzlR1nmdJLxdbxVswyDb+t+qO3GTlKqkoqegjEhU6k0
aOYWx+1wfqJUAMLpHtn51vf461pwTHwSybQ/NEAKkG9ySDAcCVFfz22MRGP8utMO
GRONWEV2M854+FRrLUgolp48TUXf5B1PhBLhJ5AvnFph4vqfQ6NefJ6RznhBo/EV
yBPxYC686DA17bV/QEeTIiJnSXndQSN8WmkufyHZBbnd4e9pTVf40BXZXZOQ93s1
LO2vc16Vn+Ezvuia5LNrtbD242VKOTLY90mgdLGJDO9nAgMBAAGjUzBRMB0GA1Ud
DgQWBBQlhnJSTTtjwyEw0fOszPTIyuNFDTAfBgNVHSMEGDAWgBQlhnJSTTtjwyEw
0fOszPTIyuNFDTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAU
DxAoaNnRvBV0HaI7i4s5Cqpu8vgeM4tZ7cRvhqFnyVa2GLpoZBXYgQwjcAYEHysD
urMydnVzye6sHprXCaxLBAGLR5dy8CcrLGlg4vxvReVE8xoyjnoS7gfFdTNLaWq2
Wc6zCcsC5Z6RvSOjO3SyOCRTu3ghB6Qgr16tOIqAAGg1+fPzfl1uaErJDQL3LHbR
IYyhSISW9MZzkbXT6mpM0n2XVgd7tfPj6S3leLJ8/acSC/Xa8vcQNEXtCRmqClPh
KLoTWf6E+RRiUuj5D8XvKbBB/qiIe7UpgtjDsmsmyxBtd8tMpSBZ5Yz7mm4ozGVq
qy0UlC6klwFznbr8uZgd
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDmC1Doj8oLID1Y
cQqPfB6nD3tr+43QcFKH21QBV3yVfVKv5ztDh52EpP6SLpYlvyzlR1nmdJLxdbxV
swyDb+t+qO3GTlKqkoqegjEhU6k0aOYWx+1wfqJUAMLpHtn51vf461pwTHwSybQ/
NEAKkG9ySDAcCVFfz22MRGP8utMOGRONWEV2M854+FRrLUgolp48TUXf5B1PhBLh
J5AvnFph4vqfQ6NefJ6RznhBo/EVyBPxYC686DA17bV/QEeTIiJnSXndQSN8Wmku
fyHZBbnd4e9pTVf40BXZXZOQ93s1LO2vc16Vn+Ezvuia5LNrtbD242VKOTLY90mg
dLGJDO9nAgMBAAECggEAbEmzYmYdU7NvbSx5LiXdQALXtHMLxKy7DNy/5InMSYpe
3BLbIOS7z27jruhjIY2mkp9NwF/rs+IaL7VDFLQghNT8aLcBzu2AdzEN84QwSE2A
0gR2ztetjiF1nss5DJSW0gPn5Kj8VtPAF2h/JPnsnD1C+E+ikJlSFg8zigpfw2hC
BCzAIuawESMOsX49O7hQO1Xbqoettl1s2v4oLg5zSEx6RvGqAv94vQM4Pc8vIouI
HDRG/OrjwSyAKymWfCepNRvDf9ooXLaMBb4J+DilBj3pyzzZ84QBI0uIaS6SFtOD
zvaSh+1z0lsqseItmFjCcYnVLvzU4+dEBYGvaDrA0QKBgQD0PPXHrXCKo+mPOgQS
I4RsqzoYkNyJG2tlElpVY+QJCNvalpnDiI3X1x0LhVrT8U/PaHcRnxMzceGqXVkY
CJ27AKh1iS43zUnqhl4PK2TQ1sBMtrkHE9FBgVF74b15UvXSAVxxYT2qP6t9aCSk
G4+tYszIrmcH9qGJcuNN9UKXxQKBgQDxH159MIzN1UOdX2QSkfZDIO6bUsCtTATe
iA8slmPybTHKL27ut5lGDZe02uTpz9sLVD80xevzhWS1BC5N6ilHNso8xqzVjbbz
bUcZCFKuUaQ/yjUTZtRnT6kUpDLLQNF3XxIeKPLnioOrFfb7U508d/SABda/x/7A
uCJNLD5xOwKBgGX1mOkt14CZIuSe5Jop55tx88PTna1DHBdKjRl+pPC8mQNswW4m
cIh9jeuEVUGLSLUeOC7MCLj+PqXfaFUnK6mogarnhLrY4ZWdWGDezax9KjQcR6vT
sxS0hq6/s1iVsHdmCBBw9sw+3jlxI3K66sUILNNOM0bYx+DYbFncHFu9AoGBAMfY
hgogqTMYZTgUDe9ORtuQefMGfWeksAx4nIsKAsC1PCUldz4nscPcFDbzjfM0MYqM
Qu7MdCmcD8HwOyicwaWihbAlwq4lDNNpaRoYSd7tD8NHJwJzoewWnD7dcLQBfxr/
ExcoPVsm9MZiKBhaTuIFUgKh1EGT01OLyfJIj2BtAoGAQ4JZZjJ/ZOEidqElUedQ
ChqoRX3PwdCMJ4ZkyxD/QAyS09fgw02DAL1qTVKcZjQnI7XREicC9okFcV7lAVuE
yMGb5aH9Nsuq8ucPf2JTyZ0CXwcxnaw5zZKaUXzf4Dr3BvDrYZ23ptiDi8pOH0kV
Iq4ITEtYW5tfl1hf8AyEmz0=
-----END PRIVATE KEY-----
"""


def osslsigncode(args, log_errors=True):
    """Run a command using `osslsigncode`.

    Example:
        >>> osslsigncode(["verify", "signed.exe"])

    Args:
        args (list): List of command arguments to pass to osslsigncode
        log_errors (bool): Whether errors should be logged. Defaults to True

    Returns:
        None on success.

    Raises:
        OSError: osslsigncode returned with non-zero status. Errors are logged
                 via log.error

    """
    cmd = ["osslsigncode"] + list(args)
    log.debug("running: %s", cmd)
    p = subprocess.run(
        cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, encoding="utf8"
    )
    if p.returncode != 0:
        if log_errors:
            log.error("osslsigncode failed when running %s:", args[0])
            for line in p.stdout.split("\n"):
                log.error(line)
        raise OSError("osslsigncode failed")


def run_sign_command(
    infile,
    outfile,
    cert,
    key,
    digest_algo,
    url=None,
    comment=None,
    crosscert=None,
    timestamp_style=None,
    timestamp_url=None,
):
    """Sign a file using osslsigncode.

    Args:
        infile (str): Path to the unsigned file
        outfile (str): Path to where the signed file will be written
        cert (str): Path to where the PEM encoded public certificate(s) are located
        key (str): Path to where the PEM encoded private key is located
        digest_algo (str): Which digest algorithm to use. Generally 'sha1' or 'sha256'
        url (str): A URL to embed into the signature
        comment (str): A string to embed into the signature
        crosscert (str): Extra certificates to attach to the signature
        timestamp_style (str): What kind of signed timestamp to include in the
                               signature. Can be None, 'old', or 'rfc3161'.
        timestamp_url (str): URL for the timestamp server to use. Required if
                             timestamp_style is set.

    Returns:
        Same as `winsign.sign.osslsigncode`_

    """
    cmd = [
        "sign",
        "-certs",
        cert,
        "-key",
        key,
        "-h",
        digest_algo,
        "-in",
        infile,
        "-out",
        outfile,
    ]
    if url:
        cmd += ["-i", url]
    if comment:
        cmd += ["-n", comment]
    if crosscert:
        cmd += ["-ac", crosscert]
    if timestamp_style == "old":
        cmd += ["-t", timestamp_url]
    elif timestamp_style == "rfc3161":
        cmd += ["-ts", timestamp_url]

    osslsigncode(cmd)


def extract_signature(infile, sigfile):
    """Extract a signature from a PE or MSI file.

    The signature is extracted as a DER encoded ASN.1 stucture.

    Args:
        infile (str): Path to file to extract the signature from
        sigfile (str): Path to file where signature will be written to.

    Returns:
        Same as `winsign.sign.osslsigncode`_

    """
    cmd = ["extract-signature", "-in", infile, "-out", sigfile]
    osslsigncode(cmd)


def is_signed(filename):
    """Determine if a file is signed or not.

    Args:
        filename (str): Path to file to check

    Returns:
        True if the file is signed
        False otherwise

    """
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            cmd = [
                "extract-signature",
                "-in",
                filename,
                "-out",
                os.path.join(tmpdir, "sig.out"),
            ]
            osslsigncode(cmd, log_errors=False)
            return True
        except OSError:
            return False


def get_dummy_signature(infile, digest_algo, url=None, comment=None, crosscert=None):
    """Sign a file using dummy keys.

    This is useful as a way to get the structure of a signature, without having
    to create it from scratch. The dummy signature will also include relevent
    Authenticode specific checksums.

    Args:
        infile (str): Path to the file to generate a dummy signature for
        digest_algo (str): What digest algorithm to use. Should be one of
                           'sha1', or 'sha256'
        url (str): A URL to embed into the signature
        comment (str): A string to embed into the signature
        crosscert (str): Extra certificates to attach to the signature

    Returns:
        bytes of the dummy signature as a DER encoded ASN.1 structure

    """
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        cert_file = d / "cert.pem"
        cert_file.write_text(DUMMY_KEY)
        infile = Path(infile)
        dest = d / ("signed1" + infile.suffix)
        run_sign_command(
            infile,
            dest,
            cert_file,
            cert_file,
            digest_algo,
            url=url,
            comment=comment,
            crosscert=crosscert,
        )
        sig = d / "signature"
        extract_signature(dest, sig)
        if is_pefile(infile):
            pefile_cert = certificate.parse(sig.read_bytes())
            return pefile_cert.data
        else:
            return sig.read_bytes()


def write_signature(infile, outfile, sig):
    """Writes a signature into a file.

    Args:
        infile (str): Path to the unsigned file
        outfile (str): Path to write the signature into
        sig (str): bytes of signature to add into the file

    Returns:
        Same as `winsign.sign.osslsigncode`_

    """
    # PE files need their signatures encapsulated
    if is_pefile(infile):
        padlen = (8 - len(sig) % 8) % 8
        sig += b"\x00" * padlen
        cert = certificate.build(
            {"size": len(sig) + 8, "revision": "REV2", "certtype": "PKCS7", "data": sig}
        )
    else:
        cert = sig
    with tempfile.NamedTemporaryFile() as sigfile:
        sigfile.write(cert)
        sigfile.flush()
        cmd = [
            "attach-signature",
            "-sigin",
            sigfile.name,
            "-in",
            infile,
            "-out",
            outfile,
        ]
        osslsigncode(cmd)


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
    infile = Path(infile)
    outfile = Path(outfile)
    try:
        log.debug("Generating dummy signature")
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
        newsig = resign(old_sig, certs, signer)
    except Exception:
        log.error("Couldn't re-sign")
        log.debug("Exception:", exc_info=True)
        return False

    if timestamp_style == "old":
        ci = der_decode(newsig, ContentInfo())[0]
        sig = der_decode(ci["content"], SignedData())[0]
        sig = winsign.timestamp.add_old_timestamp(sig, timestamp_url)
        ci = ContentInfo()
        ci["contentType"] = id_signedData
        ci["content"] = sig
        newsig = der_encode(ci)
    elif timestamp_style == "rfc3161":
        ci = der_decode(newsig, ContentInfo())[0]
        sig = der_decode(ci["content"], SignedData())[0]
        sig = winsign.timestamp.add_rfc3161_timestamp(sig, digest_algo, timestamp_url)
        ci = ContentInfo()
        ci["contentType"] = id_signedData
        ci["content"] = sig
        newsig = der_encode(ci)

    try:
        log.debug("Attaching new signature")
        write_signature(infile, outfile, newsig)
    except Exception:
        log.error("Couldn't write new signature")
        log.debug("Exception:", exc_info=True)
        return False

    log.debug("Done!")
    return True


def build_parser():
    """Create our CLI ArgumentParser."""
    parser = ArgumentParser()
    parser.add_argument("infile", help="unsigned file to sign")
    parser.add_argument(
        "outfile",
        help="where to write output to. defaults to infile",
        default=None,
        nargs="?",
    )
    parser.add_argument(
        "--certs",
        dest="certs",
        help="certificates to include in the signature",
        required=True,
    )
    parser.add_argument(
        "--key", dest="priv_key", help="private key used to sign", required=True
    )
    parser.add_argument("-n", dest="comment", help="comment to include in signature")
    parser.add_argument("-i", dest="url", help="url to include in signature")
    parser.add_argument(
        "-d",
        dest="digest_algo",
        help="digest to use for signing. must be one of sha1 or sha256",
        choices=["sha1", "sha256"],
        required=True,
    )
    parser.add_argument("-t", dest="timestamp", choices=["old", "rfc3161"])
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    parser.add_argument(
        "-q", "--quiet", dest="loglevel", action="store_const", const=logging.WARNING
    )
    return parser


def _copy_stream(instream, outstream):
    while True:
        block = instream.read(1024 ** 2)
        if not block:
            break
        outstream.write(block)


def main(argv=None):
    """Main CLI entry point for signing."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(format="%(asctime)s - %(message)s", level=args.loglevel)

    if not args.priv_key:
        if not (args.autograph_user and args.autograph_secret):
            parser.error(
                "--key, or all of --autograph-url, --autograph-user, and "
                "--autograph-secret must be specified"
            )

    if not args.outfile:
        args.outfile = args.infile

    certs = []
    certs_data = open(args.certs, "rb").read()
    certs = load_pem_certs(certs_data)
    priv_key = load_private_key(open(args.priv_key, "rb").read())

    signer = key_signer(priv_key)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        if args.infile == "-":
            args.infile = d / "unsigned"
            with args.infile.open("wb") as f:
                _copy_stream(sys.stdin.buffer, f)
        else:
            args.infile = Path(args.infile)

        if args.outfile == "-":
            outfile = d / "signed"
        else:
            outfile = Path(args.outfile)

        r = sign_file(
            args.infile,
            outfile,
            args.digest_algo,
            certs,
            signer,
            url=args.url,
            comment=args.comment,
            timestamp_style=args.timestamp,
        )

        # TODO: Extra cross-cert
        # TODO: Check with a cert chain
        if not r:
            return 1

        if args.outfile == "-":
            with outfile.open("rb") as f:
                _copy_stream(f, sys.stdout.buffer)

        return 0

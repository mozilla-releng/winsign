"""Functions for using osslsigncode utility for signing."""
import logging
import os
import subprocess
import tempfile
from pathlib import Path

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


def write_signature(infile, outfile, sig, certs, cafile, timestampfile):
    """Writes a signature into a file.

    Args:
        infile (str): Path to the unsigned file
        outfile (str): Path to write the signature into
        sig (str): bytes of signature to add into the file
        certs (list of x509 certificates): certificates to attach to the new signature
        cafile (str): path to the corresponding cafile to match the cert
        timestampfile (str): path to the ca bundle for validating the timestamp

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

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        sigfile = d / "sigfile"
        with open(sigfile, "wb") as sf:
            sf.write(cert)

        cmd = [
            "attach-signature",
            "-sigin",
            sigfile,
            "-CAfile",
            cafile,
            "-untrusted",
            timestampfile,
            "-in",
            infile,
            "-out",
            outfile,
        ]

        osslsigncode(cmd)

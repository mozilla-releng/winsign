"""Functions for using the makemsix utility for signing."""
import base64
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile

log = logging.getLogger(__name__)

# This dummy key/cert is used to initially sign the package.
# makemsx needs a pfx, so this was converted from osslsigncode.DUMMY_KEY with:
#   openssl pkcs12 -export -in DUMMY_KEY.pem -keypbe NONE -certpbe NONE -nomaciter | base64 --wrap=64 > DUMMY_KEY.pfx.b64
DUMMY_KEY = """\
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
1nPgq/9LxJMXSNfIhQQIxcKo5utbX70=
"""


def makemsix(args, log_errors=True):
    """Run a command using `makemsix`.

    Example:
        >>> makemsix(["sign", "-p", "x.msix", "-c" "cert.pfx"])

    Args:
        args (list): List of command arguments to pass to makemsix
        log_errors (bool): Whether errors should be logged. Defaults to True

    Returns:
        None on success.

    Raises:
        OSError: makemsix returned with non-zero status. Errors are logged
                 via log.error

    """
    cmd = ["makemsix"] + list(args)
    log.debug("running: %s", cmd)
    p = subprocess.run(
        cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, encoding="utf8"
    )
    if p.returncode != 0:
        if log_errors:
            log.error("makemsix failed when running %s:", args[0])
            for line in p.stdout.split("\n"):
                log.error(line)
        raise OSError("makemsix failed")


def run_sign_command(infile, outfile, pfxfile):
    """Sign a file using makemsix.

    Args:
        infile (str or Path): Path to the file to sign (overwritten in place if
                              it is the same as outfile)
        outfile (str or Path): Path to where the signed file will be written
        pfxfile (str or Path): Path to the PCKS#12 file containing the certificate and signing key

    """
    # makemsix modifies files in place, so first copy input to output
    try:
        shutil.copyfile(infile, outfile)
    except shutil.SameFileError:
        pass

    cmd = ["sign", "-p", outfile, "-c", pfxfile, "-cf", "pfx"]

    makemsix(cmd)


def get_signature(infile):
    """Extract a signature from a file.

    Args:
        infile (str or Path): Path to file to extract the signature from

    Returns:
        bytes of the signature

    """
    in_zip = ZipFile(infile)
    pkcx = in_zip.read("AppxSignature.p7x")

    if pkcx[0:4] != b"PKCX":
        log.error("Signature is missing PKCX magic")
        raise ValueError("Signature is missing PKCX magic")

    return pkcx[4:]


def dummy_sign(infile, outfile):
    """Sign a file using a dummy key.

    This is useful to get the signature structure and the digest, which
    can later be re-signed and re-attached with `attach_signature`.

    Args:
        infile (str or Path): Path to the file to sign (overwritten in place if
                              it is the same as outfile)
        outfile (str or Path): Path to the output signed file

    Returns:
        bytes of the dummy PKCS#7 signature

    """
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        cert_file = d / "cert.pfx"
        cert_file.write_bytes(base64.b64decode(DUMMY_KEY))
        run_sign_command(infile, outfile, cert_file)

    return get_signature(outfile)


def attach_signature(infile, outfile, sig):
    """Writes a new signature into an already signed file.

    Args:
        infile (str or Path): Path to the file whose signature is to be
                             replacedb (overwritten in place if it is
                             the same as outfile)
        outfile (str or Path): Path to the output signed file
        sig (bytes): bytes of the PKCS#7 signature to write

    """
    # makemsix modifies files in place, so first copy input to output
    try:
        shutil.copyfile(infile, outfile)
    except shutil.SameFileError:
        pass

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        pkcx_file = d / "AppxSignature.p7x"
        pkcx_file.write_bytes(b"PKCX" + sig)

        cmd = ["attach", "-p", outfile, "-s", pkcx_file]

        makemsix(cmd)


def is_msixfile(filename):
    """Determine if a file is likely MSIX/Appx.

    This simply checks that the file is a Zip and contains AppxManifest.xml.

    Args:
        filename (str or Path): path to the file to check

    Returns:
        True if the file appears to be a PE file
        False otherwise

    """
    try:
        in_zip = ZipFile(filename)
        in_zip.read("AppxManifest.xml")
        return True
    except Exception:
        return False

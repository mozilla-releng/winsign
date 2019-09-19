"""Test osslsigncode integration."""
import subprocess

import pytest
from common import DATA_DIR, TEST_MSI_FILES, have_osslsigncode
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.osslsigncode import is_signed, sign_file

# Skip testing this module if we don't have osslsigncode.
# None of the signing functions will work
if not have_osslsigncode():
    pytest.skip(
        "skipping tests that require osslsigncode to run", allow_module_level=True
    )


def osslsigncode_verify(filename, substr=b""):
    """Run osslsigncode verify on the file.

    Args:
        filename (str): path on disk to verify
        substr (bytes): substring to look for in the output

    Returns:
        False is MISMATCH!!! is found in the output, or if substr is specified
        and not found in the output.
        True otherwise

    """
    proc = subprocess.run(
        ["osslsigncode", "verify", filename],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if b"MISMATCH!!!" in proc.stdout:
        return False
    if substr and substr not in proc.stdout:
        return False
    return proc.returncode == 0


@pytest.mark.parametrize("test_file", TEST_MSI_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_sign_file(test_file, digest_algo, tmp_path, signing_keys):
    """Check that we can sign with the osslsign wrapper."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(test_file, signed_exe, digest_algo, certs, signer)


@pytest.mark.parametrize(
    "test_file, file_is_signed",
    (
        ("unsigned.exe", False),
        ("signed.exe", True),
        ("unsigned.msi", False),
        ("cert.pem", False),
    ),
)
def test_is_signed(test_file, file_is_signed, caplog):
    """Test that we can properly determine if files are signed or not."""
    assert is_signed(DATA_DIR / test_file) == file_is_signed

    if not file_is_signed:
        assert "osslsigncode failed" not in caplog.text

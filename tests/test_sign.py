import subprocess

import pytest
from common import DATA_DIR, TEST_MSI_FILES, TEST_PE_FILES
from winsign.asn1 import get_signatures_from_certificates
from winsign.crypto import load_pem_cert, load_private_key, sign_signer_digest
from winsign.pefile import is_pefile, pefile
from winsign.sign import winsign


def have_osslsigncode():
    try:
        subprocess.run(["osslsigncode", "--version"])
        return True
    except OSError:
        return False


if not have_osslsigncode():
    pytest.skip(
        "skipping tests that require osslsigncode to run", allow_module_level=True
    )


def osslsigncode_verify(filename, substr=b""):
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


def get_certificates(f):
    pe = pefile.parse_stream(f)
    return pe.certificates


@pytest.mark.parametrize("test_file", TEST_PE_FILES + TEST_MSI_FILES)
def test_osslsign_winsign(test_file, tmp_path, signing_keys):
    """
    Check that we can sign with the osslsign wrapper
    """
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    cert = load_pem_cert(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert winsign(test_file, signed_exe, "sha1", cert, signer)

    # Check that we have 1 certificate in the signature
    if is_pefile(test_file):
        with signed_exe.open("rb") as f:
            certificates = get_certificates(f)
            sigs = get_signatures_from_certificates(certificates)
            assert len(certificates) == 1
            assert len(sigs) == 1
            assert len(sigs[0]["certificates"]) == 1


def test_osslsign_winsign_dummy(tmp_path, signing_keys):
    """
    Check that we can sign with an additional dummy certificate for use by the
    stub installer
    """
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    cert = load_pem_cert(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert winsign(
        test_file, signed_exe, "sha1", cert, signer, crosscert=signing_keys[1]
    )

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2

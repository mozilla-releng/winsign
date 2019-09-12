"""Tests specific to signing functionality."""
import subprocess
from functools import wraps
from pathlib import Path
from unittest import mock

import pytest
import winsign.asn1
from common import DATA_DIR, TEST_MSI_FILES, TEST_PE_FILES
from winsign.asn1 import (
    get_signatures_from_certificates,
    id_signingTime,
    id_timestampSignature,
)
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.pefile import get_certificates, is_pefile
from winsign.sign import is_signed, sign_file
from winsign.verify import verify_pefile


def use_fixed_signing_time(f):
    """Decorator that injects a hardcoded signing time into signatures.

    Args:
        f (func): function to wrap

    """
    orig_resign = winsign.asn1.resign

    def wrapped_resign(old_sig, certs, signer):
        # Inject a fixed signing time into old_sig
        for info in old_sig["signerInfos"]:
            for attr in info["authenticatedAttributes"]:
                if attr["type"] == id_signingTime:
                    attr["values"][0] = b"\x17\r190912061110Z"
        return orig_resign(old_sig, certs, signer)

    @wraps(f)
    def wrapper(*args, **kwargs):
        with mock.patch("winsign.sign.resign", wrapped_resign):
            return f(*args, **kwargs)

    return wrapper


def have_osslsigncode():
    """Check if osslsigncode is executable."""
    try:
        subprocess.run(["osslsigncode", "--version"])
        return True
    except OSError:
        return False


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


@pytest.mark.parametrize("test_file", TEST_PE_FILES + TEST_MSI_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_sign_file(test_file, digest_algo, tmp_path, signing_keys):
    """Check that we can sign with the osslsign wrapper."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(test_file, signed_exe, digest_algo, certs, signer)

    # Check that we have 1 certificate in the signature
    if test_file in TEST_PE_FILES:
        assert is_pefile(test_file)
        with signed_exe.open("rb") as f:
            certificates = get_certificates(f)
            sigs = get_signatures_from_certificates(certificates)
            assert len(certificates) == 1
            assert len(sigs) == 1
            assert len(sigs[0]["certificates"]) == 1

            assert verify_pefile(f)


def test_sign_file_dummy(tmp_path, signing_keys):
    """Check that we can sign with an additional dummy certificate.

    The extra dummy certs are used by the stub installer.
    """
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(
        test_file, signed_exe, "sha1", certs, signer, crosscert=signing_keys[1]
    )

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2


def test_sign_file_twocerts(tmp_path, signing_keys):
    """Check that we can include multiple certificates."""
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(open(DATA_DIR / "twocerts.pem", "rb").read())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(test_file, signed_exe, "sha1", certs, signer)

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2


def test_sign_file_badfile(tmp_path, signing_keys):
    """Verify that we can't sign non-exe files."""
    test_file = Path(__file__)
    signed_file = tmp_path / "signed.py"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert not sign_file(test_file, signed_file, "sha1", certs, signer)


@pytest.mark.parametrize("test_file", [DATA_DIR / "unsigned.exe"])
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
@use_fixed_signing_time
def test_timestamp_old(test_file, digest_algo, tmp_path, signing_keys, httpserver):
    """Verify that we can sign with old style timestamps."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-old.dat").read_bytes()
    )
    assert sign_file(
        test_file,
        signed_exe,
        digest_algo,
        certs,
        signer,
        timestamp_style="old",
        # Comment this out to use a real timestamp server so that we can
        # capture a response
        timestamp_url=httpserver.url,
    )

    # Check that we have 3 certificates in the signature
    if is_pefile(test_file):
        with signed_exe.open("rb") as f:
            certificates = get_certificates(f)
            sigs = get_signatures_from_certificates(certificates)
            assert len(certificates) == 1
            assert len(sigs) == 1
            assert len(sigs[0]["certificates"]) == 3

            assert verify_pefile(f)


@pytest.mark.parametrize("test_file", [DATA_DIR / "unsigned.exe"])
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
@use_fixed_signing_time
def test_timestamp_rfc3161(test_file, digest_algo, tmp_path, signing_keys, httpserver):
    """Verify that we can sign with RFC3161 timestamps."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-rfc3161.dat").read_bytes()
    )
    assert sign_file(
        test_file,
        signed_exe,
        digest_algo,
        certs,
        signer,
        timestamp_style="rfc3161",
        # Comment this out to use a real timestamp server so that we can
        # capture a response
        timestamp_url=httpserver.url,
    )

    # Check that we have 1 certificate in the signature,
    # and have a counterSignature section
    if is_pefile(test_file):
        with signed_exe.open("rb") as f:
            certificates = get_certificates(f)
            sigs = get_signatures_from_certificates(certificates)
            assert len(certificates) == 1
            assert len(sigs) == 1
            assert len(sigs[0]["certificates"]) == 1
            assert any(
                (
                    sigs[0]["signerInfos"][0]["unauthenticatedAttributes"][i]["type"]
                    == id_timestampSignature
                )
                for i in range(
                    len(sigs[0]["signerInfos"][0]["unauthenticatedAttributes"])
                )
            )

            assert verify_pefile(f)


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


def test_verify_signed_file():
    """Test that our internal verification code works."""
    with (DATA_DIR / "signed.exe").open("rb") as f:
        assert verify_pefile(f)

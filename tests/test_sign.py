import subprocess
from pathlib import Path

import pytest
from common import DATA_DIR, EXPECTED_SIGNATURES, TEST_MSI_FILES, TEST_PE_FILES
from winsign.asn1 import get_signatures_from_certificates, id_timestampSignature
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.pefile import is_pefile, pefile
from winsign.sign import is_signed, sign_file


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
def test_sign_file(test_file, tmp_path, signing_keys):
    """
    Check that we can sign with the osslsign wrapper
    """
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(test_file, signed_exe, "sha1", certs, signer)

    # Check that we have 1 certificate in the signature
    if is_pefile(test_file):
        with signed_exe.open("rb") as f:
            certificates = get_certificates(f)
            sigs = get_signatures_from_certificates(certificates)
            assert len(certificates) == 1
            assert len(sigs) == 1
            assert len(sigs[0]["certificates"]) == 1


def test_sign_file_dummy(tmp_path, signing_keys):
    """
    Check that we can sign with an additional dummy certificate for use by the
    stub installer
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
    """
    Check that we can include multiple certificates
    """
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
    """
    Verify that we can't sign non-exe files
    """
    test_file = Path(__file__)
    signed_file = tmp_path / "signed.py"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert not sign_file(test_file, signed_file, "sha1", certs, signer)


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
def test_timestamp_old(test_file, tmp_path, signing_keys, httpserver):
    """
    Verify that we can sign with old style timestamps
    """
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content((DATA_DIR / f"unsigned-sha1-ts-old.dat").read_bytes())
    assert sign_file(
        test_file,
        signed_exe,
        "sha1",
        certs,
        signer,
        timestamp_style="old",
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


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
def test_timestamp_rfc3161(test_file, tmp_path, signing_keys, httpserver):
    """
    Verify that we can sign with RFC3161 timestamps
    """
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content((DATA_DIR / f"unsigned-sha1-ts-rfc3161.dat").read_bytes())
    assert sign_file(
        test_file,
        signed_exe,
        "sha1",
        certs,
        signer,
        timestamp_style="rfc3161",
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


@pytest.mark.parametrize(
    "test_file, file_is_signed",
    (
        ("unsigned.exe", False),
        ("signed.exe", True),
        ("unsigned.msi", False),
        ("cert.pem", False),
    ),
)
def test_is_signed(test_file, file_is_signed):
    assert is_signed(DATA_DIR / test_file) == file_is_signed

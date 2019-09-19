"""Tests specific to signing functionality."""
from pathlib import Path

import pytest
from common import DATA_DIR, TEST_PE_FILES, have_osslsigncode, use_fixed_signing_time
from winsign.asn1 import get_signatures_from_certificates, id_timestampSignature
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.osslsigncode import sign_file as ossl_sign_file
from winsign.pefile import get_certificates, is_pefile
from winsign.pefile import sign_file as pefile_sign_file
from winsign.verify import verify_pefile


def test_verify_signed_file():
    """Test that our internal verification code works."""
    with (DATA_DIR / "signed.exe").open("rb") as f:
        assert verify_pefile(f)


SIGNING_FUNCS = [pefile_sign_file]
if have_osslsigncode():
    SIGNING_FUNCS.append(ossl_sign_file)


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
def test_sign_file(test_file, digest_algo, tmp_path, signing_keys, signing_func):
    """Check that we can sign with the osslsign wrapper."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert signing_func(test_file, signed_exe, digest_algo, certs, signer)

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


@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
def test_sign_file_dummy(tmp_path, signing_keys, signing_func):
    """Check that we can sign with an additional dummy certificate.

    The extra dummy certs are used by the stub installer.
    """
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert signing_func(
        test_file, signed_exe, "sha1", certs, signer, crosscert=signing_keys[1]
    )

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2


@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
def test_sign_file_twocerts(tmp_path, signing_keys, signing_func):
    """Check that we can include multiple certificates."""
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(open(DATA_DIR / "twocerts.pem", "rb").read())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert signing_func(test_file, signed_exe, "sha1", certs, signer)

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2


@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
def test_sign_file_badfile(tmp_path, signing_keys, signing_func):
    """Verify that we can't sign non-exe files."""
    test_file = Path(__file__)
    signed_file = tmp_path / "signed.py"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert not signing_func(test_file, signed_file, "sha1", certs, signer)


@pytest.mark.parametrize("test_file", [DATA_DIR / "unsigned.exe"])
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
@use_fixed_signing_time
def test_timestamp_old(
    test_file, digest_algo, tmp_path, signing_keys, httpserver, signing_func
):
    """Verify that we can sign with old style timestamps."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-old.dat").read_bytes()
    )
    assert signing_func(
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
    assert is_pefile(test_file)
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 3

        assert verify_pefile(f)


@pytest.mark.parametrize("test_file", [DATA_DIR / "unsigned.exe"])
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
@pytest.mark.parametrize("signing_func", SIGNING_FUNCS)
@use_fixed_signing_time
def test_timestamp_rfc3161(
    test_file, digest_algo, tmp_path, signing_keys, httpserver, signing_func
):
    """Verify that we can sign with RFC3161 timestamps."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-rfc3161.dat").read_bytes()
    )
    assert signing_func(
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
    assert is_pefile(test_file)
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
            for i in range(len(sigs[0]["signerInfos"][0]["unauthenticatedAttributes"]))
        )

        assert verify_pefile(f)

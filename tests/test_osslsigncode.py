import subprocess
from binascii import hexlify

import pytest
from common import DATA_DIR, EXPECTED_SIGNATURES, TEST_FILES
from pyasn1.codec.der.encoder import encode as der_encode
from winsign.asn1 import id_signingTime
from winsign.pefile import add_signature, calc_hash, get_certificates
from winsign.sign import (
    add_old_timestamp,
    add_rfc3161_timestamp,
    get_authenticode_signature,
    get_signatures_from_certificates,
)
from winsign.x509 import decode_key, load_pem_cert


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


@pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
# Using sha1cert here is fine. It doesn't really matter what digest is used in
# the certificate itself
def test_signature_parity(test_file, digest_algo, tmp_path, sha1cert):
    """
    Tests that we can generate the same signatures as osslsigncode
    """
    signed_exe = tmp_path / "signed.exe"
    subprocess.run(
        [
            "osslsigncode",
            "sign",
            "-key",
            sha1cert[0],
            "-certs",
            sha1cert[1],
            "-h",
            digest_algo,
            test_file,
            signed_exe,
        ],
        check=True,
    )

    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        signatures = get_signatures_from_certificates(certificates)
        assert len(signatures) == 1
        signed_data = signatures[0]

        signing_time = None
        for a in signed_data["signerInfos"][0]["authenticatedAttributes"]:
            if a["type"] == id_signingTime:
                signing_time = a["values"][0]
                break

        assert signing_time

        authenticode_digest = calc_hash(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(sha1cert[1].read_bytes()),
            decode_key(sha1cert[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        sig = der_encode(sig)
        padlen = (8 - len(sig) % 8) % 8
        sig += b"\x00" * padlen
        assert len(sig) == len(certificates[0]["data"])


@pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature(test_file, digest_algo, tmp_path, sha1cert):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_hash(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(sha1cert[1].read_bytes()),
            decode_key(sha1cert[0].read_bytes()),
            authenticode_digest,
            digest_algo,
        )
        encoded_sig = der_encode(sig)
        ifile.seek(0)
        add_signature(ifile, ofile, encoded_sig)

    # Verify that it's sane
    assert osslsigncode_verify(signed_exe)


# TODO: This test should fail. We're hardcoding the timestamp response for the wrong
# file, and osslsigncode isn't failing to verify
@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
# @pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature_rfc3161_timestamp(
    test_file, digest_algo, tmp_path, sha1cert, httpserver
):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_hash(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(sha1cert[1].read_bytes()),
            decode_key(sha1cert[0].read_bytes()),
            authenticode_digest,
            digest_algo,
        )
        httpserver.serve_content(
            (DATA_DIR / f"unsigned-{digest_algo}-ts-rfc3161.dat").read_bytes()
        )
        add_rfc3161_timestamp(sig["content"], digest_algo, httpserver.url)
        encoded_sig = der_encode(sig)
        ifile.seek(0)
        add_signature(ifile, ofile, encoded_sig)

    # Verify that it's sane
    assert osslsigncode_verify(signed_exe)
    # TODO: Verify that the timestamp is valid. osslsigncode currently doesn't
    # check this


# TODO: This test should fail. We're hardcoding the timestamp response for the wrong
# file, and osslsigncode isn't failing to verify
@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
# @pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature_old_timestamp(
    test_file, digest_algo, tmp_path, sha1cert, httpserver
):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_hash(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(sha1cert[1].read_bytes()),
            decode_key(sha1cert[0].read_bytes()),
            authenticode_digest,
            digest_algo,
        )
        httpserver.serve_content(
            (DATA_DIR / f"unsigned-{digest_algo}-ts-old.dat").read_bytes()
        )
        add_old_timestamp(sig["content"], httpserver.url)
        encoded_sig = der_encode(sig)
        ifile.seek(0)
        add_signature(ifile, ofile, encoded_sig)

    # Verify that it's sane
    assert osslsigncode_verify(signed_exe)
    # TODO: Verify that the timestamp is valid. osslsigncode currently doesn't
    # check this


@pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
# Using sha1cert here is fine. It doesn't really matter what digest is used in
# the certificate itself
def test_calc_hash(test_file, digest_algo, tmp_path, sha1cert):
    """
    Tests that we can calculate the same PE file hash as osslsigncode
    """
    signed_exe = tmp_path / "signed.exe"
    subprocess.run(
        [
            "osslsigncode",
            "sign",
            "-key",
            sha1cert[0],
            "-certs",
            sha1cert[1],
            "-h",
            digest_algo,
            test_file,
            signed_exe,
        ],
        check=True,
    )
    assert osslsigncode_verify(signed_exe)

    with open(test_file, "rb") as unsigned, open(signed_exe, "rb") as signed:
        unsigned_hash = hexlify(calc_hash(unsigned))
        signed_hash = hexlify(calc_hash(signed))
        assert unsigned_hash == signed_hash

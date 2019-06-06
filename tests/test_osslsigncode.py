import subprocess
from binascii import hexlify

import pytest
import winsign.osslsign as osslsign
from common import DATA_DIR, EXPECTED_SIGNATURES, TEST_MSI_FILES, TEST_PE_FILES
from pyasn1.codec.der.encoder import encode as der_encode
from winsign.asn1 import id_signingTime
from winsign.pefile import add_signature, calc_authenticode_digest, get_certificates
from winsign.sign import (
    add_old_timestamp,
    add_rfc3161_timestamp,
    get_authenticode_signature,
    get_signatures_from_certificates,
    sign_signer_digest,
)
from winsign.verify import verify_pefile
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


def osslsigncode_sign(signing_keys, digest_algo, input_file, output_file, *extra_args):
    subprocess.run(
        [
            "osslsigncode",
            "sign",
            "-key",
            signing_keys[0],
            "-certs",
            signing_keys[1],
            "-h",
            digest_algo,
            *extra_args,
            input_file,
            output_file,
        ],
        check=True,
    )


def get_signing_time(certificates):
    signatures = get_signatures_from_certificates(certificates)
    signed_data = signatures[0]

    signing_time = None
    for a in signed_data["signerInfos"][0]["authenticatedAttributes"]:
        if a["type"] == id_signingTime:
            signing_time = a["values"][0]
            break

    return signing_time


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_signature_parity(test_file, digest_algo, tmp_path, signing_keys):
    """
    Tests that we can generate the same signatures as osslsigncode
    """
    signed_exe = tmp_path / "signed.exe"
    osslsigncode_sign(signing_keys, digest_algo, test_file, signed_exe)

    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        signing_time = get_signing_time(certificates)

        authenticode_digest = calc_authenticode_digest(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        sig = der_encode(sig)
        padlen = (8 - len(sig) % 8) % 8
        sig += b"\x00" * padlen
        assert sig == certificates[0]["data"]


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature(test_file, digest_algo, tmp_path, signing_keys):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_authenticode_digest(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
        )
        encoded_sig = der_encode(sig)
        ifile.seek(0)
        add_signature(ifile, ofile, encoded_sig)

    # Check that we get the same signature on the output file
    assert authenticode_digest == calc_authenticode_digest(
        signed_exe.open("rb"), digest_algo
    )

    # Verify that it's sane
    assert osslsigncode_verify(signed_exe)
    assert verify_pefile(signed_exe.open("rb"))


# TODO: This test should fail. We're hardcoding the timestamp response for the wrong
# file, and osslsigncode isn't failing to verify
@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
# @pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature_rfc3161_timestamp(
    test_file, digest_algo, tmp_path, signing_keys, httpserver
):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_authenticode_digest(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
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
    assert verify_pefile(signed_exe.open("rb"))
    # TODO: Verify that the timestamp is valid. osslsigncode currently doesn't
    # check this


# TODO: This test should fail. We're hardcoding the timestamp response for the wrong
# file, and osslsigncode isn't failing to verify
@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
# @pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_attach_signature_old_timestamp(
    test_file, digest_algo, tmp_path, signing_keys, httpserver
):
    "Check that we can validly attach signatures we generate"
    signed_exe = tmp_path / "signed.exe"
    with test_file.open("rb") as ifile, signed_exe.open("wb+") as ofile:
        authenticode_digest = calc_authenticode_digest(ifile, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
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
    assert verify_pefile(signed_exe.open("rb"))
    # TODO: Verify that the timestamp is valid. osslsigncode currently doesn't
    # check this


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_calc_digest(test_file, digest_algo, tmp_path, signing_keys):
    """
    Tests that we can calculate the same PE file hash as osslsigncode
    """
    signed_exe = tmp_path / "signed.exe"
    osslsigncode_sign(signing_keys, digest_algo, test_file, signed_exe)
    assert osslsigncode_verify(signed_exe)
    assert verify_pefile(signed_exe.open("rb"))

    with open(test_file, "rb") as unsigned, open(signed_exe, "rb") as signed:
        unsigned_digest = hexlify(calc_authenticode_digest(unsigned))
        signed_digest = hexlify(calc_authenticode_digest(signed))
        assert unsigned_digest == signed_digest


@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_signature_parity_rfc3161_timestamp(
    digest_algo, tmp_path, signing_keys, httpserver
):
    """
    Tests that we can generate the same signatures as osslsigncode, using
    RFC3161 timestamps
    """
    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-rfc3161.dat").read_bytes()
    )
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"
    osslsigncode_sign(
        signing_keys, digest_algo, test_file, signed_exe, "-ts", httpserver.url
    )

    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        signing_time = get_signing_time(certificates)

        authenticode_digest = calc_authenticode_digest(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        add_rfc3161_timestamp(sig["content"], digest_algo, httpserver.url)
        sig = der_encode(sig)
        padlen = (8 - len(sig) % 8) % 8
        sig += b"\x00" * padlen
        assert sig == certificates[0]["data"], "signatures differ"


@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_signature_parity_old_timestamp(
    digest_algo, tmp_path, signing_keys, httpserver
):
    """
    Tests that we can generate the same signatures as osslsigncode, using old timestamps
    """
    httpserver.serve_content(
        (DATA_DIR / f"unsigned-{digest_algo}-ts-old.dat").read_bytes()
    )
    test_file = DATA_DIR / "unsigned.exe"
    signed_exe = tmp_path / "signed.exe"
    osslsigncode_sign(
        signing_keys, digest_algo, test_file, signed_exe, "-t", httpserver.url
    )

    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        signing_time = get_signing_time(certificates)

        authenticode_digest = calc_authenticode_digest(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        add_old_timestamp(sig["content"], httpserver.url)
        sig = der_encode(sig)
        padlen = (8 - len(sig) % 8) % 8
        sig += b"\x00" * padlen
        # For easier debugging, write out the signatures separately so we can
        # compare them after
        # (tmp_path / "orig.sig").write_bytes(certificates[0]["data"])
        # (tmp_path / "new.sig").write_bytes(sig)
        assert sig == certificates[0]["data"], "signatures differ"


@pytest.mark.parametrize("test_file", TEST_PE_FILES + TEST_MSI_FILES)
def test_osslsign_winsign(test_file, tmp_path, signing_keys):
    """
    Check that we can sign with the osslsign wrapper
    """
    signed_exe = tmp_path / "signed.exe"

    priv_key = decode_key(open(signing_keys[0], "rb").read())
    cert = load_pem_cert(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert osslsign.winsign(test_file, signed_exe, "sha1", cert, signer)

    # Check that we have 1 certificate in the signature
    if osslsign.is_pefile(test_file):
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

    priv_key = decode_key(open(signing_keys[0], "rb").read())
    cert = load_pem_cert(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert osslsign.winsign(
        test_file, signed_exe, "sha1", cert, signer, crosscert=signing_keys[1]
    )

    # Check that we have 2 certificates in the signature
    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 2

"""Tests specific to PE files."""

import pytest
from common import TEST_PE_FILES
from winsign.asn1 import get_signatures_from_certificates
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.pefile import get_certificates, is_pefile, sign_file
from winsign.verify import verify_pefile


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_sign_file(test_file, digest_algo, tmp_path, signing_keys):
    """Test that we can sign PE files."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    assert sign_file(test_file, signed_exe, digest_algo, certs, signer)

    assert is_pefile(signed_exe)

    with signed_exe.open("rb") as f:
        certificates = get_certificates(f)
        sigs = get_signatures_from_certificates(certificates)
        assert len(certificates) == 1
        assert len(sigs) == 1
        assert len(sigs[0]["certificates"]) == 1
        assert verify_pefile(f)

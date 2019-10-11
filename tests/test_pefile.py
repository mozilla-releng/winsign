"""Tests specific to PE files."""

import pytest
from common import TEST_PE_FILES
from winsign.crypto import load_pem_certs, load_private_key, sign_signer_digest
from winsign.pefile import sign_file
from winsign.verify import verify_pefile


@pytest.mark.parametrize("test_file", TEST_PE_FILES)
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_sign(test_file, digest_algo, tmp_path, signing_keys):
    """Check that we can sign a PE file."""
    signed_exe = tmp_path / "signed.exe"

    priv_key = load_private_key(open(signing_keys[0], "rb").read())
    certs = load_pem_certs(signing_keys[1].read_bytes())
    # TODO: Make sure multiple works
    cert = certs[0]

    def signer(digest, digest_algo):
        return sign_signer_digest(priv_key, digest_algo, digest)

    with test_file.open("rb") as infile, signed_exe.open("wb+") as outfile:
        assert sign_file(infile, outfile, digest_algo, cert, signer)

        assert verify_pefile(outfile)

from binascii import hexlify
from datetime import datetime

import pytest
from common import EXPECTED_SIGNATURES
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import useful
from winsign.pefile import calc_hash
from winsign.sign import get_authenticode_signature
from winsign.x509 import decode_key, load_pem_cert


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_signatures(test_file, digest_algo, sha1cert):
    """Make sure that we can generate the expected signatures for the same test data"""
    expected_sig = EXPECTED_SIGNATURES[test_file][digest_algo]

    signing_time = useful.UTCTime.fromDateTime(datetime(2019, 4, 29))

    with test_file.open("rb") as f:
        authenticode_digest = calc_hash(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(sha1cert[1].read_bytes()),
            decode_key(sha1cert[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        assert (
            hexlify(der_encode(sig["content"]["signerInfos"][0]["encryptedDigest"]))
            == expected_sig
        )

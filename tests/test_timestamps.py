from datetime import datetime

import pytest
from common import DATA_DIR, EXPECTED_SIGNATURES
from pyasn1.type import useful
from winsign.pefile import calc_hash
from winsign.sign import (
    add_old_timestamp,
    add_rfc3161_timestamp,
    get_authenticode_signature,
)
from winsign.x509 import decode_key, load_pem_cert


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_rfc3161_timestamp(test_file, digest_algo, sha1cert, httpserver):
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
        assert not sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0]

        httpserver.serve_content(
            (DATA_DIR / f"{test_file.stem}-{digest_algo}-ts-rfc3161.dat").read_bytes()
        )

        add_rfc3161_timestamp(sig["content"], digest_algo, httpserver.url)

        assert sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0]
        assert len(httpserver.requests) == 1


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_old_timestamp(test_file, digest_algo, sha1cert, httpserver):
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
        assert not sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0]

        httpserver.serve_content(
            (DATA_DIR / f"{test_file.stem}-{digest_algo}-ts-old.dat").read_bytes()
        )

        add_old_timestamp(sig["content"], httpserver.url)

        assert sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0]
        assert len(httpserver.requests) == 1

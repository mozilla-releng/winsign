from datetime import datetime

import pytest
from common import DATA_DIR, EXPECTED_SIGNATURES
from pyasn1.type import univ, useful
from winsign.pefile import calc_authenticode_digest
from winsign.sign import (
    add_old_timestamp,
    add_rfc3161_timestamp,
    get_authenticode_signature,
)
from winsign.x509 import decode_key, load_pem_cert


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_rfc3161_timestamp(test_file, digest_algo, signing_keys, httpserver):
    signing_time = useful.UTCTime.fromDateTime(datetime(2019, 4, 29))

    with test_file.open("rb") as f:
        authenticode_digest = calc_authenticode_digest(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        assert len(sig["content"]["signerInfos"][0]["unauthenticatedAttributes"]) == 0

        httpserver.serve_content(
            (DATA_DIR / f"{test_file.stem}-{digest_algo}-ts-rfc3161.dat").read_bytes()
        )

        add_rfc3161_timestamp(sig["content"], digest_algo, httpserver.url)

        assert len(sig["content"]["signerInfos"][0]["unauthenticatedAttributes"]) == 1
        assert sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0][
            "type"
        ] == univ.ObjectIdentifier("1.3.6.1.4.1.311.3.3.1")
        assert len(httpserver.requests) == 1


@pytest.mark.parametrize("test_file", EXPECTED_SIGNATURES.keys())
@pytest.mark.parametrize("digest_algo", ["sha1", "sha256"])
def test_old_timestamp(test_file, digest_algo, signing_keys, httpserver):
    signing_time = useful.UTCTime.fromDateTime(datetime(2019, 4, 29))

    with test_file.open("rb") as f:
        authenticode_digest = calc_authenticode_digest(f, digest_algo)
        sig = get_authenticode_signature(
            load_pem_cert(signing_keys[1].read_bytes()),
            decode_key(signing_keys[0].read_bytes()),
            authenticode_digest,
            digest_algo,
            signing_time,
        )
        assert len(sig["content"]["signerInfos"][0]["unauthenticatedAttributes"]) == 0

        httpserver.serve_content(
            (DATA_DIR / f"{test_file.stem}-{digest_algo}-ts-old.dat").read_bytes()
        )

        add_old_timestamp(sig["content"], httpserver.url)

        assert len(sig["content"]["signerInfos"][0]["unauthenticatedAttributes"]) == 1

        assert sig["content"]["signerInfos"][0]["unauthenticatedAttributes"][0][
            "type"
        ] == univ.ObjectIdentifier("1.2.840.113549.1.9.6")
        assert len(httpserver.requests) == 1

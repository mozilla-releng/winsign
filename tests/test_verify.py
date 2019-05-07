import pytest
import winsign.verify
from common import TEST_FILES
from winsign.pefile import pefile


@pytest.mark.parametrize("test_file", TEST_FILES)
@pytest.mark.parametrize(
    "verify_func",
    [
        winsign.verify.verify_pefile_digest,
        winsign.verify.verify_pefile_signature,
        winsign.verify.verify_pefile_rfc3161_timestamp,
        pytest.param(
            winsign.verify.verify_pefile_old_timestamp, marks=pytest.mark.xfail
        ),
    ],
)
def test_verify_pefile(test_file, verify_func):
    "Check that all our test files are valid"
    with test_file.open("rb") as f:
        pe = pefile.parse_stream(f)
        res, messages = verify_func(f, pe)
        assert res, messages


@pytest.mark.parametrize("test_file", TEST_FILES)
def test_verify_pefile_checksum(test_file):
    "Check that all our test files checksums are valid"
    with test_file.open("rb") as f:
        pe = pefile.parse_stream(f)
        checksum = pe.optional_header.checksum
        res, messages = winsign.verify.verify_pefile_checksum(f, pe)
        if checksum == 0:
            assert not res, messages
        else:
            assert res, messages

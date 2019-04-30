import pytest
from common import TEST_FILES
from winsign.pefile import pefile
from winsign.verify import verify_pefile


@pytest.mark.parametrize("test_file", TEST_FILES)
def test_verify(test_file):
    "Check that all our test files are valid"
    with test_file.open("rb") as f:
        pe = pefile.parse_stream(f)
        checksum = pe.optional_header.checksum
        if checksum == 0:
            assert not verify_pefile(f)
        else:
            assert verify_pefile(f)

import pytest
from common import DATA_DIR, TEST_FILES
from winsign.pefile import calc_checksum, calc_checksum_slow, pefile

KNOWN_CHECKSUMS = {DATA_DIR / "signed.exe": 0x000A76B5}


@pytest.mark.skipif(
    calc_checksum == calc_checksum_slow, reason="no fast checksum available"
)
@pytest.mark.parametrize("test_file", TEST_FILES)
def test_calc_checksum_fastslow(test_file):
    "Checks that the fast and slow checksum implementations return the same result."
    with test_file.open("rb") as f:
        pe = pefile.parse_stream(f)

        checksum_offset = pe.optional_header.checksum_offset
        assert calc_checksum(f, checksum_offset) == calc_checksum_slow(
            f, checksum_offset
        )


@pytest.mark.parametrize("test_file", KNOWN_CHECKSUMS.keys())
@pytest.mark.parametrize("func", [calc_checksum, calc_checksum_slow])
def test_calc_checksum_known(test_file, func):
    "Checks that we can calculate the proper checksum for known files"
    with test_file.open("rb") as f:
        pe = pefile.parse_stream(f)

        assert pe.optional_header.checksum == KNOWN_CHECKSUMS[test_file]

        checksum_offset = pe.optional_header.checksum_offset
        assert func(f, checksum_offset) == KNOWN_CHECKSUMS[test_file]

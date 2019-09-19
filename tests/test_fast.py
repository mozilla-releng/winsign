"""Test that our cython functions are equivalient to our python functions."""
from hypothesis import given
from hypothesis.strategies import binary, integers
from winsign._fast import _checksum_update_fast
from winsign.pefile import _checksum_update_slow


@given(binary(), integers(min_value=0, max_value=65535))
def test_checksum_update(b, i):
    """Check that the checksum update functions."""
    if len(b) % 2 == 1:
        b = b[:-1]
    b = bytearray(b)
    assert _checksum_update_fast(b, i) == _checksum_update_slow(b, i)

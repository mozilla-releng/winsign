"""Tests specific to signing functionality."""
from common import DATA_DIR
from winsign.verify import verify_pefile


def test_verify_signed_file():
    """Test that our internal verification code works."""
    with (DATA_DIR / "signed.exe").open("rb") as f:
        assert verify_pefile(f)

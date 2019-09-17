"""common paths used by tests."""
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
TEST_PE_FILES = list(DATA_DIR.glob("**/*.exe")) + list(DATA_DIR.glob("**/*.dll"))

TEST_MSI_FILES = list(DATA_DIR.glob("**/*.msi"))

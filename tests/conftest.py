"""pytest fixtures and settings."""
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parent / "data"


@pytest.fixture(scope="session")
def signing_keys():
    """Fixture to provide paths to test signing keys."""
    return (DATA_DIR / "privkey.pem", DATA_DIR / "cert.pem")

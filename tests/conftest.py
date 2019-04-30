from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parent / "data"


@pytest.fixture(scope="session")
def sha1cert():
    return (DATA_DIR / "privkey.pem", DATA_DIR / "cert.pem")

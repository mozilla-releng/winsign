"""common paths used by tests."""
from functools import wraps
from pathlib import Path
from unittest import mock
import inspect

import winsign.asn1
from winsign.asn1 import id_signingTime

DATA_DIR = Path(__file__).resolve().parent / "data"
TEST_PE_FILES = list(DATA_DIR.glob("**/*.exe")) + list(DATA_DIR.glob("**/*.dll"))

TEST_MSI_FILES = list(DATA_DIR.glob("**/*.msi"))


def use_fixed_signing_time(f):
    """Decorator that injects a hardcoded signing time into signatures.

    Args:
        f (func): function to wrap

    """
    orig_resign = winsign.asn1.resign

    def wrapped_resign(old_sig, certs, signer):
        # Inject a fixed signing time into old_sig
        for info in old_sig["signerInfos"]:
            for attr in info["authenticatedAttributes"]:
                if attr["type"] == id_signingTime:
                    attr["values"][0] = b"\x17\r190912061110Z"
        return orig_resign(old_sig, certs, signer)

    if inspect.iscoroutinefunction(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            with mock.patch("winsign.sign.resign", wrapped_resign):
                return await f(*args, **kwargs)
    else:
        @wraps(f)
        def wrapper(*args, **kwargs):
            with mock.patch("winsign.sign.resign", wrapped_resign):
                return f(*args, **kwargs)

    return wrapper

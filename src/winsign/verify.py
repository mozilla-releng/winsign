"""
Code to verify signatures
"""
from winsign.pefile import calc_checksum, pefile


class VerifyStatus:
    def __init__(self):
        self.result = True
        self.results = []

    def __bool__(self):
        return self.result

    def add_result(self, name, value, message):
        self.results.append((name, value, message))
        if not value:
            self.result = False


def verify_pefile_checksum(f, pe):
    cur_checksum = pe.optional_header.checksum
    new_checksum = calc_checksum(f, pe.optional_header.checksum_offset)
    if cur_checksum == new_checksum:
        return True, f"Checksum OK: {cur_checksum}"
    else:
        return False, f"Checksums differ: {cur_checksum} != {new_checksum}"


def verify_pefile(f):
    """Verifies the given pefile.

    Arguments:
        f (file object): open pefile. This must be open in binary mode.

    Returns:
        A VerifyStatus object, which evaluates to True if all checks pass, or
        False if one or more checks fail. A list of checks and their statuses
        can be found in the .results attribute.
    """
    retval = VerifyStatus()
    f.seek(0)
    pe = pefile.parse_stream(f)

    # First, check the checksum
    retval.add_result("checksum", *verify_pefile_checksum(f, pe))

    return retval

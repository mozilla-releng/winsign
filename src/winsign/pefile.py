# Based on https://docs.microsoft.com/en-ca/windows/desktop/Debug/pe-format
# https://github.com/etingof/pyasn1-modules/blob/master/pyasn1_modules/rfc2315.py
# https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
# https://docs.google.com/document/d/1TJf22nAqtIJPB1ybTnoTdgZiFq2oi-LHgrSuwBqOC2g/edit#
# https://github.com/theuni/osslsigncode/blob/9fb9e1503ca3f49bcfd7535fdd587f2988438706/osslsigncode.c
# https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
"""PE file format support.

This module provides various structures and methods that represent Windows PE files,
with a specific focus on the parts of the format required for signing.
"""
import hashlib

from construct import (
    Array,
    Bytes,
    Const,
    ConstructError,
    Enum,
    GreedyRange,
    If,
    Int16ul,
    Int32ul,
    PaddedString,
    Pointer,
    Seek,
    Struct,
    Tell,
    this,
)

from winsign.asn1 import der_encode, make_authenticode_signeddata

dos_stub = Struct("magic" / Const(b"MZ"), "pe_offset" / Pointer(0x3C, Int16ul))

coff_header = Struct(
    "signature" / Const(b"PE\x00\x00"),
    "machine" / Int16ul,
    "nsections" / Int16ul,
    "timestamp" / Int32ul,
    "symboltable_offset" / Int32ul,
    "nsymbols" / Int32ul,
    "optionalheader_size" / Int16ul,
    "characteristics" / Int16ul,
)


pe_header = Struct(
    "offset" / Tell,
    "magic" / Enum(Int16ul, PE32=0x10B, PE32PLUS=0x20B),
    Seek(this.offset + 64),
    "checksum_offset" / Tell,
    "checksum" / Int32ul,
    Seek(lambda ctx: ctx.offset + (92 if ctx.magic == "PE32" else 108)),
    "nrvasizes" / Int32ul,
    Seek(lambda ctx: ctx.offset + (128 if ctx.magic == "PE32" else 144)),
    "certtable_info" / If(this.nrvasizes >= 5, Tell),
    "certtable_offset" / If(this.nrvasizes >= 5, Int32ul),
    "certtable_size" / If(this.nrvasizes >= 5, Int32ul),
)


certificate = Struct(
    "size" / Int32ul,
    "revision" / Enum(Int16ul, REV1=0x0100, REV2=0x0200),
    "certtype" / Enum(Int16ul, PKCS7=0x002),
    "data" / Bytes(this.size - 8),
)

section = Struct(
    "name" / PaddedString(8, "utf8"),
    "vsize" / Int32ul,
    "vaddr" / Int32ul,
    "size" / Int32ul,
    "data_offset" / Int32ul,
    Bytes(16),  # Stuff we don't use
)

pefile = Struct(
    "dos_stub" / dos_stub,
    Seek(this.dos_stub.pe_offset),
    "coff_header" / coff_header,
    "optional_header" / pe_header,
    Seek(this.optional_header.offset + this.coff_header.optionalheader_size),
    "sections" / Array(this.coff_header.nsections, section),
    If(
        this.optional_header.certtable_offset,
        Seek(this.optional_header.certtable_offset),
    ),
    "certificates"
    / If(this.optional_header.certtable_offset, GreedyRange(certificate)),
)


def is_pefile(filename):
    """Determine if a file is a PE file or not.

    Args:
        filename (str): path to file to check

    Returns:
        True if the file appears to be a PE file
        False otherwise

    """
    try:
        pefile.parse_stream(open(filename, "rb"))
        return True
    except ConstructError:
        return False


def is_signed(filename):
    """Determine if a PE file is signed or not.

    This does not verify the signatures, it merely returns whether a file
    contains signatures or not.

    Args:
        filename (str): path to file to check

    Returns:
        True if the file has signatures
        False otherwise

    """
    try:
        pe = pefile.parse_stream(open(filename, "rb"))
    except ConstructError:
        return False

    if not pe.certificates:
        return False
    return len(pe.certificates) > 0


# TODO: This is slow in Python
def calc_authenticode_digest(f, alg="sha256"):
    """Calculate the authenticode digest for file.

    Args:
        f (file object): opened PE file
        alg (str): digest algorithm to use. Defaults to sha256.

    Returns:
        The authenicode digest as a byte string

    """
    h = hashlib.new(alg)
    f.seek(0)
    pe = pefile.parse_stream(f)

    f.seek(0, 2)
    eof = f.tell()
    f.seek(0)

    # Read up until the checksum
    to_read = pe.optional_header.checksum_offset
    h.update(f.read(to_read))
    # Skip 4 bytes of the checksum
    f.read(4)

    # If we have a certificate table entry, skip over it
    if pe.optional_header.certtable_info:
        t = f.tell()
        to_read = pe.optional_header.certtable_info - t
        h.update(f.read(to_read))
        # Skip over the 8 bytes of the certificate table entry (offset and size)
        f.read(8)

    # Read the rest of the file, until the certificates
    if pe.optional_header.certtable_offset:
        to_read = pe.optional_header.certtable_offset - f.tell()
        padlen = 8 - (pe.optional_header.certtable_offset % 8)
    else:
        to_read = eof - f.tell()
        padlen = 8 - (eof % 8)
    h.update(f.read(to_read))

    # Pad the end of the file, before the certificates to 8 bytes
    if padlen > 0 and padlen < 8:
        h.update(b"\x00" * padlen)

    return h.digest()


def calc_checksum(f, checksum_offset):
    """Calculate the PE file checksum.

    Args:
        f (file object): PE file opened for reading
        checksum_offset (int): where in the PE file the checksum is located

    Returns:
        integer checksum

    """
    checksum = 0
    size = 0
    f.seek(0)

    while True:
        data = f.read(1024 ** 2)
        if not data:
            break
        if len(data) % 2 == 1:
            data = bytearray(data[:-1])
        else:
            data = bytearray(data)
        for i in range(0, len(data), 2):
            if size == checksum_offset or size == checksum_offset + 2:
                val = 0
            else:
                val = (data[i + 1] << 8) | data[i + 0]
            checksum += val
            checksum = 0xFFFF & (checksum + (checksum >> 0x10))
            size += 2

    checksum = 0xFFFF & (checksum + (checksum >> 0x10))
    checksum += size
    checksum &= 0xFFFFFFFFFF
    return checksum


def get_certificates(f):
    """Return the set of certificates in the PE file.

    Args:
        f (file object): PE file opened for reading

    Returns:
        List of `certificate` objects, or None if there are none

    """
    pe = pefile.parse_stream(f)
    return pe.certificates


def add_signature(infile, outfile, signature):
    """Add a signature to a PE file."""
    # First copy infile to outfile
    infile.seek(0)
    while True:
        block = infile.read(1024)
        if not block:
            break
        outfile.write(block)

    outfile.seek(0)
    pe = pefile.parse_stream(outfile)
    if not pe.optional_header.certtable_info:
        raise ValueError(
            "Can't add a signature into this file (not enough RVA sections)"
        )

    cert = certificate.build(
        {
            "size": len(signature) + 8,
            "revision": "REV2",
            "certtype": "PKCS7",
            "data": signature,
        }
    )

    # If we already have signatures, then add the new one to the end of the file
    if pe.optional_header.certtable_offset:
        certs_offset = pe.optional_header.certtable_offset
        certs_size = pe.optional_header.certtable_size + len(cert)
        old_certs_size = pe.optional_header.certtable_size
    else:
        # Figure out the end of the file
        outfile.seek(0, 2)
        certs_offset = outfile.tell()
        # Pad to 8 byte boundary
        if certs_offset % 8:
            certs_offset += 8 - (certs_offset % 8)
        certs_size = len(cert)
        old_certs_size = 0

    # Update the certificate table info
    outfile.seek(pe.optional_header.certtable_info)
    outfile.write(Int32ul.build(certs_offset))
    outfile.write(Int32ul.build(certs_size))

    # Add the signature
    outfile.seek(certs_offset + old_certs_size)
    outfile.write(cert)

    # Update the checksum
    checksum = calc_checksum(outfile, pe.optional_header.checksum_offset)
    outfile.seek(pe.optional_header.checksum_offset)
    outfile.write(Int32ul.build(checksum))


async def sign_file(
    infile,
    outfile,
    digest_algo,
    certs,
    signer,
    url=None,
    comment=None,
    crosscert=None,
    timestamp_style=None,
    timestamp_url=None,
    authenticode_timestamp=None,
):
    """Sign a file."""
    authenticode_digest = calc_authenticode_digest(infile, digest_algo)

    # TODO: Support crosscert
    # TODO: timestamp counter sigs

    sig = await make_authenticode_signeddata(
        certs,
        signer,
        authenticode_digest,
        digest_algo,
        authenticode_timestamp,
        comment,
        url,
    )

    sig = der_encode(sig)

    add_signature(infile, outfile, sig)

    return True

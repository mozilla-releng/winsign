#!/usr/bin/env python
# Based on https://docs.microsoft.com/en-ca/windows/desktop/Debug/pe-format
# https://github.com/etingof/pyasn1-modules/blob/master/pyasn1_modules/rfc2315.py
# https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
# https://docs.google.com/document/d/1TJf22nAqtIJPB1ybTnoTdgZiFq2oi-LHgrSuwBqOC2g/edit#
# https://github.com/theuni/osslsigncode/blob/9fb9e1503ca3f49bcfd7535fdd587f2988438706/osslsigncode.c
# https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
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
    try:
        pefile.parse_stream(open(filename, "rb"))
        return True
    except ConstructError:
        return False


def is_signed(filename):
    try:
        pe = pefile.parse_stream(open(filename, "rb"))
    except ConstructError:
        return False

    if not pe.certificates:
        return False
    return len(pe.certificates) > 0

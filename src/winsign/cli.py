#!/usr/bin/env python
"""CLI for signing PE and MSI files."""
import asyncio
import logging
import sys
import tempfile
from argparse import ArgumentParser
from pathlib import Path

from winsign.crypto import load_pem_certs, load_private_key
from winsign.sign import key_signer, sign_file

log = logging.getLogger(__name__)


def _copy_stream(instream, outstream):
    while True:
        block = instream.read(1024 ** 2)
        if not block:
            break
        outstream.write(block)


def build_parser():
    """Create our CLI ArgumentParser."""
    parser = ArgumentParser()
    parser.add_argument("infile", help="unsigned file to sign")
    parser.add_argument(
        "outfile",
        help="where to write output to. defaults to infile",
        default=None,
        nargs="?",
    )
    parser.add_argument(
        "--certs",
        dest="certs",
        help="certificates to include in the signature",
        required=True,
    )
    parser.add_argument(
        "--key", dest="priv_key", help="private key used to sign", required=True
    )
    parser.add_argument("-n", dest="comment", help="comment to include in signature")
    parser.add_argument("-i", dest="url", help="url to include in signature")
    parser.add_argument(
        "-d",
        dest="digest_algo",
        help="digest to use for signing. must be one of sha1 or sha256",
        choices=["sha1", "sha256"],
        required=True,
    )
    parser.add_argument("-t", dest="timestamp", choices=["old", "rfc3161"])
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    parser.add_argument(
        "-q", "--quiet", dest="loglevel", action="store_const", const=logging.WARNING
    )
    return parser


async def async_main(argv=None):
    """Main CLI entry point for signing (async)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(format="%(asctime)s - %(message)s", level=args.loglevel)

    if not args.priv_key:
        if not (args.autograph_user and args.autograph_secret):
            parser.error(
                "--key, or all of --autograph-url, --autograph-user, and "
                "--autograph-secret must be specified"
            )

    if not args.outfile:
        args.outfile = args.infile

    certs = []
    certs_data = open(args.certs, "rb").read()
    certs = load_pem_certs(certs_data)
    priv_key = load_private_key(open(args.priv_key, "rb").read())

    signer = key_signer(priv_key)

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        if args.infile == "-":
            args.infile = d / "unsigned"
            with args.infile.open("wb") as f:
                _copy_stream(sys.stdin.buffer, f)
        else:
            args.infile = Path(args.infile)

        if args.outfile == "-":
            outfile = d / "signed"
        else:
            outfile = Path(args.outfile)

        r = await sign_file(
            args.infile,
            outfile,
            args.digest_algo,
            certs,
            signer,
            url=args.url,
            comment=args.comment,
            timestamp_style=args.timestamp,
        )

        # TODO: Extra cross-cert
        # TODO: Check with a cert chain
        if not r:
            return 1

        if args.outfile == "-":
            with outfile.open("rb") as f:
                _copy_stream(f, sys.stdout.buffer)

        return 0


def main(argv=None, loop=None):
    """Main CLI entry point for signing (sync)."""
    loop = loop or asyncio.get_event_loop()
    return loop.run_until_complete(async_main(argv))

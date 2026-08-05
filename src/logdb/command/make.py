import argparse
import sys

from logdb.config import load_config
from logdb.core import db_make


def register(parser: argparse.ArgumentParser):
    """Register the make command and its arguments."""
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to the input log file",
    )
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        choices=("dumpstate", "pcap", "hci"),
        help="Input log type",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path to the output DuckDB database",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Drop and recreate table if it already exists",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    try:
        return db_make(args.type, args.input, args.output, force=args.force)
    except FileExistsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

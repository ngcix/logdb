import argparse
import sys


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
        choices=("dumpstate", "wireshark"),
        help="Input log type",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Path to the output DuckDB database",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Build a DuckDB database from a supported log file."""
    print("The make command is not implemented yet.", file=sys.stderr)
    return 1
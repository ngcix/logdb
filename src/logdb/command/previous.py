import argparse
import sys


def register(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", help="Path to the DuckDB database")
    parser.add_argument("-t", "--table", required=True, help="Table to search")
    parser.add_argument("-l", "--line", required=True, type=int, help="Current line")
    parser.add_argument(
        "-c", "--column",
        action="append",
        nargs=2,
        metavar=("COLUMN", "VALUE"),
        default=[],
        help="Filter a column; repeat to combine filters",
    )
    parser.add_argument("-r", "--rows", type=int, default=100)
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    print("The previous command is not implemented yet.", file=sys.stderr)
    return 1
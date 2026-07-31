import argparse
import sys


def register(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", help="Path to the DuckDB database")
    parser.add_argument("sql", help="Read-only SQL query")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    print("The query command is not implemented yet.", file=sys.stderr)
    return 1
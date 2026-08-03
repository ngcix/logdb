import argparse
import sys

import duckdb

from logdb.database.query import format_json, run_search


def register(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", help="Path to the DuckDB database")
    parser.add_argument("-t", "--table", required=True, help="Table to search")
    parser.add_argument(
        "-c",
        "--column",
        action="append",
        nargs=2,
        metavar=("COLUMN", "REGEX"),
        default=[],
        help="Regex-filter a column; repeat to combine filters",
    )
    parser.add_argument(
        "-r",
        "--rows",
        type=int,
        default=100,
        help="Maximum rows to return (default: 100)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    try:
        result = run_search(
            args.database,
            args.table,
            args.column,
            max_rows=args.rows,
        )
    except (duckdb.Error, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(format_json(result))

    if result.truncated:
        print(
            "output truncated; increase --rows to see more",
            file=sys.stderr,
        )

    return 0
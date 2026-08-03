import argparse
import sys

import duckdb

from logdb.database.query import format_json, run_next


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
    try:
        result = run_next(
            args.database,
            args.table,
            args.line,
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
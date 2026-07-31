import argparse
import sys

import duckdb

from logdb.database.query import QueryResult, run_query


def register(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", help="Path to the DuckDB database")
    parser.add_argument("sql", help="Read-only SQL query")
    parser.add_argument(
        "-r",
        "--rows",
        type=int,
        default=100,
        help="Maximum rows to print (default: 100)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    try:
        result = run_query(args.database, args.sql, max_rows=args.rows)
    except (duckdb.Error, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    _print_result(result)
    return 0


def _print_result(result: QueryResult) -> None:
    print("\t".join(result.columns))

    for row in result.rows:
        print("\t".join("" if value is None else str(value) for value in row))

    print(f"({len(result.rows)} rows)")

    if result.truncated:
        print(
            "output truncated; increase --rows to see more",
            file=sys.stderr,
        )
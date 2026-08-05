import argparse

from logdb.database.query import run_query
from logdb.command._shared import run_query_command


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
    return run_query_command(
        lambda a: run_query(a.database, a.sql, max_rows=a.rows),
        args,
    )
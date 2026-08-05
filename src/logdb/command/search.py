import argparse

from logdb.database.query import run_search
from logdb.command._shared import run_query_command


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
    parser.add_argument(
        "--from",
        dest="from_line",
        type=int,
        default=None,
        help="Start line number (inclusive)",
    )
    parser.add_argument(
        "--to",
        dest="to_line",
        type=int,
        default=None,
        help="End line number (inclusive)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    return run_query_command(
        lambda a: run_search(
            a.database,
            a.table,
            a.column,
            max_rows=a.rows,
            from_line=a.from_line,
            to_line=a.to_line,
        ),
        args,
    )
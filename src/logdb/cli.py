import argparse

from logdb.command import inspect, make, next, previous, query, search

PROGRAM_NAME = "logdb"


def parser_builder() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME)
    commands = parser.add_subparsers(dest="cmd", required=True)

    make_parser = commands.add_parser(
        "make",
        help="Import a log file into a DuckDB database",
    )
    make.register(make_parser)

    search_parser = commands.add_parser(
        "search",
        help="Search records in a database table",
    )
    search.register(search_parser)

    next_parser = commands.add_parser(
        "next",
        help="Return records after a line",
    )
    next.register(next_parser)

    previous_parser = commands.add_parser(
        "previous",
        help="Return records before a line",
    )
    previous.register(previous_parser)

    query_parser = commands.add_parser(
        "query",
        help="Run a read-only SQL query",
    )
    query.register(query_parser)

    inspect_parser = commands.add_parser(
        "inspect",
        help="List tables in a database",
    )
    inspect.register(inspect_parser)

    return parser


def main() -> int:
    parser = parser_builder()

    try:
        args = parser.parse_args()
    except SystemExit as error:
        return int(error.code) if error.code is not None else 1

    return int(args.func(args))
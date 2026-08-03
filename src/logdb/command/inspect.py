import argparse
import json
import sys

import duckdb

from logdb.database.query import get_tables


def register(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", help="Path to the DuckDB database")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    try:
        tables = get_tables(args.database)
    except (duckdb.Error, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps({"tables": tables, "count": len(tables)}))
    return 0

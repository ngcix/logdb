import argparse
import sys
from typing import Callable, Any

import duckdb

from logdb.database.query import format_json, QueryResult


def run_query_command(
    handler: Callable[[argparse.Namespace], QueryResult],
    args: argparse.Namespace,
) -> int:
    """Wrapper for query commands (next, previous, search, query).

    Handles:
    - Error catching and printing
    - JSON formatting of results
    - Truncation warnings
    """
    try:
        result = handler(args)
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

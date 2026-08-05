from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import duckdb
import sys
import csv
import os
import tempfile

from logdb.database.query import _quote_identifier


def _show_progress(current: int, total: int | None) -> None:
    """Display progress to stderr without third-party dependencies."""
    if total is None:
        message = f"Imported {current:,} rows"
    elif total == 0:
        message = "Imported 0 rows"
    else:
        percent = min(current / total, 1)
        filled = int(percent * 30)
        bar = "#" * filled + "-" * (30 - filled)
        message = f"[{bar}] {percent:.0%} ({current:,}/{total:,} rows)"

    print(f"\r{message}", end="", file=sys.stderr, flush=True)


def _inject_default_columns(columns_sql: str) -> str:
    """Inject line_no (PK) and raw_line into SQL definition."""
    return f"""
    line_no       BIGINT PRIMARY KEY,
    {columns_sql.strip()},
    raw_line      TEXT NOT NULL,
    """


def connect_database(database_path: str) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB database, creating it when the file does not exist."""
    return duckdb.connect(database_path)


def create_table(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    columns: Mapping[str, str] | str,
) -> None:
    """Create a table from a column mapping or SQL column definition.

    Auto-injects line_no (PRIMARY KEY) and raw_line columns if not present.
    """
    if _table_exists(connection, table_name):
        raise FileExistsError(f"Table already exists: {table_name}")
    if isinstance(columns, str):
        definition = _inject_default_columns(columns)
    else:
        definition = ", ".join(
            f"{_quote_identifier(name)} {data_type}"
            for name, data_type in columns.items()
        )

    connection.execute(
        f"CREATE TABLE {_quote_identifier(table_name)} ({definition})"
    )


def _table_exists(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
) -> bool:
    """Return whether a table exists in the main DuckDB schema."""
    row = connection.execute(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'main' AND table_name = ?
        """,
        [table_name],
    ).fetchone()
    return row is not None

_CSV_NULL = "\x01"

def insert_rows(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    columns: Sequence[str],
    records: Iterable[Sequence[Any]],
    total_rows: int | None = None,
) -> int:
    """Stream records to CSV, then bulk-load them with DuckDB COPY.

    Auto-injects line_no and raw_line columns if not in the provided columns list.
    """
    # Auto-inject line_no and raw_line if not present
    full_columns = columns
    if '"line_no"' not in columns and 'line_no' not in columns:
        full_columns = ['"line_no"'] + list(columns) + ['"raw_line"']

    quoted_columns = ", ".join(_quote_identifier(name) for name in full_columns)

    file_descriptor, csv_path = tempfile.mkstemp(suffix=".csv")
    os.close(file_descriptor)

    inserted = 0

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(
                csv_file,
                quoting=csv.QUOTE_ALL,
                doublequote=True,
                lineterminator="\n",
            )

            _show_progress(0, total_rows)

            for record in records:
                writer.writerow(
                    _CSV_NULL if value is None else value
                    for value in record
                )
                inserted += 1

                if inserted % 1_000 == 0:
                    _show_progress(inserted, total_rows)

        if inserted:
            _show_progress(inserted, total_rows)
            print(file=sys.stderr, flush=True)

            connection.execute(
                f"COPY {_quote_identifier(table_name)} ({quoted_columns}) "
                "FROM ? (FORMAT CSV, HEADER false, NULL ?, "
                "QUOTE '\"', ESCAPE '\"', DELIMITER ',', NEW_LINE '\\n')",
                [csv_path, _CSV_NULL],
            )
        else:
            # Mark that no rows were inserted (table created but empty)
            pass

        return inserted
    finally:
        try:
            os.unlink(csv_path)
        except OSError:
            pass

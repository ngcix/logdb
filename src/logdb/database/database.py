from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import duckdb


def connect_database(database_path: str) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB database, creating it when the file does not exist."""
    return duckdb.connect(database_path)


def create_table(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    columns: Mapping[str, str] | str,
) -> None:
    """Create a table from a column mapping or SQL column definition."""
    if _table_exists(connection, table_name):
        raise FileExistsError(f"Table already exists: {table_name}")
    if isinstance(columns, str):
        definition = columns
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

def insert_rows(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    columns: Sequence[str],
    records: Iterable[Sequence[Any]],
) -> None:
    """Insert parsed records using bound values."""
    rows = list(records)
    if not rows:
        return

    quoted_columns = ", ".join(_quote_identifier(name) for name in columns)
    placeholders = ", ".join("?" for _ in columns)
    statement = (
        f"INSERT INTO {_quote_identifier(table_name)} "
        f"({quoted_columns}) VALUES ({placeholders})"
    )
    connection.executemany(statement, rows)


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'
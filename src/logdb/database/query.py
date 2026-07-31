from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import duckdb


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]]
    truncated: bool


def run_query(
    database_path: str,
    sql: str,
    *,
    parameters: Sequence[Any] = (),
    max_rows: int = 100,
) -> QueryResult:
    connection = duckdb.connect(database_path, read_only=True)
    try:
        return fetch_rows(connection, sql, parameters, max_rows=max_rows)
    finally:
        connection.close()


def fetch_rows(
    connection: duckdb.DuckDBPyConnection,
    sql: str,
    parameters: Sequence[Any] = (),
    *,
    max_rows: int = 100,
) -> QueryResult:
    """Execute one row-producing statement and return bounded results."""
    if max_rows < 1:
        raise ValueError("max_rows must be at least 1")

    if len(connection.extract_statements(sql)) != 1:
        raise ValueError("Exactly one SQL statement is required")

    result = connection.execute(sql, parameters)
    if result.description is None:
        raise ValueError("The query must return rows")

    rows = result.fetchmany(max_rows + 1)
    truncated = len(rows) > max_rows

    if truncated:
        rows.pop()

    return QueryResult(
        columns=tuple(column[0] for column in result.description),
        rows=rows,
        truncated=truncated,
    )


def run_search(
    database_path: str,
    table_name: str,
    filters: Sequence[tuple[str, str]],
    *,
    max_rows: int = 100,
) -> QueryResult:
    """Search table columns with AND-combined, case-insensitive regex filters."""
    connection = duckdb.connect(database_path, read_only=True)

    try:
        columns = _table_columns(connection, table_name)
        conditions: list[str] = []
        parameters: list[str] = []

        for requested_column, pattern in filters:
            column_name = columns.get(requested_column.casefold())
            if column_name is None:
                raise ValueError(
                    f"Unknown column {requested_column!r} "
                    f"in table {table_name!r}"
                )

            conditions.append(
                f"regexp_matches("
                f"CAST({_quote_identifier(column_name)} AS VARCHAR), ?, 'i')"
            )
            parameters.append(pattern)

        sql = f"SELECT * FROM {_quote_identifier(table_name)}"

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        if "line_no" in columns:
            sql += f" ORDER BY {_quote_identifier(columns['line_no'])}"

        return fetch_rows(connection, sql, parameters, max_rows=max_rows)
    finally:
        connection.close()


def _table_columns(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
) -> dict[str, str]:
    description = connection.execute(
        f"DESCRIBE {_quote_identifier(table_name)}"
    ).fetchall()

    return {
        str(column[0]).casefold(): str(column[0])
        for column in description
    }


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'
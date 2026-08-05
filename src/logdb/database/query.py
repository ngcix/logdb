import json
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


def _add_filter_conditions(
    conditions: list[str],
    parameters: list[Any],
    filters: Sequence[tuple[str, str]],
    columns: dict[str, str],
    table_name: str,
) -> None:
    """Add column regex filters to conditions list."""
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


def run_search(
    database_path: str,
    table_name: str,
    filters: Sequence[tuple[str, str]],
    *,
    max_rows: int = 100,
    from_line: int | None = None,
    to_line: int | None = None,
) -> QueryResult:
    """Search table columns with AND-combined, case-insensitive regex filters and optional line_no range."""
    connection = duckdb.connect(database_path, read_only=True)

    try:
        columns = _table_columns(connection, table_name)
        conditions: list[str] = []
        parameters: list[Any] = []

        if from_line is not None or to_line is not None:
            if from_line is not None and to_line is not None:
                conditions.append("line_no BETWEEN ? AND ?")
                parameters.extend([from_line, to_line])
            elif from_line is not None:
                conditions.append("line_no >= ?")
                parameters.append(from_line)
            else:
                conditions.append("line_no <= ?")
                parameters.append(to_line)

        _add_filter_conditions(conditions, parameters, filters, columns, table_name)

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


def run_next(
    database_path: str,
    table_name: str,
    line_no: int,
    filters: Sequence[tuple[str, str]],
    *,
    max_rows: int = 100,
) -> QueryResult:
    """Return records after a given line with optional regex column filters."""
    connection = duckdb.connect(database_path, read_only=True)

    try:
        columns = _table_columns(connection, table_name)
        conditions = ["line_no > ?"]
        parameters: list[Any] = [line_no]

        _add_filter_conditions(conditions, parameters, filters, columns, table_name)

        sql = f"SELECT * FROM {_quote_identifier(table_name)} WHERE " + " AND ".join(conditions)
        sql += " ORDER BY line_no"

        return fetch_rows(connection, sql, parameters, max_rows=max_rows)
    finally:
        connection.close()


def run_previous(
    database_path: str,
    table_name: str,
    line_no: int,
    filters: Sequence[tuple[str, str]],
    *,
    max_rows: int = 100,
) -> QueryResult:
    """Return records before a given line with optional regex column filters."""
    connection = duckdb.connect(database_path, read_only=True)

    try:
        columns = _table_columns(connection, table_name)
        conditions = ["line_no < ?"]
        parameters: list[Any] = [line_no]

        _add_filter_conditions(conditions, parameters, filters, columns, table_name)

        sql = f"SELECT * FROM {_quote_identifier(table_name)} WHERE " + " AND ".join(conditions)
        sql += " ORDER BY line_no DESC"

        return fetch_rows(connection, sql, parameters, max_rows=max_rows)
    finally:
        connection.close()


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def get_tables(database_path: str) -> list[dict[str, Any]]:
    """Get list of tables with their columns."""
    connection = duckdb.connect(database_path, read_only=True)
    try:
        tables_result = connection.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()

        tables = []
        for table_row in tables_result:
            table_name = table_row[0]
            columns_result = connection.execute(
                f"DESCRIBE {_quote_identifier(table_name)}"
            ).fetchall()
            columns = [col[0] for col in columns_result]
            tables.append({"name": table_name, "columns": columns})

        return tables
    finally:
        connection.close()


def format_json(result: QueryResult) -> str:
    """Convert QueryResult to JSON format."""
    rows_as_dicts = [dict(zip(result.columns, row)) for row in result.rows]
    data = {
        "columns": result.columns,
        "rows": rows_as_dicts,
        "row_count": len(result.rows),
        "truncated": result.truncated,
    }
    return json.dumps(data)
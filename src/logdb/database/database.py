from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import duckdb
import sys
import pyarrow as pa

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
    columns = columns_sql.strip().rstrip(',')
    return f"""
    line_no       BIGINT PRIMARY KEY,
    {columns},
    raw_line      TEXT NOT NULL
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
    chunk_size: int = 100_000,  # 100k dòng mỗi batch nạp ~ 1-2 giây
) -> int:
    """
    Bulk-load dữ liệu trực tiếp từ RAM vào DuckDB thông qua Apache Arrow.
    - Không sinh file rác trên đĩa
    - Miễn nhiễm 100% với lỗi max_line_size, newline, quotes
    - Tối ưu cho dataset từ 10 - 50 triệu dòng
    """
    quoted_table = _quote_identifier(table_name)
    inserted = 0
    _show_progress(0, total_rows)

    # Khởi tạo buffer theo dạng cột (Columnar Dict)
    col_buffers: dict[str, list[Any]] = {col: [] for col in columns}

    def _flush_chunk():
        """Nạp chunk hiện tại từ RAM vào DuckDB qua Arrow Table."""
        if not col_buffers[columns[0]]:
            return
        
        # 1. Chuyển Python List thành Arrow Table trong RAM C++
        arrow_table = pa.Table.from_pydict(col_buffers)
        
        # 2. Đăng ký Arrow Table ảo trong DuckDB và Insert thẳng vào bảng
        connection.register("arrow_chunk_view", arrow_table)
        connection.execute(f"INSERT INTO {quoted_table} SELECT * FROM arrow_chunk_view")
        connection.unregister("arrow_chunk_view")
        
        # 3. Reset buffer
        for col in columns:
            col_buffers[col].clear()

    try:
        # Bắt đầu Transaction để DuckDB tối ưu tốc độ ghi đĩa
        connection.execute("BEGIN TRANSACTION")

        for record in records:
            for idx, col in enumerate(columns):
                col_buffers[col].append(record[idx])
            
            inserted += 1

            # Khi đủ 100,000 dòng, đẩy trực tiếp vào DuckDB
            if inserted % chunk_size == 0:
                _flush_chunk()
                _show_progress(inserted, total_rows)

        # Nạp số dòng còn dư ở batch cuối cùng
        _flush_chunk()
        
        # Commit toàn bộ dữ liệu vào DuckDB
        connection.execute("COMMIT")

        _show_progress(inserted, total_rows)
        print(file=sys.stderr, flush=True)
        return inserted

    except Exception:
        connection.execute("ROLLBACK")
        raise

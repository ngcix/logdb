---
name: logdb-query
description: Query and analyze large diagnostic logs (dumpstate, pcap) efficiently with DuckDB. Use when importing Android logs, searching patterns, navigating log context, or extracting evidence for RCA.
version: 1.0.0
---

# LogDB — Diagnostic Log Query Tool

Lightweight CLI to import large Android dumpstate/logcat logs into DuckDB and return structured evidence for AI agents and users.

**CLI Usage:** Commands can be run as either:
- `logdb <command>` — if installed/built as executable
- `python -m logdb <command>` — if running from source

## Quick Start

### 1. Create Database from Log File

```bash
logdb make -i path/to/dumpstate.log -t dumpstate -o case.duckdb
# or: python -m logdb make -i path/to/dumpstate.log -t dumpstate -o case.duckdb
```

Creates:
- `case.duckdb` — DuckDB database
- `case.dumpstate.toml` — Configuration with schema and parsing rules (edit before re-import)

### 2. Inspect Database Schema

```bash
logdb inspect case.duckdb
# or: python -m logdb inspect case.duckdb
```

Output: JSON with table names and column lists.

### 3. Search Records

```bash
logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -c level "ERROR" -r 50
# or: python -m logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -c level "ERROR" -r 50
```

- `-t, --table` — Table to search
- `-c, --column` — Regex filter (repeatable, AND-combined)
- `-r, --rows` — Limit output rows (default: 100)

### 4. Navigate by Line Number

```bash
# Get records after line 500
logdb next case.duckdb -t dumpstate -l 500 -r 20
# or: python -m logdb next case.duckdb -t dumpstate -l 500 -r 20

# Get records before line 500 (in reverse order)
logdb previous case.dumpstate -t dumpstate -l 500 -r 20
# or: python -m logdb previous case.dumpstate -t dumpstate -l 500 -r 20
```

With optional column filters:
```bash
logdb next case.duckdb -t dumpstate -l 500 -c pid "1234" -r 10
# or: python -m logdb next case.duckdb -t dumpstate -l 500 -c pid "1234" -r 10
```

### 5. Raw SQL Queries

```bash
logdb query case.duckdb "SELECT * FROM dumpstate WHERE tag LIKE '%Activity%' ORDER BY line_no" --rows 50
# or: python -m logdb query case.duckdb "SELECT * FROM dumpstate WHERE tag LIKE '%Activity%' ORDER BY line_no" --rows 50
```

## Output Format

All commands return **JSON** by default:

```json
{
  "columns": ["line_no", "tag", "message"],
  "rows": [
    {"line_no": 1, "tag": "stdout", "message": "..."},
    {"line_no": 2, "tag": "stdout", "message": "..."}
  ],
  "row_count": 2,
  "truncated": false
}
```

Special commands:
- `inspect` → `{"tables": [{"name": "dumpstate", "columns": [...]}], "count": 1}`

## Dumpstate Schema

Default schema (auto-detected, configurable via TOML):

| Column | Type | Purpose |
|--------|------|---------|
| `line_no` | int | Source line number (primary ordering) |
| `log_date` | text | Date from parsed log line |
| `log_time` | text | Time from parsed log line |
| `ts_order` | int | Timestamp order counter |
| `level` | text | Log level (ERROR, WARN, INFO, etc.) |
| `uid` | int | User ID |
| `pid` | int | Process ID |
| `tid` | int | Thread ID |
| `tag` | text | Log tag (component name) |
| `message` | text | Log message |
| `raw_line` | text | Original unparsed line |

## Commands

| Command | Purpose |
|---------|---------|
| `make` | Import log file into DuckDB |
| `inspect` | List tables and columns in database |
| `search` | Filter records by columns (regex) |
| `next` | Get N records after a line (with filters) |
| `previous` | Get N records before a line (with filters) |
| `query` | Run raw SQL query |

## Use Cases

### Find Error Context

```bash
# Search for error
logdb search case.duckdb -t dumpstate -c level "ERROR" -r 5

# Get 10 lines before error line 523 (context)
logdb previous case.duckdb -t dumpstate -l 523 -r 10
```

*(Replace `logdb` with `python -m logdb` when running from source)*

### Trace Module Calls

```bash
# All ActivityManager events
logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -r 100

# What happened after ActivityManager error at line 1200
logdb next case.duckdb -t dumpstate -l 1200 -c tag "ActivityManager" -r 20
```

*(Replace `logdb` with `python -m logdb` when running from source)*

### Cross-Module Correlation

```bash
logdb query case.duckdb \
  "SELECT line_no, tag, message FROM dumpstate 
   WHERE (tag LIKE '%Bluetooth%' OR tag LIKE '%Audio%')
   AND line_no BETWEEN 1000 AND 2000
   ORDER BY line_no"
```

*(Replace `logdb` with `python -m logdb` when running from source)*

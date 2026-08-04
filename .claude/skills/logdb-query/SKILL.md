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

#### Basic Search
```bash
logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -c level "ERROR" -r 50
# or: python -m logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -c level "ERROR" -r 50
```

Options:
- `-t, --table` — Table to search
- `-c, --column` — Regex filter (repeatable, AND-combined)
- `-r, --rows` — Limit output rows (default: 100)

#### Search Within Line Range
```bash
logdb search case.duckdb -t dumpstate --from 100 --to 500 -c tag "ERROR" -r 50
# or: python -m logdb search case.duckdb -t dumpstate --from 100 --to 500 -c tag "ERROR" -r 50
```

Options:
- `--from` — Start line number (inclusive)
- `--to` — End line number (inclusive)
- Can use `--from` alone or `--to` alone
- Combines with column filters using AND logic

### 4. Navigate by Line Number

#### Get Next Records (After a Line)
```bash
logdb next case.duckdb -t dumpstate -l 500 -r 20
# or: python -m logdb next case.duckdb -t dumpstate -l 500 -r 20
```

This returns the 20 records immediately after line 500. Useful for:
- Continuing from a previous search result
- Pagination through results
- Finding what happened after an error

#### Get Previous Records (Before a Line)
```bash
logdb previous case.duckdb -t dumpstate -l 500 -r 20
# or: python -m logdb previous case.dumpstate -t dumpstate -l 500 -r 20
```

Returns the 20 records before line 500 in reverse order. Useful for:
- Getting context before an error
- Tracing back to root cause

#### With Column Filters
Combine with regex filters (AND-combined):
```bash
logdb next case.duckdb -t dumpstate -l 500 -c tag "ActivityManager" -r 10
# or: python -m logdb next case.duckdb -t dumpstate -l 500 -c tag "ActivityManager" -r 10
```

Options:
- `-l, --line` — Current line number (required)
- `-c, --column` — Regex filter (repeatable, AND-combined)
- `-r, --rows` — Limit output rows (default: 100)

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
# Search for error in specific section
logdb search case.duckdb -t dumpstate --from 1000 --to 5000 -c level "ERROR" -r 5

# Get 10 lines before error at line 2523 (for context)
logdb previous case.duckdb -t dumpstate -l 2523 -r 10
```

*(Replace `logdb` with `python -m logdb` when running from source)*

### Trace Module Calls with Pagination

```bash
# Find all ActivityManager events
logdb search case.duckdb -t dumpstate -c tag "ActivityManager" -r 50

# From the last result (line 1200), continue browsing forward
logdb next case.duckdb -t dumpstate -l 1200 -c tag "ActivityManager" -r 20

# From that result (line 1350), continue further
logdb next case.dumpstate -t dumpstate -l 1350 -c tag "ActivityManager" -r 20
```

This pattern allows efficient pagination through filtered results using the line_no from the previous response.

*(Replace `logdb` with `python -m logdb` when running from source)*

### Cross-Module Correlation in Range

```bash
# Search for related errors in a specific line range
logdb search case.duckdb -t dumpstate --from 5000 --to 10000 \
  -c tag "Bluetooth" -c level "ERROR" -r 50
```

Or with raw SQL for complex queries:

```bash
logdb query case.duckdb \
  "SELECT line_no, tag, message FROM dumpstate 
   WHERE (tag LIKE '%Bluetooth%' OR tag LIKE '%Audio%')
   AND line_no BETWEEN 5000 AND 10000
   ORDER BY line_no"
```

*(Replace `logdb` with `python -m logdb` when running from source)*

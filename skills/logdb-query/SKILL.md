---
name: logdb-query
description: Query and search large diagnostic logs in DuckDB databases efficiently. Use when analyzing patterns, navigating context, extracting evidence, or running complex queries for RCA.
version: 1.0.0
---

# LogDB — Query & Search Tool

Efficient search and analysis of diagnostic logs imported into DuckDB. Works with dumpstate, pcap, and HCI logs.

## Setup — Resolve the Tool

Set `$LOGDB` once per session, then reuse it for every command:

```bash
# Default: works for any pip install, PATH or not, venv or not
export LOGDB="python -m logdb"

# Or: standalone binary from `make build`
# export LOGDB=./dist/__main__        # Windows: ./dist/__main__.exe
```

Then use it:
```bash
$LOGDB search case.duckdb -t dumpstate -c tag ERROR
$LOGDB next case.duckdb -t dumpstate -l 500 -r 20
$LOGDB query case.duckdb "SELECT * FROM dumpstate WHERE level='E'"
```

**Priority order** (if `$LOGDB` not set): `python -m logdb` → `logdb` on PATH → `./dist/__main__` (or `.exe`)

## Quick Start

**Prerequisites:** Database already created using the `logdb-make` guide

### 1. Inspect Database Schema

```bash
$LOGDB inspect case.duckdb
```

Output: JSON with table names and column lists.

### 2. Search Records

#### Basic Search
```bash
$LOGDB search case.duckdb -t dumpstate -c tag "ActivityManager" -c level "ERROR" -r 50
```

Options:
- `-t, --table` — Table to search
- `-c, --column` — Regex filter (repeatable, AND-combined)
- `-r, --rows` — Limit output rows (default: 100)

#### Search Within Line Range
```bash
$LOGDB search case.duckdb -t dumpstate --from 100 --to 500 -c tag "ERROR" -r 50
```

Options:
- `--from` — Start line number (inclusive)
- `--to` — End line number (inclusive)
- Can use `--from` alone or `--to` alone
- Combines with column filters using AND logic

### 3. Navigate by Line Number

#### Get Next Records (After a Line)
```bash
$LOGDB next case.duckdb -t dumpstate -l 500 -r 20
```

This returns the 20 records immediately after line 500. Useful for:
- Continuing from a previous search result
- Pagination through results
- Finding what happened after an error

#### Get Previous Records (Before a Line)
```bash
$LOGDB previous case.duckdb -t dumpstate -l 500 -r 20
```

Returns the 20 records before line 500 in reverse order. Useful for:
- Getting context before an error
- Tracing back to root cause

#### With Column Filters
Combine with regex filters (AND-combined):
```bash
$LOGDB next case.duckdb -t dumpstate -l 500 -c tag "ActivityManager" -r 10
```

Options:
- `-l, --line` — Current line number (required)
- `-c, --column` — Regex filter (repeatable, AND-combined)
- `-r, --rows` — Limit output rows (default: 100)

### 4. Raw SQL Queries

```bash
$LOGDB query case.duckdb "SELECT * FROM dumpstate WHERE tag LIKE '%Activity%' ORDER BY line_no" --rows 50
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
| `inspect` | List tables and columns in database |
| `search` | Filter records by columns (regex) and line ranges |
| `next` | Get N records after a line (with filters) |
| `previous` | Get N records before a line (with filters) |
| `query` | Run raw SQL query |

## Use Cases

### Find Error Context

```bash
# Search for error in specific section
$LOGDB search case.duckdb -t dumpstate --from 1000 --to 5000 -c level "ERROR" -r 5

# Get 10 lines before error at line 2523 (for context)
$LOGDB previous case.duckdb -t dumpstate -l 2523 -r 10
```

### Trace Module Calls with Pagination

```bash
# Find all ActivityManager events
$LOGDB search case.duckdb -t dumpstate -c tag "ActivityManager" -r 50

# From the last result (line 1200), continue browsing forward
$LOGDB next case.duckdb -t dumpstate -l 1200 -c tag "ActivityManager" -r 20

# From that result (line 1350), continue further
$LOGDB next case.duckdb -t dumpstate -l 1350 -c tag "ActivityManager" -r 20
```

This pattern allows efficient pagination through filtered results using the line_no from the previous response.

### Cross-Module Correlation in Range

```bash
# Search for related errors in a specific line range
$LOGDB search case.duckdb -t dumpstate --from 5000 --to 10000 \
  -c tag "Bluetooth" -c level "ERROR" -r 50
```

Or with raw SQL for complex queries:

```bash
$LOGDB query case.duckdb \
  "SELECT line_no, tag, message FROM dumpstate 
   WHERE (tag LIKE '%Bluetooth%' OR tag LIKE '%Audio%')
   AND line_no BETWEEN 5000 AND 10000
   ORDER BY line_no"
```

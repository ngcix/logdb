---
name: logdb-make
description: Create and manage DuckDB databases from diagnostic logs (dumpstate, pcap, hci). Use when initializing a new case database or regenerating with updated config.
version: 1.0.0
---

# LogDB — Database Creation & Configuration

Initialize and manage DuckDB databases from diagnostic log files with automatic schema configuration.

## Setup — Resolve the Tool

Set `$LOGDB` once per session, then reuse it for every command:

```bash
# Default: works for any pip install, PATH or not, venv or not
export LOGDB="python -m logdb"

# Or: standalone binary from `make build`
# export LOGDB=./dist/__main__        # Windows: ./dist/__main__.exe
```

**Priority order** (if `$LOGDB` not set): `python -m logdb` → `logdb` on PATH → `./dist/__main__` (or `.exe`)

Verify before use: `$LOGDB --help`

## Quick Start

View help: `$LOGDB make --help`

### 1. Create Database from Log File

```bash
$LOGDB make -i path/to/dumpstate.log -t dumpstate -o case.duckdb
```

Creates:
- `case.duckdb` — DuckDB database with parsed logs
- Config saved to `~/.logdb/config/dumpstate.toml` (shared across all dumpstate databases)

**Supported log types:**
- `dumpstate` — Android system dumps (multiple format patterns)
- `pcap` — Network packet captures (via tshark parsing)
- `hci` — Bluetooth HCI UART logs (.cfa files)

### 2. Recreate Database (Force Overwrite)

If the database already exists, use `--force` to drop the old table and reimport:

```bash
$LOGDB make -i updated.log -t dumpstate -o case.duckdb --force
```

This allows re-importing with updated config without deleting the .duckdb file.

### 3. Support different log types
- `text` base file can be use `dumpstate`
- `pcap` file
- ``
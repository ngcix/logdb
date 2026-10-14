---
name: logdb-make
description: Create and manage DuckDB databases from diagnostic logs (dumpstate, pcap, hci). Use when initializing a new case database or regenerating with updated config.
version: 1.1.0
---

# LogDB — Database Creation & Configuration

Initialize and manage DuckDB databases from diagnostic log files with automatic schema configuration.

## Step 0 — Install & Update Check

Run once per session, before anything else. Pure Python + `git`, so it behaves the
same on Windows, Linux, and macOS (no `curl` vs `curl.exe` / PowerShell issues).

```bash
python -c "
import importlib.metadata as md, subprocess, re
GIT = 'git@github.sec.samsung.net:cuong-nguyen/logdb.git'
try: local = md.version('logdb')
except md.PackageNotFoundError: local = None
if local is None:
    print('INSTALL'); raise SystemExit
try:
    out = subprocess.run(['git','ls-remote','--tags',GIT], capture_output=True, text=True, timeout=20)
    vs = re.findall(r'refs/tags/v([0-9]+(?:[.][0-9]+)*)$', out.stdout, re.M)
    remote = max(vs, key=lambda s: [int(x) for x in s.split('.')]) if vs else None
except Exception:
    remote = None
if remote is None:
    print('OFFLINE', local); raise SystemExit
print('UPDATE' if local != remote else 'OK', local, remote)
"
```

- `INSTALL` or `UPDATE` → run
  `python -m pip install -U git+https://github.sec.samsung.net/cuong-nguyen/logdb.git`
  (Windows: `py -m pip` if `python` is missing), then continue.
- `OK` → continue.
- `OFFLINE` → skip the update, continue with the installed version. Never block on it.

The check compares against **release tags** (`v1.1.0`), not `main`, so users only
move between tested releases.

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
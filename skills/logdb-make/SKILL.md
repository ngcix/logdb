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

### 3. Manage Configuration Files

LogDB stores config files centrally at `~/.logdb/config/`:
- `~/.logdb/config/dumpstate.toml`
- `~/.logdb/config/pcap.toml`
- `~/.logdb/config/hci.toml`

#### Initialize All Configs

```bash
$LOGDB config init
```

Output:
```
✓ Generated: ~/.logdb/config/dumpstate.toml
✓ Generated: ~/.logdb/config/pcap.toml
✓ Generated: ~/.logdb/config/hci.toml

Config files saved to: ~/.logdb/config
```

#### Regenerate Specific Config

```bash
$LOGDB config init -t pcap
```

This overwrites the pcap config with defaults. Useful if config is corrupted or needs reset.

#### Edit Configuration

Open config in your default editor (registered for .toml files):

```bash
$LOGDB config open -t dumpstate
```

On Windows, this uses your configured TOML editor (VS Code, Notepad++, etc.).
On Linux/macOS, uses `xdg-open`.

## Configuration

Each log type has a TOML config stored in `~/.logdb/config/`:

### Dumpstate Config

**Schema definition** — Column list and data types:
```toml
[table]
columns_sql = """
    log_date      VARCHAR,
    log_time      VARCHAR,
    ts_order      BIGINT NOT NULL,
    level         VARCHAR(1),
    tag           VARCHAR NOT NULL,
    message       TEXT NOT NULL,
"""
```

**Parsing rules** — Regex patterns with named groups matching columns:
```toml
[filter]
regex = [
  r"^(?P<log_date>...)  (?P<log_time>\d+) ... (?P<level>[A-Z]) (?P<tag>\S+): (?P<message>.*)$",
  # Additional patterns for alternate formats...
]
```

To customize:
1. Run `$LOGDB config open -t dumpstate`
2. Edit regex patterns to match your log format
3. Re-run `$LOGDB make ... --force` to reimport with new config

### PCAP Config

**Field extraction** — tshark field names become columns:
```toml
[table]
columns_sql = """
    "frame.number"      VARCHAR,
    "frame.time"        VARCHAR,
    "ip.src"            VARCHAR,
    "ip.dst"            VARCHAR,
    "tcp.srcport"       VARCHAR,
    ...
"""
```

To add more fields:
1. Run `$LOGDB config open -t pcap`
2. Add tshark field names to `columns_sql`
3. Re-run `$LOGDB make ... --force`

Available fields: Any tshark field name. Common ones:
- Frame: `frame.number`, `frame.time`, `frame.len`
- IP: `ip.src`, `ip.dst`, `ip.proto`
- TCP: `tcp.srcport`, `tcp.dstport`, `tcp.flags`
- UDP: `udp.srcport`, `udp.dstport`
- DNS: `dns.qry.name`, `dns.resp.type`
- HTTP: `http.request.uri`, `http.request.method`

### HCI Config

**Packet field extraction** with nested JSON support:
```toml
[table]
columns_sql = """
    packet_num         BIGINT NOT NULL,
    timestamp          VARCHAR,
    "data.type"        VARCHAR,
    "data.direction"   VARCHAR,
    "data.event_code"  VARCHAR,
    "data.event_name"  VARCHAR,
    "data.status"      VARCHAR,
    data_raw           JSON,
"""
```

**Dotted notation** (`data.field`) extracts from nested JSON:
- `data.type` → packet type (COMMAND, EVENT, ACL_DATA, SCO_DATA)
- `data.direction` → SENT or RECEIVED
- `data.event_code` → HCI event code (hex)
- `data.event_name` → Human-readable event name
- `data.parameters` → Full parameters object (as JSON)

To add more fields, use dotted notation in config and re-run `$LOGDB make ... --force`.

## Output Format

The `make` command prints progress and timing:

```
Done preprocess
Imported 1,234,567 rows
Execution time: 0:00:42.123456
```

## Commands

| Command | Purpose |
|---------|---------|
| `make` | Import log file into DuckDB database |
| `config init` | Generate default configs for all log types |
| `config init -t TYPE` | Regenerate config for specific type |
| `config open -t TYPE` | Open config in default editor |

## Use Cases

### Initialize New Case

```bash
# Create fresh database
$LOGDB make -i android_dump.log -t dumpstate -o case_001.duckdb

# View which tables were created
$LOGDB inspect case_001.duckdb
```

### Re-import with Custom Config

```bash
# Edit config
$LOGDB config open -t dumpstate

# Re-run with updated parsing rules
$LOGDB make -i android_dump.log -t dumpstate -o case_001.duckdb --force

# Verify schema updated
$LOGDB inspect case_001.duckdb
```

### Set Up Multiple Log Types

```bash
# Initialize all configs at once
$LOGDB config init

# Create databases from different log types
$LOGDB make -i dumpstate.log -t dumpstate -o case.duckdb
$LOGDB make -i capture.pcap -t pcap -o case.duckdb
$LOGDB make -i bt_snooz.cfa -t hci -o case.duckdb

# All share centralized configs from ~/.logdb/config/
```

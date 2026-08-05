# LogDB

LogDB imports large diagnostic logs into DuckDB and returns structured log
evidence for users and AI agents to analyze.

The project keeps log-type parsing separate from generic database operations:

```text
input log → type-specific parser → DuckDB table → generic query CLI
```

## Status

- ✅ `make`: imports dumpstate, pcap, and hci logs into DuckDB tables
- ✅ `search`, `next`, `previous`, `query`: full implementation with JSON output
- ✅ `inspect`: view database schema
- ✅ `config`: manage log type configurations
- ✅ All log types (dumpstate, pcap, hci) implemented

## Installation for AI Providers

### For Users: Install Module + Skills

Copy this prompt into your AI provider to install logdb and enable the two skills:

```
Install logdb module and skills for log analysis:

**Module Installation:**
- Install Python package: https://github.sec.samsung.net/cuong-nguyen/logdb/releases/download/release/logdb-1.0.0-py3-none-any.whl
- Or from source: pip install git+https://github.sec.samsung.net/cuong-nguyen/logdb.git

**Skill 1: logdb-make** (Database Creation & Config)
- Purpose: Create databases from log files, manage configurations
- Location: .claude/skills/logdb-make/SKILL.md
- Skill file: https://github.sec.samsung.net/cuong-nguyen/logdb/blob/main/.claude/skills/logdb-make/SKILL.md
- Commands: make, config init, config open

**Skill 2: logdb-query** (Search & Analysis)
- Purpose: Search, navigate, and analyze logs in databases
- Location: .claude/skills/logdb-query/SKILL.md
- Skill file: https://github.sec.samsung.net/cuong-nguyen/logdb/blob/main/.claude/skills/logdb-query/SKILL.md
- Commands: inspect, search, next, previous, query

**Setup:**
1. Install the Python package (pip or wheel)
2. Add both skill files to your AI provider's skill directory:
   - For Claude Code: Add to .claude/skills/ directory in your project
   - For other providers: Check your provider's skill location (may vary)
3. Run: `logdb config init` to generate default configs in ~/.logdb/config/

**Quick Test:**
```bash
logdb config init
logdb config open -t dumpstate
logdb make -i sample.log -t dumpstate -o test.duckdb
logdb inspect test.duckdb
logdb search test.duckdb -t dumpstate -c tag ERROR -r 10
```
```





## Install dev

Python 3.11 or newer is required.

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Create a database

```bash
logdb make \
  --input path/to/dumpstate.log \
  --type dumpstate \
  --output case.duckdb
```

The first command creates a sidecar configuration file beside the database:

```text
case.duckdb
case.dumpstate.toml
```

The sidecar config contains the dumpstate table schema, insertion columns, and
ordered parsing regexes. Edit it before a subsequent import to customize the
parser. Existing tables are not overwritten.

## Query a database

```bash
logdb query case.duckdb \
  'SELECT line_no, tag, message FROM dumpstate ORDER BY line_no' \
  --rows 50
```

`query` opens the database read-only and prints tab-separated rows to standard
output. Use `--rows` to bound output for terminal and AI-agent workflows.

## Dumpstate records

The default dumpstate schema contains:

```text
line_no, log_date, log_time, ts_order, level, uid, pid, tid,
tag, message, raw_line
```

Each input line becomes one record. The parser tries the configured regexes in
priority order; unmatched lines are retained with `tag = "stdout"`.

## Development

```bash
make install-dev
make test
make make-db LOG=path/to/dumpstate.log DB=case.duckdb
make query DB=case.duckdb SQL='SELECT * FROM dumpstate LIMIT 10'
make wheel
```

## Project layout

```text
src/logdb/
  cli.py                 Top-level command registration and dispatch
  command/                Command arguments and handlers
  core/                   Type-specific parsers and database builders
  database/               Shared DuckDB connection, table, insert, and query helpers
```

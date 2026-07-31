# LogDB

LogDB imports large diagnostic logs into DuckDB and returns structured log
evidence for users and AI agents to analyze.

The project keeps log-type parsing separate from generic database operations:

```text
input log → type-specific parser → DuckDB table → generic query CLI
```

## Status

- `make`: imports dumpstate-style logs into a DuckDB table.
- `query`: runs a bounded, read-only SQL query.
- `search`, `next`, and `previous`: CLI scaffolding; implementation is pending.
- `pcap` and `hci`: reserved log types; importers are pending.

## Install

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

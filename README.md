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

## Install

```bash
make setup
```

Installs the module, downloads the two usage guides, and writes the default
configs. Equivalent to:

```bash
pip install git+https://github.sec.samsung.net/cuong-nguyen/logdb.git

curl -fL --create-dirs -o ~/.agents/skills/logdb-make/SKILL.md \
  https://github.sec.samsung.net/cuong-nguyen/logdb/raw/main/skills/logdb-make/SKILL.md
curl -fL --create-dirs -o ~/.agents/skills/logdb-query/SKILL.md \
  https://github.sec.samsung.net/cuong-nguyen/logdb/raw/main/skills/logdb-query/SKILL.md

python -m logdb config init
```

Guides go to `~/.agents/skills` by default; override with
`make install-skills SKILLS_DIR=path/to/skills` if your tool reads them from
elsewhere. `config init` writes one config per log type to `~/.logdb/config/`
and prints the path.

Invoke the tool as `python -m logdb` so it works whether or not pip's scripts
directory is on `PATH`.


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
python -m logdb make \
  --input path/to/dumpstate.log \
  --type dumpstate \
  --output case.duckdb
```

Configuration is read from `~/.logdb/config/<type>.toml`, shared by every
database of that type, and created with defaults on first use. It holds the
table schema and — for dumpstate — the ordered parsing regexes:

```bash
python -m logdb config open -t dumpstate     # edit schema or regexes
python -m logdb make -i log.txt -t dumpstate -o case.duckdb --force
```

Existing tables are not overwritten unless `--force` is passed, which drops and
rebuilds the table.

## Query a database

```bash
python -m logdb search case.duckdb -t dumpstate -c level E --from 1000 -r 50
python -m logdb next case.duckdb -t dumpstate -l 2523 -r 20
python -m logdb previous case.duckdb -t dumpstate -l 2523 -r 20
python -m logdb query case.duckdb \
  'SELECT line_no, tag, message FROM dumpstate ORDER BY line_no' \
  --rows 50
```

All read commands open the database read-only and print JSON with `columns`,
`rows`, `row_count`, and `truncated`. Use `--rows` to bound output.

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

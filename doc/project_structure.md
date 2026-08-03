# Purpose
LogDB is a lightweight command-line tool that imports large diagnostic logs
into a DuckDB database for efficient querying by AI agents and users. Each log
type is stored in its own table, enabling focused filtering and inspection of
Android dumpstate/logcat data and Wireshark packet captures.

# Log file

## 1. Android logcat/dumpstate
- big dumpstate file from android phone

## 2. Wireshark pcap log
- Air log to monitor wifi frames

# Use case

LogDB provides focused, read-only retrieval of log records from a DuckDB
database. It returns evidence for an AI agent or user to analyze; root-cause
reasoning and investigation workflow are defined outside this CLI.

- Inspect a line range from one source log.
- From a known record, return the next or previous N records.
  - Optionally filter adjacent records by fields such as UID, PID, process,
    tag, severity, or log type.
- Return records within a timestamp range.
  - From a known record, return a time window before and/or after its
    timestamp.
- Search text fields for a word, phrase, or regular-expression pattern.
- Filter records by one or more column values.
  - Combine filters with `AND`, such as `pid = 1234` and
    `tag contains "ActivityManager"`.
  - Match any of several patterns, such as
    `Settings|ActivityManager`.
- Return a bounded number of records, ordered by source line or timestamp.
- Run a read-only SQL query for advanced filtering, aggregation, joins, and
  correlation across log-type tables.
- Return each matching record with sufficient evidence metadata:
  table name, source file, source line, timestamp when available, and parsed
  log fields.
- Emit results in a human-readable format or a machine-readable format
  (for example, JSON Lines) for AI-agent processing.






- Get from line \<n1\> to line \<n2\>
- From a line
    - get next N lines
    - get next N lines but match uid and/or pid ... multile choice
    - get previous N lines
    - get previous N lines but match uid and/or pid ... 

- From \<timestamp\> to \<timestamp\>

    - From a line, get window time range, previous or after current timestamp

- if the line contains `word` or `sentences` (plain text search)


# Commands

## make
Import a log file into a DuckDB database.

```bash
logdb make -i <input_path> -t <type> -o <output_path>
```

- `-i, --input` — Path to the input log file
- `-t, --type` — Log type: `dumpstate`, `pcap`, or `hci`
- `-o, --output` — Path to the output DuckDB database

Creates a sidecar `.toml` config file with schema and parsing rules.

## inspect
List tables in a database.

```bash
logdb inspect <database>
```

- `database` — Path to the DuckDB database

## search
Search records in a database table with regex-based column filtering.

```bash
logdb search <database> -t <table> [-c <column> <regex>]... [-r <rows>]
```

- `database` — Path to the DuckDB database
- `-t, --table` — Table name to search
- `-c, --column` — Regex-filter a column (repeat to combine filters with AND)
- `-r, --rows` — Maximum rows to return (default: 100)

## next
Return records after a specified line (pending implementation).

```bash
logdb next <database> -t <table> -l <line> [-c <column> <value>]... [-r <rows>]
```

## previous
Return records before a specified line (pending implementation).

```bash
logdb previous <database> -t <table> -l <line> [-c <column> <value>]... [-r <rows>]
```

## query
Run a read-only SQL query.

```bash
logdb query <database> <sql> [-r <rows>]
```

- `database` — Path to the DuckDB database
- `sql` — Read-only SQL query
- `-r, --rows` — Maximum rows to print (default: 100)
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


# Command template

logdb make
logdb search
logdb next
logdb previous
logdb query

## -m, --make <database_name>
Make a database from logfile
    sub_cmd:
    -i, --input <file_path>

    -t, --type <db type>
        db type: dumpstate or wireshark

## -s, --search <database_file> 
search inside database with multiple column filter and limit rows output
- sub_cmd:
    -t, --table `table_name`

    -r, --rows <max number of output rows>

    
    -c, --column <column_name> <value>


    - value:
            single value: Settings
            any column which value contains Settings

            multi regex: Settings|ActivityManager
            any column which value contains Settings or ActivityManager


        multi sub_cmd:

        -c, --column <column_name_1> <value_1> -c, --column <column_name_2> <value_2> ...
            find all column_name_1 contains value_1 then from result, filter column_name_2 contains value_2


        

## -n, --next <database_file> 
return the lines printed after current line, column filter is optional
    sub_cmd:
    -l, --line <current line number> 

    -t, --table <table_name>

    -r, --rows <max number of output rows>


        -c, --column <column_name> <value>


        value:
            single value: Settings
            any column which value contains Settings

            multi regex: Settings|ActivityManager
            any column which value contains Settings or ActivityManager


        multi sub_cmd:

        -c, --column <column_name_1> <value_1> -c, --column <column_name_2> <value_2> ...
            find all column_name_1 contains value_1 then from result, filter column_name_2 contains value_2

## -p, --previous <database_file> 
return the lines printed before current line, column filter is optional


## -q --query <database_file> "<SQL_raw>"
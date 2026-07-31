

# Log file

## 1. Android logcat/dumpstate
- 

## 2. Wireshark pcap log

# Use case
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

## -m, --make <database_name>
    sub_cmd:
    -i, --input <file_path>

    -t, --type <db type>
        db type: dumpstate or wireshark

## -s, --search <database_file> 
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


## -q --query <database_file> "<SQL_raw>"
from logdb.core.pcap.preprocess import preprocess
from logdb.database import connect_database, create_table, insert_rows
from logdb.config import load_config, extract_columns_from_sql

def db_make(input_path: str, output_path: str) -> int:
    config = load_config("pcap", output_path)
    table = config["table"]
    insert_columns = extract_columns_from_sql(table["columns_sql"])
    insert_columns = ['"line_no"'] + insert_columns + ['"raw_line"']

    records = (
        tuple(record.get(column.strip('"')) for column in insert_columns)
        for record in preprocess(input_path, config)
    )
    print("Done preprocess")

    connection = connect_database(output_path)
    try:
        create_table(
            connection,
            table["name"],
            table["columns_sql"],
        )
        insert_rows(
            connection,
            table["name"],
            insert_columns,
            records,
        )
    finally:
        connection.close()
    return 0


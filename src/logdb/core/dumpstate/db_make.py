from logdb.core.dumpstate.preprocess import preprocess
from logdb.database import connect_database, create_table, insert_rows


def db_make(input_path: str, output_path: str, config: dict) -> int:
    table = config["table"]
    insert_columns = config["insert"]["columns"]

    records = (
        tuple(record.get(column) for column in insert_columns)
        for record in preprocess(input_path, config)
    )

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
COLUMNS = """
    packet_num    BIGINT NOT NULL,
    timestamp     VARCHAR,
    "type"        VARCHAR,
    direction     VARCHAR,
    event_code    VARCHAR,
    event_name    VARCHAR,
    status        VARCHAR,
    data          JSON,
"""


def make_default_config() -> str:
    """Return the default HCI TOML configuration."""
    return "\n".join(
        [
            "[logdb]",
            'type = "hci"',
            "",
            "[table]",
            'name = "hci"',
            'columns_sql = """',
            COLUMNS.strip(),
            '"""',
            "",
        ]
    )
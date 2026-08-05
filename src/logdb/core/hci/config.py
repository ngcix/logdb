COLUMNS = """
    packet_num      BIGINT NOT NULL,
    timestamp       VARCHAR,
    "data.type"     VARCHAR,
    "data.direction" VARCHAR,
    "data.event_code" VARCHAR,
    "data.event_name" VARCHAR,
    "data.status"   VARCHAR,
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
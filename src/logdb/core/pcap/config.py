COLUMNS = """
    line_no             BIGINT PRIMARY KEY,
    frame.number        VARCHAR,
    frame.time          VARCHAR,
    frame.len           VARCHAR,
    ip.src              VARCHAR,
    ip.dst              VARCHAR,
    tcp.srcport         VARCHAR,
    tcp.dstport         VARCHAR,
    udp.srcport         VARCHAR,
    udp.dstport         VARCHAR,
    tcp.flags           VARCHAR,
    protocol            VARCHAR,
    info                TEXT,
    raw_line            TEXT,
"""

TSHARK_FIELDS = [
    "frame.number",
    "frame.time",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "_ws.col.protocol",
    "_ws.col.info",
]

FIELD_MAPPING = {
    "_ws.col.protocol": "protocol",
    "_ws.col.info": "info",
}

INSERT_COLUMNS = [
    "line_no",
    "frame.number",
    "frame.time",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "protocol",
    "info",
    "raw_line",
]


def make_default_config() -> str:
    """Return the default pcap TOML configuration."""
    fields_lines = [f"  '{field}'," for field in TSHARK_FIELDS]
    mapping_lines = [
        f"  '{k}' = '{v}',"
        for k, v in FIELD_MAPPING.items()
    ]
    insert_columns = ", ".join(f'"{column}"' for column in INSERT_COLUMNS)

    return "\n".join(
        [
            "[logdb]",
            'type = "pcap"',
            "",
            "[table]",
            'name = "pcap"',
            'columns_sql = """',
            COLUMNS.strip(),
            '"""',
            "",
            "[insert]",
            "fields = [",
            *fields_lines,
            "]",
            f"columns = [{insert_columns}]",
            "",
            "[field_mapping]",
            *mapping_lines,
            "",
        ]
    )
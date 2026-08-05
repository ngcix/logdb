COLUMNS = """
    line_no             BIGINT PRIMARY KEY,
    "frame.number"      VARCHAR,
    "frame.time"        VARCHAR,
    "frame.len"         VARCHAR,
    "ip.src"            VARCHAR,
    "ip.dst"            VARCHAR,

    "tcp.srcport"       VARCHAR,
    "tcp.dstport"       VARCHAR,
    "udp.srcport"       VARCHAR,
    "udp.dstport"       VARCHAR,
    "tcp.flags"         VARCHAR,
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


def make_default_config() -> str:
    """Return the default pcap TOML configuration."""
    mapping_lines = [
        f'"{k}" = "{v}"'
        for k, v in FIELD_MAPPING.items()
    ]

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
            f"fields = [{', '.join(f'"{field}"' for field in TSHARK_FIELDS)}]",
            "",
            "[field_mapping]",
            *mapping_lines,
            "",
        ]
    )
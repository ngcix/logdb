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


def _extract_columns_from_sql(columns_sql: str) -> list[str]:
    """Parse SQL column definition and return ordered list of column names."""
    import re
    columns = []
    for line in columns_sql.strip().split(','):
        line = line.strip()
        if not line:
            continue
        match = re.match(r'^"([^"]+)"|^(\w+)', line)
        if match:
            name = match.group(1) or match.group(2)
            columns.append(f'"{name}"')
    return columns


def make_default_config() -> str:
    """Return the default pcap TOML configuration."""
    fields_str = ", ".join(f'"{field}"' for field in TSHARK_FIELDS)
    columns_str = ", ".join(_extract_columns_from_sql(COLUMNS))
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
            f"fields = [{fields_str}]",
            f"columns = [{columns_str}]",
            "",
            "[field_mapping]",
            *mapping_lines,
            "",
        ]
    )
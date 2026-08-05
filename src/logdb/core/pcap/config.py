COLUMNS = """
    "frame.number"              VARCHAR,
    "frame.time"                VARCHAR,
    "frame.len"                 VARCHAR,
    "ip.src"                    VARCHAR,
    "ip.dst"                    VARCHAR,
    "tcp.srcport"               VARCHAR,
    "tcp.dstport"               VARCHAR,
    "udp.srcport"               VARCHAR,
    "udp.dstport"               VARCHAR,
    "tcp.flags"                 VARCHAR,
    "wlan.ra"                   VARCHAR,
    "wlan.da"                   VARCHAR,
    "wlan.ta"                   VARCHAR,
    "wlan.sa"                   VARCHAR,
    "wlan_radio.signal_dbm"     VARCHAR,
    "wlan.fixed.status_code"    VARCHAR,
    "wlan.fixed.reason_code"    VARCHAR,
    "wlan.fc.type_subtype"      VARCHAR,
    "_ws.col.protocol"          VARCHAR,
    "_ws.col.info"              TEXT,
"""


def make_default_config() -> str:
    """Return the default pcap TOML configuration."""
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
        ]
    )
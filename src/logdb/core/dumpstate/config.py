
COLUMNS = """
    log_date      VARCHAR,
    log_time      VARCHAR,
    ts_order      BIGINT NOT NULL,
    level         VARCHAR(1),
    uid           VARCHAR,
    pid           VARCHAR,
    tid           VARCHAR,
    tag           VARCHAR NOT NULL,
    message       TEXT NOT NULL,
"""

REGEX = [
    r"^(?P<log_date>\d{2}-\d{2})\s+(?P<log_time>\d{2}:\d{2}:\d{2}\.\d+)--(?P<tag>\S+)(?:\s+(?:--|:)\s*)?(?P<message>.*)$",

    r"^(?:<\d+>)?\[(?P<log_time>\s*\d+\.\d+)\]\s+"
    r"(?:(?P<tag>[^:\[][^:]*):\s+)?(?P<message>.*)$",

    r"^(?P<log_date>[A-Z][a-z]{2} \S+)\s+(?P<log_time>\S+)\s+\S+\s+"
    r"(?P<tag>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",

    r"^\[(?P<log_date>\S+)\s+(?P<log_time>\S+)\]\s+\[[^\]]*\]\s+"
    r"\[(?P<tag>[^\]]*)\]\s+(?P<message>.*)$",

    r"^\s*(?P<pid>\d+)/\s*(?P<tid>\d+)/(?P<tag>[A-Z]+)/"
    r"(?P<level>[A-Z])/\s*[^/]+/\s*(?P<message>.*)$",

    r"^(?P<log_date>\S+)\s+(?P<log_time>\S+)\s+(?P<level>[A-Z])/"
    r"(?P<tag>[^(:\s]+)(?:\(\s*(?P<pid>\d+)\))?:\s*(?P<message>.*)$",

    r"^(?P<log_date>\S+)\s+(?P<log_time>\S+)\s+(?P<uid>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<tid>\S+)\s+(?P<level>[A-Z])\s+"
    r"(?P<tag>[^:]*?)\s*:\s*(?P<message>.*)$",

    r"^(?P<log_date>\S+)\s+(?P<log_time>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<tid>\S+)\s+(?P<level>[A-Z])\s+(?P<tag>[^:]*?)\s*:\s*"
    r"(?P<message>.*)$",
]


def make_default_config() -> str:
    """Return the default dumpstate TOML configuration."""
    regex_lines = [
        f"  '''{pattern}''',"
        for pattern in REGEX
    ]

    return "\n".join(
        [
            "[logdb]",
            'type = "dumpstate"',
            "",
            "[table]",
            'name = "dumpstate"',
            'columns_sql = """',
            COLUMNS.strip(),
            '"""',
            "",
            "[filter]",
            "regex = [",
            *regex_lines,
            "]",
            "",
        ]
    )
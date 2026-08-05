from collections.abc import Callable
from pathlib import Path
from typing import Any
import re
import tomllib


def extract_columns_from_sql(columns_sql: str) -> list[str]:
    """Parse SQL column definition and return ordered list of column names (quoted)."""
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


def _load_dumpstate_default() -> str:
    from logdb.core.dumpstate.config import make_default_config

    return make_default_config()


def _load_pcap_default() -> str:
    from logdb.core.pcap.config import make_default_config

    return make_default_config()


DEFAULT_CONFIG_LOADERS: dict[str, Callable[[], str]] = {
    "dumpstate": _load_dumpstate_default,
    "pcap": _load_pcap_default,
}


def load_config(log_type: str, database_path: str) -> dict[str, Any]:
    """Load a type-specific sidecar config, creating its default when absent."""
    try:
        default_config = DEFAULT_CONFIG_LOADERS[log_type]()
    except KeyError as error:
        raise ValueError(
            f"No default config is defined for log type: {log_type}"
        ) from error

    config_path = Path(database_path).with_suffix(f".{log_type}.toml")
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        config_path.write_text(default_config, encoding="utf-8")

    with config_path.open("rb") as config_file:
        config = tomllib.load(config_file)

    _validate_config(config, log_type)
    return config


def _validate_config(config: dict[str, Any], log_type: str) -> None:
    if config.get("logdb", {}).get("type") != log_type:
        raise ValueError("Config log type does not match the make command")

    table = config.get("table", {})
    columns_sql = table.get("columns_sql")

    if not isinstance(table.get("name"), str):
        raise ValueError("Config must define table.name")
    if not isinstance(columns_sql, str):
        raise ValueError("Config must define table.columns_sql")

    # Extract column names from SQL definition
    insert_columns = extract_columns_from_sql(columns_sql)

    if log_type == "dumpstate":
        patterns = config.get("filter", {}).get("regex")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise ValueError("Config must define filter.regex as a list of patterns")

        # Extract unquoted column names for regex matching
        unquoted_columns = [col.strip('"') for col in insert_columns]
        for pattern in patterns:
            regex_columns = set(re.compile(pattern).groupindex)
            if not regex_columns.issubset(unquoted_columns):
                raise ValueError("Every named regex group must exist in table columns")

    elif log_type == "pcap":
        fields = config.get("insert", {}).get("fields")
        if not isinstance(fields, list) or not all(
            isinstance(field, str) for field in fields
        ):
            raise ValueError("Config must define insert.fields as a list of tshark fields")

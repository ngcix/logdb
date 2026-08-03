from collections.abc import Callable
from pathlib import Path
from typing import Any
import re
import tomllib


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
    insert_columns = config.get("insert", {}).get("columns")

    if not isinstance(table.get("name"), str):
        raise ValueError("Config must define table.name")
    if not isinstance(columns_sql, str) or not isinstance(insert_columns, list):
        raise ValueError("Config must define table.columns_sql and insert.columns")

    if log_type == "dumpstate":
        patterns = config.get("filter", {}).get("regex")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise ValueError("Config must define filter.regex as a list of patterns")

        for pattern in patterns:
            regex_columns = set(re.compile(pattern).groupindex)
            if not regex_columns.issubset(insert_columns):
                raise ValueError("Every named regex group must exist in insert.columns")

    elif log_type == "pcap":
        fields = config.get("insert", {}).get("fields")
        if not isinstance(fields, list) or not all(
            isinstance(field, str) for field in fields
        ):
            raise ValueError("Config must define insert.fields as a list of tshark fields")

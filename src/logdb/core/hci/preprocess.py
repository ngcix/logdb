from collections.abc import Iterator, Mapping
import json
from typing import Any

from logdb.config import extract_columns_from_sql
from .util.hci_uart_parser import HCIUartParser


def _get_nested(obj: Any, path: str) -> Any:
    """Extract value from nested dict using dotted path (e.g., 'data.type')."""
    for key in path.split('.'):
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj


def preprocess(
    log_path: str,
    config: Mapping[str, Any],
) -> Iterator[dict[str, object]]:
    """Parse HCI .cfa log file and yield one record per packet."""
    columns = extract_columns_from_sql(config["table"]["columns_sql"])

    parser = HCIUartParser()
    packets = parser.parse_cfa_file(log_path)

    for line_no, packet in enumerate(packets, start=1):
        packet_dict = packet.to_dict()

        record = {col.strip('"'): None for col in columns}
        record["line_no"] = line_no
        record["raw_line"] = json.dumps(packet_dict)

        for col in columns:
            col_name = col.strip('"')
            if col_name in ("line_no", "raw_line"):
                continue

            if '.' in col_name:
                record[col_name] = _get_nested(packet_dict, col_name)
            else:
                record[col_name] = packet_dict.get(col_name)

        yield record
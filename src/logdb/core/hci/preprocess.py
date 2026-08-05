from collections.abc import Iterator, Mapping
import json
from typing import Any

from logdb.config import extract_columns_from_sql
from .util.hci_uart_parser import HCIUartParser


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
        record["packet_num"] = packet_dict.get("packet_num")
        record["timestamp"] = packet_dict.get("timestamp")
        record["type"] = packet_dict.get("data", {}).get("type")
        record["direction"] = packet_dict.get("data", {}).get("direction")
        record["event_code"] = packet_dict.get("data", {}).get("event_code")
        record["event_name"] = packet_dict.get("data", {}).get("event_name")
        record["status"] = packet_dict.get("data", {}).get("status")
        record["data"] = json.dumps(packet_dict.get("data", {}))
        record["raw_line"] = json.dumps(packet_dict)

        yield record
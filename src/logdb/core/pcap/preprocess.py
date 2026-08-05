from collections.abc import Iterator, Mapping
import subprocess
from typing import Any


def preprocess(
    log_path: str,
    config: Mapping[str, Any],
) -> Iterator[dict[str, object]]:
    """Stream packets from PCAP file using tshark subprocess.

    Yields one record per packet with tshark fields mapped to column names.
    """
    tshark_fields = config["insert"]["fields"]
    field_mapping = config.get("field_mapping", {})
    columns = config["insert"]["columns"]

    cmd = ["tshark", "-r", log_path, "-T", "fields", "-E", "separator=|"]
    for field in tshark_fields:
        cmd.extend(["-e", field]) 

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as proc:
            for line_no, raw_line in enumerate(proc.stdout, start=1):
                text = raw_line.rstrip("\r\n")
                values = text.split("|")

                record = {column: None for column in columns}
                record["line_no"] = line_no
                record["raw_line"] = text

                for tshark_field, value in zip(tshark_fields, values):
                    column_name = field_mapping.get(tshark_field, tshark_field)
                    record[column_name] = value if value else None

                yield record

            if proc.returncode and proc.returncode != 0:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"tshark error: {stderr}")

    except FileNotFoundError:
        raise FileNotFoundError(
            "tshark not found. Install Wireshark: "
            "sudo apt-get install tshark  (Linux) or brew install wireshark (macOS)"
        )

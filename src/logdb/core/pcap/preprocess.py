from collections.abc import Iterator, Mapping
import subprocess
from typing import Any
from logdb.config import extract_columns_from_sql


def preprocess(
    log_path: str,
    config: Mapping[str, Any],
) -> Iterator[dict[str, object]]:
    """Stream packets from PCAP file using tshark subprocess.

    Yields one record per packet with tshark fields as column names.
    """
    columns_sql = config["table"]["columns_sql"]
    columns = extract_columns_from_sql(columns_sql)
    # Remove 'line_no' and 'raw_line' from the tshark fields (they're added separately)
    tshark_fields = [col.strip('"') for col in columns if col.strip('"') not in ("line_no", "raw_line")]

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

                record = {col.strip('"'): None for col in columns}
                record["line_no"] = line_no
                record["raw_line"] = text

                for field, value in zip(tshark_fields, values):
                    record[field] = value if value else None

                yield record

            if proc.returncode and proc.returncode != 0:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"tshark error: {stderr}")

    except FileNotFoundError:
        raise FileNotFoundError(
            "tshark not found. Install Wireshark: "
            "sudo apt-get install tshark  (Linux) or brew install wireshark (macOS)"
        )

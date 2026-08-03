from collections.abc import Iterator, Mapping, Sequence
import re
from typing import Any


def preprocess(
    log_path: str,
    config: Mapping[str, Any],
) -> Iterator[dict[str, object]]:
    """Yield one parsed record mapping for every input line."""
    columns = config["insert"]["columns"]
    patterns = [re.compile(pattern) for pattern in config["filter"]["regex"]]

    with open(log_path, encoding="utf-8", errors="replace") as log_file:
        for line_no, raw_line in enumerate(log_file, start=1):
            text = raw_line.rstrip("\r\n")
            fields = _best_match(text, patterns)

            record = {column: None for column in columns}
            record.update(fields or {})
            record["line_no"] = line_no
            record["ts_order"] = line_no
            record["raw_line"] = text

            if fields is None:
                record["tag"] = "stdout"
                record["message"] = text
            elif not record.get("tag"):
                record["tag"] = "stdout"

            yield record


def _best_match(
    line: str,
    patterns: Sequence[re.Pattern[str]],
) -> dict[str, str] | None:
    """Choose the match with the most populated named groups.

    Earlier regexes win ties because the config order is preserved.
    """
    best_fields: dict[str, str] | None = None
    best_score = -1

    for pattern in patterns:
        match = pattern.fullmatch(line)
        if match is None:
            continue

        fields = {
            name: value.strip()
            for name, value in match.groupdict().items()
            if value is not None
        }
        score = sum(bool(value) for value in fields.values())

        if score > best_score:
            best_fields = fields
            best_score = score

    return best_fields

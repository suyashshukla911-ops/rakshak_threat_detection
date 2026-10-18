import csv
import io
import json
from pathlib import Path


def parse_content(filename: str, content: bytes, max_lines: int) -> tuple[list[dict], list[str]]:
    name = Path(filename).suffix.lower()
    errors: list[str] = []
    records: list[dict] = []
    base_name = Path(filename).name
    if name == ".jsonl":
        for idx, line in enumerate(content.decode("utf-8", errors="replace").splitlines(), start=1):
            if not line.strip():
                continue
            if idx > max_lines:
                errors.append(f"Line limit exceeded at line {idx}")
                break
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("record must be an object")
                obj.setdefault("source_file", base_name)
                obj.setdefault("line_offset", idx)
                records.append(obj)
            except Exception as exc:
                errors.append(f"line {idx}: {exc}")
    elif name == ".csv":
        text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for idx, row in enumerate(reader, start=2):
            if idx > max_lines + 1:
                errors.append(f"Line limit exceeded at line {idx}")
                break
            d = dict(row)
            d.setdefault("source_file", base_name)
            d.setdefault("line_offset", idx)
            records.append(d)
    else:
        obj = json.loads(content.decode("utf-8", errors="replace"))
        if isinstance(obj, dict):
            obj.setdefault("source_file", base_name)
            obj.setdefault("line_offset", 1)
            records = [obj]
        elif isinstance(obj, list):
            records = []
            for idx, item in enumerate(obj[:max_lines], start=1):
                if isinstance(item, dict):
                    item.setdefault("source_file", base_name)
                    item.setdefault("line_offset", idx)
                    records.append(item)
                else:
                    errors.append(f"item {idx}: item must be a JSON object")
        else:
            raise ValueError("JSON must contain an object or array")
    return records, errors



import re
from datetime import datetime
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<level>INFO|WARN|ERROR) "
    r"service=(?P<service>\S+) "
    r"event=(?P<event>\S+)"
    r"(?: (?P<details>.*))?$"
)


def parse_log_line(line: str) -> dict | None:
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    record = match.groupdict()

    record["timestamp"] = datetime.strptime(
        record["timestamp"], "%Y-%m-%d %H:%M:%S"
    )

    details = {}

    for item in (record.pop("details") or "").split():
        if "=" in item:
            key, value = item.split("=", 1)
            details[key] = value

    record["details"] = details
    return record


def parse_log_file(file_path: str | Path) -> list[dict]:
    path = Path(file_path)
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            record = parse_log_line(line)

            if record is None:
                if line.strip():
                    print(f"Skipping unrecognized line {line_number}")
                continue

            record["line_number"] = line_number
            records.append(record)

    return records


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    log_path = project_root / "data" / "sample_incident.log"

    events = parse_log_file(log_path)

    print(f"Parsed events: {len(events)}")
    print(f"Error events: {sum(e['level'] == 'ERROR' for e in events)}")

    for event in events:
        if event["level"] == "ERROR":
            print(
                event["timestamp"],
                event["service"],
                event["event"],
                event["details"],
            )

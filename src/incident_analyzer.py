
from collections import Counter
from datetime import timedelta
from pathlib import Path

from log_parser import parse_log_file


def analyze_incident(events: list[dict]) -> dict:
    if not events:
        return {
            "event_count": 0,
            "error_count": 0,
            "error_summary": {},
            "configuration_changes": [],
            "warnings_before_errors": [],
            "timeline": [],
        }

    events = sorted(events, key=lambda event: event["timestamp"])

    errors = [event for event in events if event["level"] == "ERROR"]
    warnings = [event for event in events if event["level"] == "WARN"]

    error_summary = dict(
        Counter(event["event"] for event in errors)
    )

    config_changes = [
        event
        for event in events
        if event["event"] == "pool_config_changed"
    ]

    warnings_before_errors = []

    for error in errors:
        related_warnings = [
            warning
            for warning in warnings
            if timedelta(0)
            <= error["timestamp"] - warning["timestamp"]
            <= timedelta(minutes=5)
        ]

        for warning in related_warnings:
            warnings_before_errors.append({
                "warning_line": warning["line_number"],
                "warning_event": warning["event"],
                "error_line": error["line_number"],
                "error_event": error["event"],
                "time_difference_seconds": (
                    error["timestamp"] - warning["timestamp"]
                ).total_seconds(),
            })

    timeline = [
        {
            "timestamp": event["timestamp"].isoformat(),
            "level": event["level"],
            "service": event["service"],
            "event": event["event"],
            "details": event["details"],
            "line_number": event["line_number"],
        }
        for event in events
    ]

    return {
        "event_count": len(events),
        "error_count": len(errors),
        "error_summary": error_summary,
        "configuration_changes": [
            {
                "line_number": event["line_number"],
                "timestamp": event["timestamp"].isoformat(),
                "details": event["details"],
            }
            for event in config_changes
        ],
        "warnings_before_errors": warnings_before_errors,
        "timeline": timeline,
    }


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    events = parse_log_file(
        project_root / "data" / "sample_incident.log"
    )

    report = analyze_incident(events)

    print("\n--- TraceLens Incident Analysis ---")
    print(f"Total events: {report['event_count']}")
    print(f"Total errors: {report['error_count']}")
    print(f"Error summary: {report['error_summary']}")
    print(f"Configuration changes: {len(report['configuration_changes'])}")
    print(f"Warning-error correlations: {len(report['warnings_before_errors'])}")

    for change in report["configuration_changes"]:
        print("Configuration change:", change)

    for correlation in report["warnings_before_errors"]:
        print("Correlation:", correlation)

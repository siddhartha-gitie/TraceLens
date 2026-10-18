
from datetime import datetime


IMPORTANT_LEVELS = {
    "WARN",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "FATAL",
}

CONFIGURATION_EVENTS = {
    "pool_config_changed",
    "pool_configured",
    "configuration_changed",
    "config_changed",
    "settings_updated",
}


def _parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _build_claim(event):
    """Build a factual claim from an actual parsed log record."""
    event_name = str(event.get("event", "unknown_event"))
    details = event.get("details", {})

    if not isinstance(details, dict):
        details = {}

    claim = f"The source records {event_name}"

    if details:
        fields = ", ".join(
            f"{key}={value}"
            for key, value in sorted(details.items())
        )
        claim += f" with {fields}"

    return claim


def build_evidence_candidates(events: list[dict]) -> list[dict]:
    """
    Generate reproducible evidence candidates from parsed events.

    Include warning/error events, recognized configuration changes,
    and INFO events within five minutes of warning/error events.

    Candidate claims and line numbers come directly from source records.
    Inclusion as evidence does not prove that an event caused an incident.
    """
    if not events:
        return []

    ordered = sorted(
        events,
        key=lambda event: event.get("line_number", 0),
    )

    important_events = [
        event
        for event in ordered
        if str(event.get("level", "")).upper() in IMPORTANT_LEVELS
    ]

    important_times = [
        _parse_timestamp(event.get("timestamp"))
        for event in important_events
    ]
    important_times = [
        timestamp
        for timestamp in important_times
        if timestamp is not None
    ]

    candidates = []

    for event in ordered:
        level = str(event.get("level", "")).upper()
        event_name = str(event.get("event", "")).lower()

        is_important = level in IMPORTANT_LEVELS
        is_configuration_change = (
            event_name in CONFIGURATION_EVENTS
        )

        include_context = False
        event_time = _parse_timestamp(event.get("timestamp"))

        if level == "INFO" and event_time is not None:
            include_context = any(
                abs(
                    (event_time - important_time).total_seconds()
                ) <= 300
                for important_time in important_times
            )

        if not (
            is_important
            or is_configuration_change
            or include_context
        ):
            continue

        line_number = event.get("line_number")

        if (
            not isinstance(line_number, int)
            or isinstance(line_number, bool)
            or line_number < 1
        ):
            continue

        details = event.get("details", {})
        if not isinstance(details, dict):
            details = {}

        candidates.append(
            {
                "evidence_id": f"E{len(candidates) + 1}",
                "line_number": line_number,
                "claim": _build_claim(event),
                "event": event.get("event"),
                "service": event.get("service"),
                "level": level,
                "timestamp": event.get("timestamp"),
                "details": details,
            }
        )

    return candidates

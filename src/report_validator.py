from __future__ import annotations

import re
from typing import Any


FIELD_ALIASES = {
    "old size": "old_size",
    "new size": "new_size",
    "wait time": "wait_ms",
    "wait ms": "wait_ms",
    "pool size": "pool_size",
    "active connections": "active_connections",
    "usage pct": "usage_pct",
}

FIELD_NAMES = {
    "old_size",
    "new_size",
    "wait_ms",
    "wait_seconds",
    "status",
    "pool_size",
    "timeout",
    "duration_ms",
    "active_connections",
    "usage_pct",
    "error_code",
    "job_id",
    "queue_size",
    "max_connections",
    "latency_ms",
    "attempts",
    "user_id",
    "reason",
}


def validate_report(
    report: dict[str, Any],
    events: list[dict],
) -> dict[str, Any]:
    """
    Validate evidence claims against parsed log events.

    Checks source-line existence, identifiable event names, and explicit
    field values. Verified evidence means the cited facts match the source;
    it does not establish that a proposed root cause is correct.

    `unsupported_claims` remains a legacy frontend-compatible aggregate
    containing all claims that are not fully verified. Use the specific
    category lists for category counts.
    """

    events_by_line: dict[int, dict] = {}
    event_names: set[str] = set()

    for event in events:
        if not isinstance(event, dict):
            continue

        line_number = event.get("line_number")
        if isinstance(line_number, int) and not isinstance(line_number, bool):
            events_by_line[line_number] = event

        event_name = event.get("event")
        if isinstance(event_name, str) and event_name.strip():
            event_names.add(event_name.strip())

    verified_claims: list[dict] = []
    mismatched_claims: list[dict] = []
    partially_verified_claims: list[dict] = []
    unsupported_claims: list[dict] = []

    likely_causes = report.get("likely_causes", [])
    if not isinstance(likely_causes, list):
        likely_causes = []

    for cause in likely_causes:
        if not isinstance(cause, dict):
            continue

        evidence_items = cause.get("supporting_evidence", [])
        if not isinstance(evidence_items, list):
            continue

        for evidence in evidence_items:
            claim = _evidence_to_text(evidence)
            line_number = _extract_line_number(evidence)

            if line_number is None:
                unsupported_claims.append({
                    "claim": claim,
                    "status": "unsupported",
                    "reason": "No identifiable log line number.",
                })
                continue

            event = events_by_line.get(line_number)
            if event is None:
                unsupported_claims.append({
                    "claim": claim,
                    "line_number": line_number,
                    "status": "unsupported",
                    "reason": (
                        f"Log line {line_number} does not correspond "
                        "to a parsed event."
                    ),
                })
                continue

            actual_event = str(event.get("event", ""))
            actual_details = event.get("details", {})
            if not isinstance(actual_details, dict):
                actual_details = {}

            candidate_events = _extract_event_candidates(
                claim=claim,
                event_names=event_names,
                actual_event=actual_event,
            )
            wrong_events = [
                name for name in candidate_events
                if name.casefold() != actual_event.casefold()
            ]

            base_claim = {
                "claim": claim,
                "line_number": line_number,
                "actual_event": actual_event,
                "actual_service": event.get("service"),
                "actual_level": event.get("level"),
                "fields_checked": [],
            }

            if wrong_events:
                mismatched_claims.append({
                    **base_claim,
                    "status": "mismatch",
                    "reason": (
                        f"Line {line_number} contains event "
                        f"'{actual_event}', but the claim refers to "
                        f"'{', '.join(wrong_events)}'."
                    ),
                })
                continue

            claimed_fields = _extract_claimed_fields(claim)
            field_errors: list[str] = []
            fields_checked: list[str] = []

            for claimed_key, claimed_value in claimed_fields.items():
                normalized_key = _normalize_key(claimed_key)

                actual_key = next(
                    (
                        key for key in actual_details
                        if _normalize_key(str(key)) == normalized_key
                    ),
                    None,
                )

                if actual_key is None:
                    field_errors.append(
                        f"Claimed field '{claimed_key}' is not present "
                        "in the source event details."
                    )
                    continue

                actual_value = str(actual_details[actual_key]).strip()
                expected_value = str(claimed_value).strip()

                if actual_value.casefold() != expected_value.casefold():
                    field_errors.append(
                        f"Field '{actual_key}' was claimed as "
                        f"'{expected_value}', but the source contains "
                        f"'{actual_value}'."
                    )
                else:
                    fields_checked.append(str(actual_key))

            base_claim["fields_checked"] = fields_checked

            if field_errors:
                mismatched_claims.append({
                    **base_claim,
                    "status": "mismatch",
                    "reason": " ".join(field_errors),
                })
                continue

            if not candidate_events and not claimed_fields:
                partially_verified_claims.append({
                    **base_claim,
                    "status": "partially_verified",
                    "reason": (
                        "The source line exists, but the claim does not "
                        "contain identifiable event or field details "
                        "to compare."
                    ),
                })
                continue

            if not candidate_events:
                partially_verified_claims.append({
                    **base_claim,
                    "status": "partially_verified",
                    "reason": (
                        "The source line exists, but an identifiable "
                        "event name could not be confirmed."
                    ),
                })
                continue

            verified_claims.append({
                **base_claim,
                "status": "verified",
                "reason": (
                    "The cited event matches the source. Any identifiable "
                    "field values in the claim also match the parsed log "
                    "record."
                ),
            })

    # Legacy aggregate retained for compatibility with the existing UI.
    all_unverified = (
        unsupported_claims
        + mismatched_claims
        + partially_verified_claims
    )

    return {
        "verified_claims": verified_claims,
        "mismatched_claims": mismatched_claims,
        "partially_verified_claims": partially_verified_claims,
        "unsupported_claims": all_unverified,
        "claims_checked": len(verified_claims) + len(all_unverified),
        "validation_note": (
            "Validation checks cited source lines, identifiable event "
            "names, and explicit field values. A matching claim does not "
            "prove that the proposed cause is correct."
        ),
    }


def _evidence_to_text(evidence: Any) -> str:
    """Convert string or structured evidence into readable text."""

    if isinstance(evidence, str):
        return evidence

    if isinstance(evidence, dict):
        for key in ("claim", "evidence", "text", "description", "source"):
            value = evidence.get(key)
            if isinstance(value, str):
                return value
        return str(evidence)

    return str(evidence)


def _extract_line_number(evidence: Any) -> int | None:
    """Extract a line number from structured evidence or claim text."""

    if isinstance(evidence, dict):
        for key in ("line_number", "line", "log_line"):
            value = evidence.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        return _extract_line_number(_evidence_to_text(evidence))

    if not isinstance(evidence, str):
        return None

    match = re.search(
        r"\bline(?:_number)?\s*:?\s*(\d+)\b",
        evidence,
        re.IGNORECASE,
    )
    return int(match.group(1)) if match else None


def _normalize_key(key: str) -> str:
    """Normalize field names and common human-readable aliases."""

    normalized = re.sub(r"[_\-.]+", " ", key.casefold()).strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return FIELD_ALIASES.get(normalized, normalized.replace(" ", "_"))


def _extract_event_candidates(
    claim: str,
    event_names: set[str],
    actual_event: str,
) -> list[str]:
    """
    Identify event names in a claim while excluding field keys and values.

    In particular, values after key=value or key:value are not interpreted
    as event names (e.g. invalid_password in reason=invalid_password).
    """

    candidates: list[str] = []

    # Mask explicit key/value expressions before scanning for event tokens.
    # This prevents values such as invalid_password and AUTH-503 from being
    # mistaken for event names.
    masked_claim = re.sub(
        r"\b[A-Za-z][A-Za-z0-9_.-]*\s*[=:]\s*"
        r"""(?:'[^']*'|"[^"]*"|[^\s,;]+)""",
        " ",
        claim,
    )

    explicit_field_names = {
        key.casefold()
        for key in re.findall(
            r"\b([A-Za-z][A-Za-z0-9_.-]*)\s*[=:]",
            claim,
        )
    }

    # Known event names mentioned outside key/value expressions.
    for name in event_names:
        if re.search(
            rf"(?<![\w]){re.escape(name)}(?![\w])",
            masked_claim,
            re.IGNORECASE,
        ):
            candidates.append(name)

    # Detect likely incorrect event names, while excluding field names,
    # line labels, and tokens that appeared as explicit field keys/values.
    for name in re.findall(
        r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b",
        masked_claim,
    ):
        normalized = name.casefold()

        if normalized in explicit_field_names or normalized in FIELD_NAMES:
            continue
        if normalized in {"line_number", "log_line"}:
            continue
        if normalized == actual_event.casefold():
            continue
        if any(item.casefold() == normalized for item in candidates):
            continue

        candidates.append(name)

    return candidates


def _extract_claimed_fields(claim: str) -> dict[str, str]:
    """Extract field/value claims in machine-style and natural-language text."""

    fields: dict[str, str] = {}

    # Machine-style key/value pairs: old_size=20, status: 503, reason=invalid_password.
    explicit_pattern = (
        r"\b([A-Za-z][A-Za-z0-9_.-]*)\s*[=:]\s*"
        r"""['"]?([^'"\s,;]+)['"]?"""
    )
    for match in re.finditer(explicit_pattern, claim):
        key = match.group(1).strip()
        value = match.group(2).strip()
        if key.casefold() not in {"line", "line_number", "log_line"}:
            fields[_normalize_key(key)] = value

    # Field followed by a value without '=' or ':':
    # old_size '20', new_size '5', wait_ms '1500'.
    known_fields = [
        "old_size",
        "new_size",
        "wait_ms",
        "wait_seconds",
        "status",
        "pool_size",
        "timeout",
        "duration_ms",
        "active_connections",
        "usage_pct",
        "error_code",
        "job_id",
        "queue_size",
        "max_connections",
        "latency_ms",
        "attempts",
        "user_id",
    ]

    for key in known_fields:
        pattern = (
            rf"\b{re.escape(key)}\b\s+"
            r"""(?:of\s+)?['"]?([+-]?\d+(?:\.\d+)?)['"]?"""
        )
        match = re.search(pattern, claim, re.IGNORECASE)
        if match:
            fields[_normalize_key(key)] = match.group(1)

    # Natural-language aliases, e.g. "old size of 20" and "wait time 1200 ms".
    natural_language_patterns = [
        (r"\bold\s+size\s+(?:of\s+)?['\"]?(\d+)['\"]?", "old_size"),
        (r"\bnew\s+size\s+(?:of\s+)?['\"]?(\d+)['\"]?", "new_size"),
        (
            r"\bwait\s+time\s+(?:of\s+)?['\"]?(\d+)['\"]?\s*ms\b",
            "wait_ms",
        ),
        (r"\bstatus\s+(?:of\s+)?['\"]?(\d{3})['\"]?", "status"),
        (r"\bpool\s+size\s+(?:of\s+)?['\"]?(\d+)['\"]?", "pool_size"),
    ]

    for pattern, field_name in natural_language_patterns:
        match = re.search(pattern, claim, re.IGNORECASE)
        if match:
            fields[field_name] = match.group(1)

    return fields

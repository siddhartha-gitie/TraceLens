import json
from datetime import datetime, timezone
import re
import requests

from evidence_selector import build_evidence_candidates


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "qwen2.5:3b"

IMPORTANT_LEVELS = {
    "WARN",
    "WARNING",
    "ERROR",
    "CRITICAL",
    "FATAL",
}

CONFIGURATION_WINDOW_SECONDS = 300


def _parse_timestamp(value):
    """Parse timestamps and normalize them for safe comparison."""
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return None
    else:
        return None

    # Treat timezone-naive log timestamps consistently as UTC.
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)

    return timestamp


def _is_valid_line_number(value):
    """Accept positive integer line numbers, but reject booleans."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    )


def _insufficient_evidence_report(analysis, events):
    """Return a conservative report without asking the LLM to guess."""
    event_count = analysis.get("event_count", len(events))
    if not isinstance(event_count, int) or isinstance(event_count, bool):
        event_count = len(events)

    if event_count == 0:
        summary = (
            "No parseable log events were available. The incident cause "
            "cannot be determined from the supplied input."
        )
    else:
        summary = (
            f"The parser found {event_count} log event(s), but none "
            "provided warning/error or recognized configuration-change "
            "evidence. The cause cannot be determined from the available logs."
        )

    return {
        "incident_summary": summary,
        "likely_causes": [],
        "alternative_explanations": [],
        "recommended_checks": [
            "Collect application logs from before, during, and after the event.",
            "Check service and operating-system shutdown or restart logs.",
            "Review deployment history and configuration changes near the event.",
            "Inspect service health, resource metrics, and dependency logs.",
        ],
        "confidence": "low",
    }


def _expand_supporting_evidence(
    selected_ids,
    evidence_candidates,
    analysis,
):
    """
    Expand model-selected evidence using source-derived candidates.

    Include related warning/error pairs and configuration changes that
    precede relevant warning/error events by no more than five minutes.
    Temporal proximity is not proof of causation.
    """
    candidate_by_id = {
        item["evidence_id"]: item
        for item in evidence_candidates
        if isinstance(item, dict)
        and isinstance(item.get("evidence_id"), str)
        and _is_valid_line_number(item.get("line_number"))
    }

    candidate_by_line = {
        item["line_number"]: item
        for item in candidate_by_id.values()
    }

    selected_lines = set()

    # Accept only IDs created by the Python evidence selector.
    for evidence_id in selected_ids:
        if not isinstance(evidence_id, str):
            continue

        candidate = candidate_by_id.get(evidence_id.strip())
        if candidate is not None:
            selected_lines.add(candidate["line_number"])

    relationships = analysis.get("warnings_before_errors", [])
    if not isinstance(relationships, list):
        relationships = []

    configuration_changes = analysis.get("configuration_changes", [])
    if not isinstance(configuration_changes, list):
        configuration_changes = []

    valid_configuration_changes = []
    for config_event in configuration_changes:
        if not isinstance(config_event, dict):
            continue

        config_line = config_event.get("line_number")
        if (
            not _is_valid_line_number(config_line)
            or config_line not in candidate_by_line
        ):
            continue

        config_timestamp = _parse_timestamp(config_event.get("timestamp"))
        if config_timestamp is None:
            continue

        valid_configuration_changes.append((config_line, config_timestamp))

    # Expand until no additional lines can be added.
    changed = True
    while changed:
        changed = False

        # If either endpoint of a known warning/error relationship is
        # selected, include both endpoints when they are candidates.
        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue

            warning_line = relationship.get("warning_line")
            error_line = relationship.get("error_line")

            if (
                not _is_valid_line_number(warning_line)
                or not _is_valid_line_number(error_line)
            ):
                continue

            if (
                warning_line in selected_lines
                or error_line in selected_lines
            ):
                for line_number in (warning_line, error_line):
                    if (
                        line_number in candidate_by_line
                        and line_number not in selected_lines
                    ):
                        selected_lines.add(line_number)
                        changed = True

        # If a configuration change or a related warning/error is selected,
        # include the change and warning/error candidates within five minutes.
        for config_line, config_timestamp in valid_configuration_changes:
            related_lines = []

            for line_number, candidate in candidate_by_line.items():
                if line_number == config_line:
                    continue

                level = str(candidate.get("level", "")).upper()
                if level not in IMPORTANT_LEVELS:
                    continue

                event_timestamp = _parse_timestamp(candidate.get("timestamp"))
                if event_timestamp is None:
                    continue

                elapsed_seconds = (
                    event_timestamp - config_timestamp
                ).total_seconds()

                if 0 <= elapsed_seconds <= CONFIGURATION_WINDOW_SECONDS:
                    related_lines.append(line_number)

            config_is_selected = config_line in selected_lines
            related_event_is_selected = any(
                line_number in selected_lines for line_number in related_lines
            )

            if config_is_selected or related_event_is_selected:
                if config_line not in selected_lines:
                    selected_lines.add(config_line)
                    changed = True

                for line_number in related_lines:
                    if line_number not in selected_lines:
                        selected_lines.add(line_number)
                        changed = True

    # Build final citations only from source-derived candidates.
    return [
        {
            "claim": candidate_by_line[line_number]["claim"],
            "line_number": line_number,
        }
        for line_number in sorted(selected_lines)
        if line_number in candidate_by_line
    ]



def _sanitize_causal_hypothesis(
    hypothesis: str,
    evidence: list[dict],
) -> str:
    """Avoid presenting an unsupported causal relationship as established."""

    causal_pattern = re.compile(
        r"\b(?:"
        r"caused\s+by|caused|causes|cause\s+of|"
        r"due\s+to|because\s+of|resulted\s+in|results\s+in|"
        r"led\s+to|leads\s+to|triggered|responsible\s+for|"
        r"as\s+a\s+result\s+of|attributable\s+to|"
        r"directly\s+caused|is\s+the\s+cause\s+of"
        r")\b",
        re.IGNORECASE,
    )

    if not causal_pattern.search(hypothesis):
        return hypothesis

    observed_events = []

    for item in evidence:
        if not isinstance(item, dict):
            continue

        event_name = (
            item.get("actual_event")
            or item.get("event")
            or item.get("event_name")
            or item.get("event_type")
        )

        if not isinstance(event_name, str) or not event_name.strip():
            claim = str(item.get("claim", ""))
            match = re.search(
                r"\brecords\s+([a-z][a-z0-9_]*)",
                claim,
                re.IGNORECASE,
            )
            if match:
                event_name = match.group(1)

        if isinstance(event_name, str) and event_name.strip():
            event_name = event_name.strip()
            if event_name not in observed_events:
                observed_events.append(event_name)

    if len(observed_events) >= 2:
        event_description = ", ".join(observed_events[:3])
        return (
            f"The observed events ({event_description}) may be related, "
            "but the supplied logs do not establish a causal relationship. "
            "Further investigation is needed."
        )

    return (
        "A possible explanation requires further investigation. "
        "The supplied logs do not establish a causal relationship."
    )


def investigate_incident(
    analysis: dict,
    events: list[dict] | None = None,
) -> dict:
    """Investigate an incident using Ollama and source-grounded evidence."""

    if not isinstance(analysis, dict):
        raise ValueError("Incident analysis must be a dictionary.")

    if events is None:
        events = []

    if not isinstance(events, list):
        raise ValueError("Source events must be a list.")

    # Generate evidence candidates once. Do not ask the LLM to invent a
    # cause when there is no relevant source evidence.
    evidence_candidates = build_evidence_candidates(events)

    if not evidence_candidates:
        return _insufficient_evidence_report(analysis, events)

    source_events = json.dumps(events, indent=2, default=str)
    candidate_data = json.dumps(
        evidence_candidates,
        indent=2,
        default=str,
    )
    incident_data = json.dumps(analysis, indent=2, default=str)

    prompt = f"""
You are TraceLens, a software incident investigation agent.

Analyze the incident using the original source events, timeline,
and Python-generated evidence candidates.

EVIDENCE AND ROOT-CAUSE RULES:
1. Separate observed facts from hypotheses.
2. Never invent events, field values, timestamps, or evidence.
3. Temporal correlation is not proof of causation.
4. An event occurring before another event does not prove it caused
   the later event.
5. Do not reverse cause and effect.
6. Do not claim a configuration change occurred if the analysis contains
   no such change. You may recommend checking for one.
7. Explain what evidence is missing to establish a proposed cause.
8. A verified source citation verifies the cited facts only; it does not
   verify the causal hypothesis.
9. If causation is not directly established, use cautious wording such
   as "may be related" or "is a possible explanation."
10. If the evidence is insufficient to identify a likely cause, return
    an empty "likely_causes" list rather than inventing one.
11. Use low confidence when the cause is uncertain.
12. Return only valid JSON, without Markdown fences.

EVIDENCE SELECTION RULES:
1. Select evidence only from the supplied candidates.
2. Return supporting_evidence as a list of evidence_id strings.
3. Do not return evidence objects, claims, or line numbers in that list.
4. Select distinct observations relevant to the hypothesis.
5. Consider configuration changes, warnings preceding errors,
   connection failures, and subsequent application failures.
6. Do not invent evidence IDs.
7. If no candidate is relevant, return an empty evidence list.
8. Do not infer that a configuration change caused an incident merely
   because the events occurred close together.

Original parsed source events:
{source_events}

Evidence candidates generated by Python:
{candidate_data}

Incident analysis:
{incident_data}

Return a JSON object with this structure:
{{
  "incident_summary": "Concise summary of observed events",
  "likely_causes": [
    {{
      "hypothesis": "A plausible explanation, explicitly identified as a hypothesis",
      "supporting_evidence": ["E1", "E2"],
      "missing_evidence": [
        "Information needed to assess the hypothesis"
      ]
    }}
  ],
  "alternative_explanations": [
    "Other plausible explanations, clearly identified as possibilities"
  ],
  "recommended_checks": [
    "Concrete investigation steps"
  ],
  "confidence": "low"
}}

Confidence must be exactly one of: low, medium, high.
Use only evidence IDs present in the supplied candidates.
Do not claim that temporal correlation proves causation.
"""

    payload = {
        "model": MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=180,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Could not communicate with Ollama: {exc}"
        ) from exc

    try:
        result = response.json()
        content = result["message"]["content"]
        report = json.loads(content)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(
            "Ollama returned an invalid or incomplete JSON response."
        ) from exc

    if not isinstance(report, dict):
        raise ValueError("The investigator did not return a JSON object.")

    if not isinstance(report.get("incident_summary"), str):
        report["incident_summary"] = "Incident investigation completed."

    causes = report.get("likely_causes", [])
    if not isinstance(causes, list):
        raise ValueError("'likely_causes' must be a list.")

    sanitized_causes = []

    for cause in causes:
        if not isinstance(cause, dict):
            continue

        selected_ids = cause.get("supporting_evidence", [])
        if not isinstance(selected_ids, list):
            selected_ids = []

        verified_source_evidence = _expand_supporting_evidence(
            selected_ids=selected_ids,
            evidence_candidates=evidence_candidates,
            analysis=analysis,
        )

        # A cause must reference valid source-grounded evidence.
        if not verified_source_evidence:
            continue

        cause["supporting_evidence"] = verified_source_evidence

        hypothesis = cause.get("hypothesis")
        if not isinstance(hypothesis, str) or not hypothesis.strip():
            hypothesis = "A possible cause requires further investigation."

        # Deterministic wording safeguard. This does not establish or
        # disprove causation; it prevents causal wording from being treated
        # as proven solely because the cited events exist.
        cause["hypothesis"] = _sanitize_causal_hypothesis(
            hypothesis,
            verified_source_evidence,
        )

        missing_evidence = cause.get("missing_evidence")
        if not isinstance(missing_evidence, list):
            missing_evidence = []

        cause["missing_evidence"] = missing_evidence
        sanitized_causes.append(cause)

    report["likely_causes"] = sanitized_causes

    if not sanitized_causes:
        report["confidence"] = "low"

        alternatives = report.get("alternative_explanations")
        if not isinstance(alternatives, list):
            report["alternative_explanations"] = []

        checks = report.get("recommended_checks")
        if not isinstance(checks, list):
            checks = []

        checks.extend([
            "Collect additional logs around the incident time.",
            "Verify relevant configuration and deployment changes.",
            "Check service health metrics and dependency logs.",
        ])

        report["recommended_checks"] = list(dict.fromkeys(checks))

    if report.get("confidence") not in {"low", "medium", "high"}:
        report["confidence"] = "low"

    if not isinstance(report.get("alternative_explanations"), list):
        report["alternative_explanations"] = []

    if not isinstance(report.get("recommended_checks"), list):
        report["recommended_checks"] = []

    return report

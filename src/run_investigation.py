
import json
from pathlib import Path

from incident_analyzer import analyze_incident
from investigator import investigate_incident
from log_parser import parse_log_file
from report_validator import validate_report


def main():
    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "data" / "sample_incident.log"

    print("TraceLens: Starting incident investigation...\n")

    # Step 1: Parse logs
    events = parse_log_file(log_file)

    # Step 2: Analyze events using Python
    analysis = analyze_incident(events)

    print(f"Events analyzed: {analysis['event_count']}")
    print(f"Errors detected: {analysis['error_count']}")
    print("Generating AI investigation report...\n")

    # Step 3: Generate the AI report
    report = investigate_incident(analysis)

    # Step 4: Validate the cited evidence
    validation = validate_report(report, events)

    # Step 5: Display the report
    print("=== TraceLens Investigation Report ===\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    print("\n=== Evidence Validation ===\n")
    print(json.dumps(validation, indent=2, ensure_ascii=False))

    # Step 6: Save both outputs
    data_dir = project_root / "data"

    report_path = data_dir / "incident_report.json"
    validation_path = data_dir / "validation_report.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    with validation_path.open("w", encoding="utf-8") as file:
        json.dump(validation, file, indent=2, ensure_ascii=False)

    print(f"\nIncident report saved to: {report_path}")
    print(f"Validation report saved to: {validation_path}")


if __name__ == "__main__":
    main()

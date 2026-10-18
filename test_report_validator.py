
from src.report_validator import validate_report


def make_events():
    """Create sample parsed log events for testing."""

    return [
        {
            "line_number": 4,
            "timestamp": "2026-10-15T10:02:00",
            "level": "INFO",
            "service": "database",
            "event": "pool_config_changed",
            "details": {
                "old_size": "20",
                "new_size": "5",
            },
        },
        {
            "line_number": 5,
            "timestamp": "2026-10-15T10:02:05",
            "level": "WARN",
            "service": "database",
            "event": "pool_wait_time_high",
            "details": {
                "wait_ms": "1200",
            },
        },
    ]


def make_report(evidence):
    """Wrap evidence strings in the report structure."""

    return {
        "likely_causes": [
            {
                "hypothesis": "Test hypothesis",
                "supporting_evidence": evidence,
            }
        ]
    }


def test_correct_event_and_field_values_are_verified():
    report = make_report([
        "Line 4: pool_config_changed with old_size '20' and new_size '5'",
    ])

    result = validate_report(report, make_events())

    assert len(result["verified_claims"]) == 1
    assert result["verified_claims"][0]["status"] == "verified"
    assert result["verified_claims"][0]["fields_checked"] == [
        "old_size",
        "new_size",
    ]


def test_incorrect_field_value_is_flagged():
    report = make_report([
        "Line 5: pool_wait_time_high with wait_ms '1500'",
    ])

    result = validate_report(report, make_events())

    assert len(result["mismatched_claims"]) == 1
    assert "1200" in result["mismatched_claims"][0]["reason"]
    assert result["mismatched_claims"][0]["status"] == "mismatch"


def test_incorrect_event_name_is_flagged():
    report = make_report([
        "Line 5: connection_timeout",
    ])

    result = validate_report(report, make_events())

    assert len(result["mismatched_claims"]) == 1
    assert result["mismatched_claims"][0]["actual_event"] == (
        "pool_wait_time_high"
    )


def test_nonexistent_line_is_unsupported():
    report = make_report([
        "Line 99: missing_event",
    ])

    result = validate_report(report, make_events())

    assert any(
        claim["status"] == "unsupported"
        for claim in result["unsupported_claims"]
    )


def test_claim_without_identifiable_details_is_partial():
    report = make_report([
        "Line 5: an issue occurred",
    ])

    result = validate_report(report, make_events())

    assert len(result["partially_verified_claims"]) == 1


def test_claim_without_line_number_is_unsupported():
    report = make_report([
        "The database experienced a timeout.",
    ])

    result = validate_report(report, make_events())

    assert any(
        claim["status"] == "unsupported"
        for claim in result["unsupported_claims"]
    )


def test_claim_count_includes_each_evidence_item_once():
    report = make_report([
        "Line 4: pool_config_changed with old_size '20' and new_size '5'",
        "Line 5: pool_wait_time_high with wait_ms '1500'",
        "Line 5: connection_timeout",
        "Line 99: missing_event",
    ])

    result = validate_report(report, make_events())

    assert result["claims_checked"] == 4
    assert len(result["verified_claims"]) == 1
    assert len(result["mismatched_claims"]) == 2
    assert len(result["partially_verified_claims"]) == 0
    assert sum(
        claim["status"] == "unsupported"
        for claim in result["unsupported_claims"]
    ) == 1



from src.report_validator import _extract_claimed_fields


def test_natural_language_pool_size_claims():
    claim = (
        "Line 4: pool_config_changed with old size '20' "
        "and new size '5'"
    )

    fields = _extract_claimed_fields(claim)

    assert fields["old_size"] == "20"
    assert fields["new_size"] == "5"
    assert "size" not in fields


def test_natural_language_wait_time_with_of():
    claim = (
        "Line 5: pool_wait_time_high warning with "
        "wait time of '1200' ms"
    )

    fields = _extract_claimed_fields(claim)

    assert fields["wait_ms"] == "1200"
    assert "of" not in fields
    assert "time" not in fields


def test_wait_time_without_of():
    fields = _extract_claimed_fields(
        "Line 9: pool_wait_time_high with wait time '1800' ms"
    )

    assert fields["wait_ms"] == "1800"

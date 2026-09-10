from __future__ import annotations

from cloudnative_security.data_quality import (
    DataQualityRule,
    FAIL,
    PASS,
    UNKNOWN,
    aggregate_quality,
    evaluate_data_quality,
)


def test_completeness_and_uniqueness_report_real_failures() -> None:
    rows = [{"id": 1, "name": "one"}, {"id": 1, "name": ""}, {"id": 2, "name": "two"}]
    results = evaluate_data_quality(rows, [
        DataQualityRule("required-name", "completeness", required_fields=["id", "name"]),
        DataQualityRule("unique-id", "uniqueness", key_fields=["id"]),
    ])
    assert results[0].status == FAIL
    assert results[0].failed_count == 1
    assert results[0].examples[0]["detail"]["missing_fields"] == ["name"]
    assert results[1].failed_count == 2
    assert results[1].details["duplicate_rate"] > 0


def test_dimensions_validate_types_values_references_and_lineage() -> None:
    rows = [
        {"id": "a", "source": "api", "enabled": True, "parent": "root", "user_id": 1},
        {"id": "a", "source": "export", "enabled": True, "parent": "root", "user_id": 1},
    ]
    rules = [
        DataQualityRule("types", "type_consistency", expected_types={"enabled": "bool"}),
        DataQualityRule("valid", "field_validity", fields=["id"], patterns={"id": r"[a-z]"}),
        DataQualityRule("ref", "reference_integrity", reference_fields={"user_id": "users"}),
        DataQualityRule("lineage", "lineage_integrity", lineage_fields=["parent"]),
        DataQualityRule("sources", "cross_source_consistency", source_field="source", compare_fields=["enabled"], key_fields=["id"]),
    ]
    result = evaluate_data_quality(rows, rules, references={"users": [{"id": 1}]})
    assert all(item.status == PASS for item in result)


def test_missing_evidence_is_unknown_not_failure() -> None:
    rules = [
        DataQualityRule("types", "type_consistency", expected_types={"count": "int"}),
        DataQualityRule("refs", "reference_integrity", reference_fields={"owner": "users"}),
        DataQualityRule("time", "temporal_continuity", time_field="observed_at", interval_seconds=60),
    ]
    result = evaluate_data_quality([], rules)
    assert [item.status for item in result] == [UNKNOWN, UNKNOWN, UNKNOWN]
    assert all(item.score is None and item.evidence_present is False for item in result)


def test_aggregate_dimensions_keep_legacy_summary_shape() -> None:
    summary = aggregate_quality(
        [{"id": 1, "name": "x", "status": "PASS"}, {"id": 1, "status": "UNKNOWN"}],
        required_fields=["id", "name"], key_fields=["id"],
    )
    assert summary["completeness"] == 50.0
    assert summary["duplicate_rate"] == 50.0
    assert summary["unknown_rate"] == 50.0

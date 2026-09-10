from __future__ import annotations

from cloudnative_security.compare import compare_tasks


def test_compare_tasks_identifies_assets_findings_status_and_scores() -> None:
    baseline = {
        "task_id": "old",
        "assets": [{"kind": "Pod", "namespace": "ops", "name": "api", "image": "v1"}, {"id": "gone"}],
        "findings": [{"fingerprint": "f1", "status": "WARN"}, {"fingerprint": "f2", "status": "FAIL"}],
        "data_quality": {"completeness": 80, "unknown_rate": 10},
        "checkpoint_scores": [{"checkpoint_id": "CN-1", "score": 60}],
    }
    current = {
        "task_id": "new",
        "assets": [{"kind": "Pod", "namespace": "ops", "name": "api", "image": "v2"}, {"id": "added"}],
        "findings": [{"fingerprint": "f1", "status": "FAIL"}, {"fingerprint": "f3", "status": "WARN"}],
        "data_quality": {"completeness": 90, "unknown_rate": 5},
        "checkpoint_scores": [{"checkpoint_id": "CN-1", "score": 75}],
    }
    result = compare_tasks(baseline, current)
    assert len(result.added_assets) == 1
    assert len(result.removed_assets) == 1
    assert result.changed_assets[0].after["image"] == "v2"
    assert [row["fingerprint"] for row in result.added_findings] == ["f3"]
    assert [row["fingerprint"] for row in result.disappeared_findings] == ["f2"]
    assert result.status_regressions[0].key == "f1"
    assert result.quality_changes[0].direction == "improved"
    assert result.checkpoint_score_changes[0].delta == 15


def test_compare_tasks_accepts_nested_report_and_missing_optional_evidence() -> None:
    baseline = {"id": "old", "report": {"findings": [{"id": "x", "status": "UNKNOWN"}]}}
    current = {"id": "new", "report": {"findings": [{"id": "x", "status": "PASS"}]}}
    result = compare_tasks(baseline, current)
    assert result.status_improvements[0].before == "UNKNOWN"
    assert result.status_improvements[0].after == "PASS"
    assert result.quality_changes == []
    assert result.checkpoint_score_changes == []
    assert result.to_dict()["baseline_task_id"] == "old"

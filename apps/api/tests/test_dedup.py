from cloudnative_security.dedup import deduplicate_evidence, deduplicate_resources


def test_resource_dedup_prefers_live_and_preserves_source_references():
    result = deduplicate_resources([
        {"kind": "Pod", "namespace": "ns", "name": "api", "source": "manifest", "image": "old", "observed_at": "2025-01-01T00:00:00Z"},
        {"kind": "Pod", "namespace": "ns", "name": "api", "source": "live", "image": "new", "observed_at": "2024-01-01T00:00:00Z"},
    ])
    assert result.records[0]["image"] == "new"
    assert result.records[0]["source_references"] == ["manifest", "live"]
    assert result.duplicate_count == 1
    assert any(conflict.field_path == "image" for conflict in result.conflicts)


def test_same_rank_evidence_conflict_remains_explicit():
    result = deduplicate_evidence([
        {"evidence_key": "r|status", "source": "api", "status": "PASS"},
        {"evidence_key": "r|status", "source": "api", "status": "FAIL"},
    ])
    assert result.records[0]["status"] in {"PASS", "FAIL"}
    assert len(result.conflicts) == 1
    assert "same precedence" in result.conflicts[0].resolution_reason


def test_distinct_evidence_and_missing_key_records_are_retained():
    result = deduplicate_evidence([{"evidence_key": "a", "value": 1}, {"evidence_key": "b", "value": 1}])
    assert len(result.records) == 2
    assert result.conflicts == []

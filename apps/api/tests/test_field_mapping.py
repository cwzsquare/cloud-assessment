from cloudnative_security.field_mapping import FieldMappingRule, apply_field_mappings


def test_nested_mapping_and_scalar_transforms_are_json_friendly():
    result = apply_field_mappings(
        [{"meta": {"enabled": "yes", "when": "2025-01-02 03:04:05"}, "port": "443", "addr": "2001:0db8::1", "tags": "a, b"}],
        [
            FieldMappingRule("enabled", "src", "dst", "meta.enabled", "spec.enabled", "boolean"),
            FieldMappingRule("when", "src", "dst", "meta.when", "observed_at", "time"),
            FieldMappingRule("port", "src", "dst", "port", "spec.port", "port"),
            FieldMappingRule("addr", "src", "dst", "addr", "spec.ip", "ip"),
            FieldMappingRule("tags", "src", "dst", "tags", "spec.tags", "list"),
        ],
    )
    row = result.records[0]
    assert row["spec"] == {"enabled": True, "port": 443, "ip": "2001:db8::1", "tags": ["a", "b"]}
    assert row["observed_at"] == "2025-01-02T03:04:05Z"
    assert result.required_failures == 0


def test_required_mapping_accounts_missing_and_invalid_values():
    result = apply_field_mappings(
        [{"name": "", "port": "not-a-port"}],
        [
            FieldMappingRule("name", "", "", "name", "name", "empty", required=True),
            FieldMappingRule("port", "", "", "port", "port", "port", required=True),
        ],
    )
    assert result.required_failures == 2
    assert result.required_failure_paths == {"name": 1, "port": 1}
    assert result.records[0]["port"] is None

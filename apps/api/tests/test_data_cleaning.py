from cloudnative_security.data_cleaning import CleaningConfig, clean_records


def test_clean_records_normalizes_common_fields_and_reports_actions():
    result = clean_records([{
        "name": "  api  ", "status": "success", "observed_at": "2025-01-02 03:04:05",
        "tags": "prod, api", "labels": "team=security, env=prod", "ip": "10.0.0.1", "port": "443",
    }])
    row = result.records[0]
    assert row["name"] == "api"
    assert row["status"] == "PASS"
    assert row["observed_at"] == "2025-01-02T03:04:05Z"
    assert row["tags"] == ["prod", "api"]
    assert row["labels"] == {"env": "prod", "team": "security"}
    assert row["port"] == 443
    assert result.action_count >= 5


def test_invalid_network_values_are_cleared_and_sensitive_fields_unchanged():
    result = clean_records([{"ip": "999.1.1.1", "port": "70000", "password": "  keep me  ", "token": "secret"}])
    row = result.records[0]
    assert row["ip"] is None and row["port"] is None
    assert row["password"] == "  keep me  " and row["token"] == "secret"
    assert result.invalid_count == 2
    assert all(action.before_value != "secret" for action in result.actions)


def test_explicit_field_configuration_is_supported():
    result = clean_records([{"phase_code": " ok ", "event_time": "2025/01/02 03:04:05"}], CleaningConfig(enum_fields=("phase_code",), time_fields=("event_time",)))
    assert result.records[0] == {"phase_code": "PASS", "event_time": "2025-01-02T03:04:05Z"}

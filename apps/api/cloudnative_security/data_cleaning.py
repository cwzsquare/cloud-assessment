"""Safe, deterministic normalization of generic evidence records."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
import hashlib
import json
import re
from typing import Any, Iterable, Mapping

from .data_observability import AnomalyRecord, AnomalyRule, detect_anomalies
from .field_mapping import get_path, set_path


_SENSITIVE_PARTS = (
    "password", "passwd", "secret", "token", "credential", "private_key",
    "privatekey", "api_key", "apikey", "access_key", "accesskey", "client_key",
    "certificate", "tls_cert", "private", "encryption_key", "stringdata",
)
_MISSING = object()


def _sensitive(path: str) -> bool:
    lowered = path.lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_PARTS)


def _empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _summary(value: Any, sensitive: bool = False) -> Any:
    if sensitive:
        if value is None:
            return None
        if isinstance(value, str):
            return {"redacted": True, "type": "string", "length": len(value)}
        return {"redacted": True, "type": type(value).__name__}
    if isinstance(value, Mapping):
        return {str(k): _summary(v, _sensitive(str(k))) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_summary(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _time(value: Any) -> str | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _list(value: Any) -> list[Any] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, str):
        if not value.strip():
            return None
        return [part.strip() for part in re.split(r"[,;\n]", value) if part.strip()]
    return [value]


def _labels(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        pairs = value.items()
    elif isinstance(value, str):
        pairs = []
        for item in re.split(r"[,\n]", value):
            if "=" in item:
                key, val = item.split("=", 1)
                pairs.append((key, val))
    elif isinstance(value, (list, tuple, set)):
        pairs = []
        for item in value:
            if isinstance(item, str) and "=" in item:
                pairs.append(tuple(item.split("=", 1)))
    else:
        return None
    result: dict[str, str] = {}
    for key, val in pairs:
        key_text = str(key).strip()
        val_text = str(val).strip()
        if key_text and val_text:
            result[key_text] = val_text
    return {key: result[key] for key in sorted(result)}


def _configured(path: str, values: tuple[str, ...]) -> bool:
    lowered = path.lower()
    leaf = lowered.rsplit(".", 1)[-1]
    return lowered in values or leaf in values


def _field_kind(path: str, value: Any, config: "CleaningConfig") -> str | None:
    leaf = path.rsplit(".", 1)[-1].lower()
    if _configured(path, config.enum_fields) or leaf in {"status", "severity", "state", "phase", "result"}:
        return "enum"
    if _configured(path, config.time_fields) or leaf.endswith(("_at", "_time", "timestamp", "date")):
        return "time"
    if _configured(path, config.label_fields) or leaf in {"labels", "label", "tags"}:
        return "labels" if _configured(path, config.label_fields) or leaf in {"labels", "label"} else "list"
    if _configured(path, config.list_fields) or leaf.endswith(("_list", "_ips", "_ports")):
        return "list"
    if _configured(path, config.name_fields) or leaf in {"name", "display_name", "resource_name"}:
        return "name"
    if _configured(path, config.ip_fields) or leaf == "ip" or leaf.endswith("_ip") or leaf.endswith("_address"):
        return "ip"
    if _configured(path, config.port_fields) or leaf in {"port", "port_number", "target_port", "container_port"}:
        return "port"
    if isinstance(value, str) and _configured(path, config.empty_fields):
        return "empty"
    return "empty" if isinstance(value, str) and not value.strip() else None


def _enum(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    aliases = {
        "ok": "PASS", "pass": "PASS", "passed": "PASS", "success": "PASS",
        "error": "FAIL", "failed": "FAIL", "failure": "FAIL",
        "warning": "WARN", "warn": "WARN", "unknown": "UNKNOWN",
        "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
    }
    text = value.strip()
    return aliases.get(text.lower(), text.upper())


@dataclass(frozen=True)
class CleaningConfig:
    """Explicit field sets plus missing-value and anomaly policy."""

    enum_fields: tuple[str, ...] = ()
    time_fields: tuple[str, ...] = ()
    list_fields: tuple[str, ...] = ()
    label_fields: tuple[str, ...] = ()
    name_fields: tuple[str, ...] = ()
    ip_fields: tuple[str, ...] = ()
    port_fields: tuple[str, ...] = ()
    empty_fields: tuple[str, ...] = ()
    field_paths: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    missing_policy: str = "record"
    default_values: Mapping[str, Any] = field(default_factory=dict)
    anomaly_rules: tuple[AnomalyRule, ...] = ()

    def __post_init__(self) -> None:
        names = (
            "enum_fields", "time_fields", "list_fields", "label_fields", "name_fields",
            "ip_fields", "port_fields", "empty_fields", "field_paths", "required_fields",
        )
        for name in names:
            value = getattr(self, name)
            if isinstance(value, str):
                values = (value,)
            else:
                values = tuple(str(item) for item in (value or ()))
            if any(not item.strip() for item in values):
                raise ValueError(f"{name} contains an empty path")
            object.__setattr__(self, name, tuple(item.lower() for item in values))
        if self.missing_policy not in {"record", "null", "default", "drop"}:
            raise ValueError(f"unsupported missing policy: {self.missing_policy}")
        object.__setattr__(self, "default_values", dict(self.default_values or {}))
        raw_rules = self.anomaly_rules if not isinstance(self.anomaly_rules, Mapping) else (self.anomaly_rules,)
        parsed_rules = tuple(rule if isinstance(rule, AnomalyRule) else AnomalyRule(**dict(rule)) for rule in (raw_rules or ()))
        object.__setattr__(self, "anomaly_rules", parsed_rules)


@dataclass(frozen=True)
class CleaningAction:
    field_path: str
    action_type: str
    before_value: Any = None
    after_value: Any = None
    reason: str = ""
    source_id: str = ""
    object_key: str = ""

    @property
    def action(self) -> str:
        return self.action_type

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CleaningResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    actions: list[CleaningAction] = field(default_factory=list)
    invalid_count: int = 0
    sensitive_skipped: int = 0
    dropped_count: int = 0
    anomalies: list[AnomalyRecord] = field(default_factory=list)
    input_count: int = 0
    invalid_by_field: dict[str, int] = field(default_factory=dict)
    invalid_by_reason: dict[str, int] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def cleaned_records(self) -> list[dict[str, Any]]:
        return self.records

    @property
    def action_count(self) -> int:
        return len(self.actions)

    def _summary(self) -> dict[str, Any]:
        action_counts: dict[str, int] = {}
        for action in self.actions:
            action_counts[action.action_type] = action_counts.get(action.action_type, 0) + 1
        anomaly_counts: dict[str, int] = {}
        for anomaly in self.anomalies:
            anomaly_counts[anomaly.anomaly_type] = anomaly_counts.get(anomaly.anomaly_type, 0) + 1
        result = {
            "input_count": self.input_count,
            "output_count": len(self.records),
            "dropped_count": self.dropped_count,
            "action_count": len(self.actions),
            "action_counts": dict(sorted(action_counts.items())),
            "anomaly_count": len(self.anomalies),
            "anomaly_counts": dict(sorted(anomaly_counts.items())),
            "invalid_count": self.invalid_count,
            "sensitive_skipped": self.sensitive_skipped,
            "invalid_by_field": dict(sorted(self.invalid_by_field.items())),
            "invalid_by_reason": dict(sorted(self.invalid_by_reason.items())),
        }
        self.summary = result
        return result

    def to_dict(self) -> dict[str, Any]:
        summary = self._summary()
        return {
            "records": self.records,
            "actions": [action.to_dict() for action in self.actions],
            "invalid_count": self.invalid_count,
            "sensitive_skipped": self.sensitive_skipped,
            "dropped_count": self.dropped_count,
            "anomalies": [anomaly.to_dict() for anomaly in self.anomalies],
            "summary": summary,
        }

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.records[index]


def _record_anomaly(result: CleaningResult, anomaly_type: str, status: str, field_path: str, rule_id: str | None, reason: str, observed: Any, expected: Any, source_id: str, object_key: str, index: int = 0) -> None:
    ref = f"{source_id}|{object_key}|{index}"
    identity = hashlib.sha256(f"{anomaly_type}|{field_path}|{rule_id}|{ref}|{reason}".encode()).hexdigest()[:20]
    result.anomalies.append(AnomalyRecord(
        f"anomaly-{identity}", anomaly_type, status, source_id, object_key, field_path,
        rule_id, reason, observed, expected, (ref,),
    ))
    if status != "UNKNOWN":
        result.invalid_by_field[field_path] = result.invalid_by_field.get(field_path, 0) + (1 if anomaly_type.startswith("invalid") else 0)
        result.invalid_by_reason[reason] = result.invalid_by_reason.get(reason, 0) + 1


def _clean_mapping(value: dict[str, Any], *, config: CleaningConfig, prefix: str, actions: list[CleaningAction], result: CleaningResult, source_id: str, object_key: str, record_index: int = 0) -> None:
    for key in sorted(list(value), key=str):
        path = f"{prefix}.{key}" if prefix else str(key)
        original = value[key]
        if isinstance(original, dict):
            _clean_mapping(original, config=config, prefix=path, actions=actions, result=result, source_id=source_id, object_key=object_key, record_index=record_index)
            continue
        if isinstance(original, list):
            for item_index, item in enumerate(original):
                if isinstance(item, dict):
                    _clean_mapping(item, config=config, prefix=f"{path}.{item_index}", actions=actions, result=result, source_id=source_id, object_key=object_key, record_index=record_index)
            continue
        if _sensitive(path):
            result.sensitive_skipped += 1
            continue
        kind = _field_kind(path, original, config)
        if kind is None:
            continue
        cleaned = original
        reason = ""
        if kind == "empty":
            cleaned = None if _empty(original) else original
            reason = "empty value normalized to null"
        elif kind == "enum":
            cleaned = _enum(original)
            reason = "enum spelling normalized"
        elif kind == "time":
            parsed = _time(original)
            cleaned = parsed if parsed is not None else original
            reason = "timestamp normalized to UTC ISO-8601" if parsed is not None else "invalid timestamp preserved"
            if parsed is None and not _empty(original):
                _record_anomaly(result, "invalid_timestamp_preserved", "FAIL", path, None, reason, original, "UTC ISO-8601 timestamp", source_id, object_key, record_index)
        elif kind == "list":
            parsed = _list(original)
            cleaned = parsed if parsed is not None else original
            reason = "list delimiter normalized"
        elif kind == "labels":
            parsed = _labels(original)
            cleaned = parsed if parsed is not None else original
            reason = "labels normalized to sorted key/value map"
        elif kind == "name":
            cleaned = original.strip() if isinstance(original, str) else original
            reason = "name whitespace normalized"
        elif kind == "ip":
            if _empty(original):
                cleaned = None
                reason = "empty IP normalized to null"
            else:
                try:
                    cleaned = str(ip_address(str(original).strip()))
                    reason = "IP address canonicalized"
                except ValueError:
                    cleaned = None
                    result.invalid_count += 1
                    reason = "invalid IP cleared"
                    _record_anomaly(result, "invalid_value", "FAIL", path, None, reason, original, "valid IP address", source_id, object_key, record_index)
        elif kind == "port":
            if _empty(original):
                cleaned = None
                reason = "empty port normalized to null"
            else:
                try:
                    candidate = int(str(original).strip())
                    if not 1 <= candidate <= 65535:
                        raise ValueError
                    cleaned = candidate
                    reason = "port normalized to integer"
                except (TypeError, ValueError):
                    cleaned = None
                    result.invalid_count += 1
                    reason = "invalid port cleared"
                    _record_anomaly(result, "invalid_value", "FAIL", path, None, reason, original, "integer port 1..65535", source_id, object_key, record_index)
        if cleaned != original:
            value[key] = cleaned
            actions.append(CleaningAction(path, kind, _summary(original, _sensitive(path)), _summary(cleaned, _sensitive(path)), reason, source_id, object_key))


def _missing_paths(record: Mapping[str, Any], paths: Iterable[str]) -> list[str]:
    return [path for path in paths if get_path(record, path, _MISSING) is _MISSING or _empty(get_path(record, path))]


def clean_records(records: Iterable[Mapping[str, Any]] | Mapping[str, Any], config: CleaningConfig | Mapping[str, Any] | None = None, **options: Any) -> CleaningResult:
    """Return deep-cleaned copies, auditable actions, and anomaly evidence."""
    if config is None:
        config = CleaningConfig(**options)
    elif isinstance(config, Mapping):
        merged = dict(config)
        merged.update(options)
        config = CleaningConfig(**merged)
    elif options:
        raise TypeError("options cannot be used with a CleaningConfig instance")
    if not isinstance(config, CleaningConfig):
        raise TypeError("config must be CleaningConfig or mapping")
    rows = [records] if isinstance(records, Mapping) else [row for row in records if isinstance(row, Mapping)]
    result = CleaningResult(input_count=len(rows))
    for index, original in enumerate(rows):
        cleaned = deepcopy(dict(original))
        source_id = str(cleaned.get("source_id", cleaned.get("source", "")) or "")
        object_key = str(cleaned.get("object_key", cleaned.get("source_reference", cleaned.get("id", cleaned.get("name", "")))) or "")
        _clean_mapping(cleaned, config=config, prefix="", actions=result.actions, result=result, source_id=source_id, object_key=object_key, record_index=index)
        missing = _missing_paths(cleaned, config.required_fields)
        drop = False
        for path in missing:
            observed = get_path(cleaned, path, _MISSING)
            observed = None if observed is _MISSING else observed
            if config.missing_policy == "record":
                _record_anomaly(result, "missing_value", "FAIL", path, None, "required field is missing", observed, "required value", source_id, object_key, index)
            elif config.missing_policy == "null":
                set_path(cleaned, path, None)
                result.actions.append(CleaningAction(path, "missing_value_imputed", _summary(observed, _sensitive(path)), None, "missing value replaced with null", source_id, object_key))
                _record_anomaly(result, "missing_value_imputed", "FAIL", path, None, "missing value replaced with null", observed, None, source_id, object_key, index)
            elif config.missing_policy == "default":
                if path in config.default_values:
                    default = deepcopy(config.default_values[path])
                    set_path(cleaned, path, default)
                    result.actions.append(CleaningAction(path, "missing_value_imputed", _summary(observed, _sensitive(path)), _summary(default, _sensitive(path)), "missing value replaced with configured default", source_id, object_key))
                    _record_anomaly(result, "missing_value_imputed", "FAIL", path, None, "missing value replaced with configured default", observed, default, source_id, object_key, index)
                else:
                    _record_anomaly(result, "missing_value", "UNKNOWN", path, None, "missing value has no configured default", observed, None, source_id, object_key, index)
            else:
                drop = True
                _record_anomaly(result, "missing_value", "FAIL", path, None, "record dropped because required field is missing", observed, "required value", source_id, object_key, index)
        if drop:
            result.dropped_count += 1
            continue
        result.records.append(cleaned)
    result.anomalies.extend(detect_anomalies(result.records, config.anomaly_rules))
    result._summary()
    return result


DataCleaningAction = CleaningAction
DataCleaningResult = CleaningResult
clean = clean_records

__all__ = ["CleaningConfig", "CleaningAction", "CleaningResult", "DataCleaningAction", "DataCleaningResult", "clean_records", "clean"]

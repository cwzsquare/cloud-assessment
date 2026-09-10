"""Safe, deterministic normalization of generic evidence records.

Cleaning is intentionally conservative: values that may contain credentials or
cryptographic material are never rewritten.  Action metadata uses summaries for
those values, so action logs remain useful without persisting secrets.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any, Iterable, Mapping, Sequence


_SENSITIVE_PARTS = ("password", "passwd", "secret", "token", "credential", "private_key", "privatekey", "api_key", "apikey", "access_key", "accesskey", "client_key", "certificate", "tls_cert", "private", "encryption_key")


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


def _field_kind(path: str, value: Any, config: "CleaningConfig") -> str | None:
    leaf = path.rsplit(".", 1)[-1].lower()
    if leaf in config.enum_fields or leaf in {"status", "severity", "state", "phase", "result"}:
        return "enum"
    if leaf in config.time_fields or leaf.endswith(("_at", "_time", "timestamp", "date")):
        return "time"
    if leaf in config.label_fields or leaf in {"labels", "label", "tags"}:
        return "labels" if leaf in config.label_fields or leaf in {"labels", "label"} else "list"
    if leaf in config.list_fields or leaf.endswith(("_list", "_ips", "_ports")):
        return "list"
    if leaf in config.name_fields or leaf in {"name", "display_name", "resource_name"}:
        return "name"
    if leaf in config.ip_fields or leaf == "ip" or leaf.endswith("_ip") or leaf.endswith("_address"):
        return "ip"
    if leaf in config.port_fields or leaf in {"port", "port_number", "target_port", "container_port"}:
        return "port"
    if isinstance(value, str) and leaf in config.empty_fields:
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
    """Optional explicit field sets; common field names are inferred too."""

    enum_fields: tuple[str, ...] = ()
    time_fields: tuple[str, ...] = ()
    list_fields: tuple[str, ...] = ()
    label_fields: tuple[str, ...] = ()
    name_fields: tuple[str, ...] = ()
    ip_fields: tuple[str, ...] = ()
    port_fields: tuple[str, ...] = ()
    empty_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("enum_fields", "time_fields", "list_fields", "label_fields", "name_fields", "ip_fields", "port_fields", "empty_fields"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, (value.lower(),))
            else:
                object.__setattr__(self, name, tuple(str(item).lower() for item in (value or ())))


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

    @property
    def cleaned_records(self) -> list[dict[str, Any]]:
        return self.records

    @property
    def action_count(self) -> int:
        return len(self.actions)

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records, "actions": [action.to_dict() for action in self.actions], "invalid_count": self.invalid_count, "sensitive_skipped": self.sensitive_skipped}

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.records[index]


def _clean_mapping(value: dict[str, Any], *, config: CleaningConfig, prefix: str, actions: list[CleaningAction], result: CleaningResult, source_id: str, object_key: str) -> None:
    for key in sorted(list(value), key=str):
        path = f"{prefix}.{key}" if prefix else str(key)
        original = value[key]
        if isinstance(original, dict):
            _clean_mapping(original, config=config, prefix=path, actions=actions, result=result, source_id=source_id, object_key=object_key)
            continue
        if _sensitive(path):
            # Do not even trim/parse sensitive values.  This is a deliberate
            # no-op rather than an action, preventing secret material in logs.
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
        if cleaned != original:
            value[key] = cleaned
            actions.append(CleaningAction(path, kind, _summary(original), _summary(cleaned), reason, source_id, object_key))


def clean_records(
    records: Iterable[Mapping[str, Any]] | Mapping[str, Any],
    config: CleaningConfig | Mapping[str, Any] | None = None,
    **options: Any,
) -> CleaningResult:
    """Return cleaned copies and an auditable action list.

    ``config`` may be a :class:`CleaningConfig` or JSON-shaped field sets.
    Keyword field-set options are accepted for adapter convenience.
    """
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
    result = CleaningResult()
    for original in rows:
        cleaned = deepcopy(dict(original))
        source_id = str(cleaned.get("source_id", cleaned.get("source", "")))
        object_key = str(cleaned.get("object_key", cleaned.get("id", cleaned.get("name", ""))))
        _clean_mapping(cleaned, config=config, prefix="", actions=result.actions, result=result, source_id=source_id, object_key=object_key)
        result.records.append(cleaned)
    return result


# Compatibility aliases used by pipeline integrations.
DataCleaningAction = CleaningAction
DataCleaningResult = CleaningResult
clean = clean_records

__all__ = ["CleaningConfig", "CleaningAction", "CleaningResult", "DataCleaningAction", "DataCleaningResult", "clean_records", "clean"]

"""Pure, JSON-friendly field mapping helpers for source normalization.

Mappings operate on ordinary dictionaries.  A rule can copy/rename a nested
source value, apply a small set of safe scalar conversions, and account for
missing required values without raising for a bad source record.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any, Callable, Iterable, Mapping, Sequence


_MISSING = object()


def _path_parts(path: str) -> list[str]:
    """Split dotted paths, accepting simple ``items[0]`` segments."""
    parts: list[str] = []
    for bit in str(path).split("."):
        parts.extend(p for p in re.findall(r"[^\[\]]+", bit) if p != "")
    return parts


def get_path(record: Mapping[str, Any], path: str, default: Any = None) -> Any:
    value: Any = record
    for part in _path_parts(path):
        if isinstance(value, Mapping) and part in value:
            value = value[part]
        elif isinstance(value, (list, tuple)) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return default
    return value


def set_path(record: dict[str, Any], path: str, value: Any) -> None:
    parts = _path_parts(path)
    if not parts:
        return
    current: Any = record
    for part in parts[:-1]:
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            while len(current) <= index:
                current.append({})
            if not isinstance(current[index], (dict, list)):
                current[index] = {}
            current = current[index]
            continue
        if not isinstance(current, dict):
            return
        existing = current.get(part)
        if not isinstance(existing, (dict, list)):
            existing = {}
            current[part] = existing
        current = existing
    final = parts[-1]
    if isinstance(current, list) and final.isdigit():
        index = int(final)
        while len(current) <= index:
            current.append(None)
        current[index] = value
    elif isinstance(current, dict):
        current[final] = value


def _empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _iso_time(value: Any) -> str | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            # Common source format used by logs and API exports.
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "y", "on", "enabled", "enable", "1"}:
            return True
        if lowered in {"false", "no", "n", "off", "disabled", "disable", "0"}:
            return False
    return None


def _port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return result if 1 <= result <= 65535 else None


def _list_value(value: Any) -> list[Any] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return [item.strip() for item in re.split(r"[,;\n]", text) if item.strip()]
    return [value]


def _transform_value(rule: "FieldMappingRule", value: Any) -> Any:
    transform = rule.transform
    if callable(transform):
        return transform(value)
    name = str(transform or "identity").lower().replace("-", "_")
    if name in {"identity", "copy", "rename", ""}:
        return value
    if name in {"empty", "empty_to_null", "null_empty"}:
        return None if _empty(value) else value
    if name in {"default", "default_value"}:
        return rule.default_value if _empty(value) else value
    if name in {"enum", "enumeration"}:
        if _empty(value):
            return rule.default_value
        mapping = rule.enum_mapping or {}
        if value in mapping:
            return mapping[value]
        lowered = str(value).strip().lower()
        for key, mapped in mapping.items():
            if str(key).strip().lower() == lowered:
                return mapped
        return value
    if name in {"boolean", "bool"}:
        parsed = _boolean(value)
        return rule.default_value if parsed is None and rule.default_value is not None else parsed
    if name in {"time", "timestamp", "datetime", "date"}:
        parsed = _iso_time(value)
        return rule.default_value if parsed is None and rule.default_value is not None else parsed
    if name in {"ip", "ip_address", "ipaddress"}:
        if _empty(value):
            return rule.default_value
        try:
            return str(ip_address(str(value).strip()))
        except ValueError:
            return rule.default_value
    if name in {"port", "port_number"}:
        parsed = _port(value)
        return rule.default_value if parsed is None and rule.default_value is not None else parsed
    if name in {"list", "array", "sequence"}:
        parsed = _list_value(value)
        return rule.default_value if parsed is None and rule.default_value is not None else parsed
    raise ValueError(f"unsupported field mapping transform: {transform}")


@dataclass(frozen=True)
class FieldMappingRule:
    """A declarative source-to-target field mapping.

    The first fields mirror the persisted mapping-rule contract.  Additional
    JSON-shaped options keep configuration useful without coupling this module
    to storage or a particular adapter.
    """

    mapping_id: str = ""
    source_schema: str = ""
    target_schema: str = ""
    source_path: str = ""
    target_path: str = ""
    transform: str | Callable[[Any], Any] = "identity"
    required: bool = False
    default_value: Any = None
    enum_mapping: Mapping[Any, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.mapping_id

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if callable(result["transform"]):
            result["transform"] = getattr(result["transform"], "__name__", "callable")
        return result


@dataclass
class MappingApplicationResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    required_failures: int = 0
    required_failure_paths: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    mapped_count: int = 0

    @property
    def failures(self) -> int:
        return self.required_failures

    @property
    def mapped_records(self) -> list[dict[str, Any]]:
        return self.records

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    # Treat the result as a read-only-ish list for callers that only need rows.
    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.records[index]


def apply_field_mappings(
    records: Iterable[Mapping[str, Any]] | Mapping[str, Any],
    rules: Iterable[FieldMappingRule | Mapping[str, Any]],
    *,
    strict: bool = False,
) -> MappingApplicationResult:
    """Apply mappings to records and account for missing required inputs.

    Input records are never mutated.  A required value is considered missing
    when it is absent or blank; invalid conversions also count as a required
    failure when they produce ``None``.  In non-strict mode a bad rule is
    recorded and processing continues; strict mode raises ``ValueError``.
    """
    if isinstance(records, Mapping):
        source_records = [records]
    else:
        source_records = [row for row in records if isinstance(row, Mapping)]
    prepared: list[FieldMappingRule] = []
    for raw in rules:
        if isinstance(raw, FieldMappingRule):
            prepared.append(raw)
        else:
            config = dict(raw)
            # Configuration commonly calls this ``default``.
            if "default" in config and "default_value" not in config:
                config["default_value"] = config.pop("default")
            if "enum_values" in config and "enum_mapping" not in config:
                config["enum_mapping"] = config.pop("enum_values")
            prepared.append(FieldMappingRule(**config))
    result = MappingApplicationResult(mapped_count=len(source_records))
    for original in source_records:
        output: dict[str, Any] = deepcopy(dict(original))
        for rule in prepared:
            value = get_path(original, rule.source_path, _MISSING)
            missing = value is _MISSING or _empty(value)
            if missing and rule.required:
                result.required_failures += 1
                result.required_failure_paths[rule.source_path] = result.required_failure_paths.get(rule.source_path, 0) + 1
            if value is _MISSING:
                value = None
            try:
                converted = _transform_value(rule, value)
            except (TypeError, ValueError, OverflowError) as exc:
                message = f"{rule.mapping_id or rule.source_path}: {exc}"
                result.errors.append(message)
                if strict:
                    raise ValueError(message) from exc
                converted = rule.default_value
            if rule.required and not missing and _empty(converted):
                result.required_failures += 1
                result.required_failure_paths[rule.source_path] = result.required_failure_paths.get(rule.source_path, 0) + 1
            set_path(output, rule.target_path or rule.source_path, converted)
        result.records.append(output)
    return result


# Friendly aliases for integrations that use shorter names.
MappingResult = MappingApplicationResult
apply_mappings = apply_field_mappings

__all__ = [
    "FieldMappingRule", "MappingApplicationResult", "MappingResult",
    "apply_field_mappings", "apply_mappings", "get_path", "set_path",
]

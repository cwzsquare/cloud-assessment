"""Generic, evidence-aware data quality evaluation.

The module deliberately works on ordinary dictionaries and lists.  It does not
know about a storage implementation and therefore can be used by adapters,
reporting code, or a one-off validation script.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Callable, Iterable, Mapping, Sequence


UNKNOWN = "UNKNOWN"
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


def _records(value: Any) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        # A single record is the least surprising interpretation.  Common
        # envelope keys are unwrapped when their value is a record collection.
        for key in ("records", "items", "data", "results"):
            nested = value.get(key)
            if isinstance(nested, (list, tuple)):
                return [r for r in nested if isinstance(r, Mapping)]
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [r for r in value if isinstance(r, Mapping)]
    return []


def _missing(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _get(record: Mapping[str, Any], path: str) -> Any:
    value: Any = record
    for part in str(path).split("."):
        if isinstance(value, Mapping) and part in value:
            value = value[part]
        else:
            return None
    return value


def _type_name(value: Any) -> str:
    return type(value).__name__


def _normalise_expected_type(value: Any) -> tuple[type[Any], ...] | None:
    names = {"str": str, "string": str, "int": int, "integer": int,
             "float": float, "number": (int, float), "bool": bool,
             "boolean": bool, "list": list, "dict": dict, "mapping": Mapping}
    if isinstance(value, type):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        result: list[type[Any]] = []
        for item in value:
            part = _normalise_expected_type(item)
            if part:
                result.extend(part)
        return tuple(result) or None
    if isinstance(value, str):
        found = names.get(value.lower())
        if found is None:
            return None
        return found if isinstance(found, tuple) else (found,)
    return None


def _safe_json(value: Any) -> Any:
    """Return a compact, export-friendly representation for examples."""
    if isinstance(value, Mapping):
        return {str(k): _safe_json(v) for k, v in value.items() if not _secret_key(str(k))}
    if isinstance(value, (list, tuple, set)):
        return [_safe_json(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("token", "password", "secret", "private_key", "privatekey", "encryption_key"))


def _example(record: Mapping[str, Any], detail: Any = None) -> dict[str, Any]:
    result = {"record": _safe_json(record)}
    if detail is not None:
        result["detail"] = _safe_json(detail)
    return result


@dataclass(frozen=True)
class DataQualityRule:
    """A declarative quality rule.

    ``dimension`` is one of completeness, uniqueness, field_validity,
    type_consistency, cross_source_consistency, reference_integrity,
    temporal_continuity, or lineage_integrity.
    """

    rule_id: str = ""
    dimension: str = ""
    description: str = ""
    required_fields: tuple[str, ...] = field(default_factory=tuple)
    key_fields: tuple[str, ...] = field(default_factory=tuple)
    fields: tuple[str, ...] = field(default_factory=tuple)
    expected_types: Mapping[str, Any] = field(default_factory=dict)
    valid_values: Mapping[str, Sequence[Any]] = field(default_factory=dict)
    patterns: Mapping[str, str] = field(default_factory=dict)
    ranges: Mapping[str, Sequence[float]] = field(default_factory=dict)
    source_field: str | None = None
    compare_fields: tuple[str, ...] = field(default_factory=tuple)
    reference_fields: Mapping[str, str] = field(default_factory=dict)
    time_field: str | None = None
    interval_seconds: float | None = None
    group_fields: tuple[str, ...] = field(default_factory=tuple)
    lineage_fields: tuple[str, ...] = field(default_factory=tuple)
    threshold: float = 100.0
    example_limit: int = 5
    # ``name`` is accepted as a configuration-friendly alias for rule_id.
    name: str | None = None

    def __post_init__(self) -> None:
        if not self.rule_id:
            object.__setattr__(self, "rule_id", self.name or self.dimension)
        if not self.dimension and self.name:
            object.__setattr__(self, "dimension", self.name)
        for name in ("required_fields", "key_fields", "fields", "compare_fields", "group_fields", "lineage_fields"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, (value,))
            elif not isinstance(value, tuple):
                object.__setattr__(self, name, tuple(value or ()))

    @property
    def id(self) -> str:
        return self.rule_id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DataQualityResult:
    rule_id: str
    dimension: str
    status: str
    score: float | None
    total_count: int
    passed_count: int
    failed_count: int
    unknown_count: int
    examples: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""
    evidence_present: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def unknown(self) -> bool:
        return self.status == UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _result(rule: DataQualityRule, total: int, passed: int, failed: int,
            unknown: int = 0, examples: list[dict[str, Any]] | None = None,
            message: str = "", evidence: bool = True,
            details: Mapping[str, Any] | None = None) -> DataQualityResult:
    if not evidence:
        status, score = UNKNOWN, None
    else:
        score = round((passed / total) * 100, 2) if total else None
        status = UNKNOWN if score is None else (PASS if score >= rule.threshold else FAIL)
    return DataQualityResult(rule.rule_id, rule.dimension, status, score, total, passed,
                             failed, unknown, examples or [], message, evidence,
                             dict(details or {}))


def _field_evidence(rows: list[Mapping[str, Any]], fields: Iterable[str]) -> bool:
    names = tuple(fields)
    return bool(rows) and bool(names) and any(_get(row, f) is not None for row in rows for f in names)


def _check_completeness(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.required_fields or rule.fields
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="required field evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for row in rows:
        missing = [name for name in fields if _missing(_get(row, name))]
        if missing:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"missing_fields": missing}))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_uniqueness(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.key_fields or rule.fields
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="key field evidence is absent", evidence=False)
    seen: dict[tuple[Any, ...], int] = {}
    duplicates: set[int] = set()
    for index, row in enumerate(rows):
        key = tuple(_get(row, field_name) for field_name in fields)
        if any(_missing(value) for value in key):
            duplicates.add(index)
            continue
        if key in seen:
            duplicates.update((index, seen[key]))
        else:
            seen[key] = index
    examples = [_example(rows[i], {"key_fields": list(fields)}) for i in sorted(duplicates)[:rule.example_limit]]
    return _result(rule, len(rows), len(rows) - len(duplicates), len(duplicates), examples=examples,
                   details={"duplicate_rate": round(len(duplicates) / len(rows) * 100, 2)})


def _check_field_validity(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.fields or tuple(rule.valid_values) or tuple(rule.patterns) or tuple(rule.ranges)
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="field validity evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for row in rows:
        errors: list[str] = []
        for name in fields:
            value = _get(row, name)
            if _missing(value):
                errors.append(f"{name}:missing")
                continue
            if name in rule.valid_values and value not in rule.valid_values[name]:
                errors.append(f"{name}:not_allowed")
            if name in rule.patterns:
                try:
                    if re.fullmatch(rule.patterns[name], str(value)) is None:
                        errors.append(f"{name}:pattern")
                except re.error:
                    errors.append(f"{name}:invalid_pattern")
            if name in rule.ranges:
                bounds = rule.ranges[name]
                if len(bounds) >= 1 and value < bounds[0]:
                    errors.append(f"{name}:below_min")
                if len(bounds) >= 2 and value > bounds[1]:
                    errors.append(f"{name}:above_max")
        if errors:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"errors": errors}))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_type_consistency(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    expected = dict(rule.expected_types)
    if not expected and rule.fields:
        return _result(rule, len(rows), 0, 0, message="expected types are absent", evidence=False)
    fields = tuple(expected) or rule.fields
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="type evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for row in rows:
        errors: list[str] = []
        for name in fields:
            value = _get(row, name)
            types = _normalise_expected_type(expected.get(name))
            if _missing(value) or not types or not isinstance(value, types):
                errors.append(f"{name}:expected={expected.get(name)!r},actual={_type_name(value)}")
        if errors:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"errors": errors}))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_cross_source(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    source_field = rule.source_field
    fields = rule.compare_fields or rule.fields
    if not rows or not source_field or not fields:
        return _result(rule, len(rows), 0, 0, message="source or comparison evidence is absent", evidence=False)
    sources = {_get(row, source_field) for row in rows if not _missing(_get(row, source_field))}
    if len(sources) < 2:
        return _result(rule, len(rows), 0, 0, message="at least two sources are required", evidence=False)
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    group_fields = rule.key_fields or rule.group_fields
    if not group_fields:
        group_fields = ("id",) if any(_get(r, "id") is not None for r in rows) else tuple()
    if not group_fields:
        return _result(rule, len(rows), 0, 0, message="record identity evidence is absent", evidence=False)
    for row in rows:
        key = tuple(_get(row, name) for name in group_fields)
        if not any(_missing(v) for v in key):
            groups.setdefault(key, []).append(row)
    compared = failed = 0
    examples: list[dict[str, Any]] = []
    for group in groups.values():
        if len({_get(row, source_field) for row in group}) < 2:
            continue
        compared += 1
        values = {tuple(_get(row, name) for name in fields) for row in group}
        if len(values) > 1:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(group[0], {"sources": sorted(str(_get(r, source_field)) for r in group), "values": list(values)}))
    return _result(rule, compared, compared - failed, failed, examples=examples)


def _check_references(rule: DataQualityRule, rows: list[Mapping[str, Any]], references: Mapping[str, Any] | None) -> DataQualityResult:
    mapping = dict(references or {})
    fields = dict(rule.reference_fields)
    if not rows or not fields or not mapping:
        return _result(rule, len(rows), 0, 0, message="reference evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for row in rows:
        errors = []
        for field_name, target_name in fields.items():
            value = _get(row, field_name)
            target = mapping.get(target_name)
            if target is None:
                errors.append(f"{field_name}:target_missing")
                continue
            target_rows = _records(target)
            keys = {r.get("id", r.get("key", r.get("name"))) for r in target_rows}
            if _missing(value) or value not in keys:
                errors.append(f"{field_name}:unresolved")
        if errors:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"errors": errors}))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _check_temporal(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    if not rows or not rule.time_field or rule.interval_seconds is None:
        return _result(rule, len(rows), 0, 0, message="temporal evidence is absent", evidence=False)
    groups: dict[tuple[Any, ...], list[datetime]] = {}
    group_fields = rule.group_fields
    for row in rows:
        parsed = _parse_time(_get(row, rule.time_field))
        if parsed is not None:
            groups.setdefault(tuple(_get(row, f) for f in group_fields), []).append(parsed)
    if not groups:
        return _result(rule, len(rows), 0, 0, message="timestamps are absent or invalid", evidence=False)
    gaps = []
    for key, timestamps in groups.items():
        ordered = sorted(timestamps)
        for before, after in zip(ordered, ordered[1:]):
            if (after - before).total_seconds() > rule.interval_seconds:
                gaps.append({"group": key, "from": before.isoformat(), "to": after.isoformat()})
    total = sum(max(0, len(values) - 1) for values in groups.values())
    return _result(rule, total, total - len(gaps), len(gaps), examples=[{"detail": _safe_json(g)} for g in gaps[:rule.example_limit]])


def _check_lineage(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.lineage_fields or rule.fields
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="lineage evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for row in rows:
        missing = [name for name in fields if _missing(_get(row, name))]
        if missing:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"missing_fields": missing}))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


_CHECKERS: dict[str, Callable[..., DataQualityResult]] = {
    "completeness": _check_completeness,
    "uniqueness": _check_uniqueness,
    "duplicate": _check_uniqueness,
    "field_validity": _check_field_validity,
    "validity": _check_field_validity,
    "type_consistency": _check_type_consistency,
    "types": _check_type_consistency,
    "cross_source_consistency": _check_cross_source,
    "consistency": _check_cross_source,
    "reference_integrity": _check_references,
    "references": _check_references,
    "temporal_continuity": _check_temporal,
    "temporal": _check_temporal,
    "lineage_integrity": _check_lineage,
    "lineage": _check_lineage,
}


def evaluate_rule(rule: DataQualityRule, records: Any, *, references: Mapping[str, Any] | None = None) -> DataQualityResult:
    rows = _records(records)
    checker = _CHECKERS.get(rule.dimension.lower())
    if checker is None:
        return _result(rule, len(rows), 0, 0, message=f"unsupported dimension: {rule.dimension}", evidence=False)
    if rule.dimension.lower() in {"reference_integrity", "references"}:
        return checker(rule, rows, references)
    return checker(rule, rows)


def evaluate_data_quality(records: Any, rules: Iterable[DataQualityRule] | None = None, *, references: Mapping[str, Any] | None = None,
                          required_fields: Sequence[str] | None = None, key_fields: Sequence[str] | None = None) -> list[DataQualityResult]:
    """Evaluate all supplied rules; absent rules get useful aggregate defaults."""
    rows = _records(records)
    selected = list(rules or ())
    if not selected and required_fields:
        selected.append(DataQualityRule("completeness", "completeness", required_fields=tuple(required_fields)))
    if not selected and key_fields:
        selected.append(DataQualityRule("uniqueness", "uniqueness", key_fields=tuple(key_fields)))
    return [evaluate_rule(rule, rows, references=references) for rule in selected]


def evaluate_rules(records: Any, rules: Iterable[DataQualityRule] | None = None, **kwargs: Any) -> list[DataQualityResult]:
    return evaluate_data_quality(records, rules, **kwargs)


def aggregate_quality(records: Any, *, required_fields: Sequence[str] | None = None,
                      key_fields: Sequence[str] | None = None, status_field: str = "status") -> dict[str, Any]:
    """Compute the legacy aggregate dimensions used by report summaries."""
    rows = _records(records)
    result: dict[str, Any] = {"completeness": None, "duplicate_rate": None, "unknown_rate": None,
                              "record_count": len(rows)}
    if rows and required_fields:
        complete = sum(all(not _missing(_get(row, f)) for f in required_fields) for row in rows)
        result["completeness"] = round(complete / len(rows) * 100, 2)
    if rows and key_fields:
        keys = [tuple(_get(row, f) for f in key_fields) for row in rows]
        result["duplicate_rate"] = round((len(keys) - len(set(keys))) / len(rows) * 100, 2)
    if rows and any(status_field in row for row in rows):
        result["unknown_rate"] = round(sum(str(row.get(status_field)).upper() == UNKNOWN for row in rows) / len(rows) * 100, 2)
    return result


__all__ = ["DataQualityRule", "DataQualityResult", "evaluate_rule", "evaluate_rules", "evaluate_data_quality", "aggregate_quality", "UNKNOWN", "PASS", "FAIL", "WARN"]

"""Evidence-aware deterministic data quality evaluation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import re
import sqlite3
from typing import Any, Callable, Iterable, Mapping, Sequence

UNKNOWN = "UNKNOWN"
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


def _records(value: Any) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
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
    for part in str(path).replace("[", ".").replace("]", "").split("."):
        if isinstance(value, Mapping) and part in value:
            value = value[part]
        elif isinstance(value, (list, tuple)) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def _type_name(value: Any) -> str:
    return type(value).__name__


def _normalise_expected_type(value: Any) -> tuple[type[Any], ...] | None:
    names = {"str": str, "string": str, "int": int, "integer": int, "float": float, "number": (int, float), "bool": bool, "boolean": bool, "list": list, "dict": dict, "mapping": Mapping}
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


def _secret_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(token in lowered for token in ("token", "password", "secret", "private_key", "privatekey", "encryption_key", "certificate", "raw_snippet", "stringdata"))


def _safe_json(value: Any, key: str = "") -> Any:
    if key and _secret_key(key):
        return {"redacted": True} if value is not None else None
    if isinstance(value, Mapping):
        return {str(k): _safe_json(v, str(k)) for k, v in value.items() if not _secret_key(str(k))}
    if isinstance(value, (list, tuple, set)):
        return [_safe_json(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _record_ref(record: Mapping[str, Any], index: int) -> str:
    source = record.get("source_id", record.get("source", ""))
    key = record.get("object_key", record.get("source_reference", record.get("id", record.get("name", ""))))
    return f"{source or 'unknown'}|{key or ''}|{index}"


def _example(record: Mapping[str, Any], detail: Any = None, index: int = 0) -> dict[str, Any]:
    result = {"record": _safe_json(record), "evidence_refs": [_record_ref(record, index)]}
    if detail is not None:
        result["detail"] = _safe_json(detail)
    return result


PythonQualityHandler = Callable[[Mapping[str, Any]], bool | tuple[bool, str]]
_PYTHON_HANDLERS: dict[str, PythonQualityHandler] = {}


def register_python_quality_handler(name: str, handler: PythonQualityHandler) -> None:
    if not str(name).strip() or not callable(handler):
        raise ValueError("quality handler requires a name and callable")
    _PYTHON_HANDLERS[str(name)] = handler


def _ai_label_present(row: Mapping[str, Any]) -> bool | tuple[bool, str]:
    value = row.get("ai_label")
    return (not _missing(value), "ai_label is present" if not _missing(value) else "ai_label is missing")


def _resource_identity_present(row: Mapping[str, Any]) -> bool | tuple[bool, str]:
    present = any(not _missing(row.get(key)) for key in ("entity_id", "object_key", "id", "uid", "name"))
    return (present, "resource identity is present" if present else "resource identity is missing")


register_python_quality_handler("ai_label_present", _ai_label_present)
register_python_quality_handler("resource_identity_present", _resource_identity_present)


@dataclass(frozen=True)
class DataQualityRule:
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
    name: str | None = None
    custom_type: str | None = None
    expression: str | None = None
    python_handler: str | None = None

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
        if self.custom_type is not None and self.custom_type not in {"regex", "sql", "python"}:
            raise ValueError(f"unsupported custom quality type: {self.custom_type}")
        if self.custom_type == "python" and not self.python_handler:
            raise ValueError("python custom rule requires python_handler")
        if self.custom_type in {"regex", "sql"} and not self.expression:
            raise ValueError(f"{self.custom_type} custom rule requires expression")

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
    score_known: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def unknown(self) -> bool:
        return self.status == UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _result(rule: DataQualityRule, total: int, passed: int, failed: int, unknown: int = 0, examples: list[dict[str, Any]] | None = None, message: str = "", evidence: bool = True, details: Mapping[str, Any] | None = None) -> DataQualityResult:
    comparable = passed + failed
    details_out = dict(details or {})
    details_out.setdefault("evidence_refs", sorted({str(ref) for example in examples or () for ref in example.get("evidence_refs", [])}))
    details_out.setdefault("root_causes", [f"quality:{rule.rule_id}"] if failed else [])
    details_out.setdefault("rule_type", rule.custom_type or rule.dimension)
    details_out.setdefault("comparison_count", comparable)
    details_out.setdefault("passed_count", passed)
    details_out.setdefault("failed_count", failed)
    details_out.setdefault("unknown_count", unknown)
    if not evidence or comparable == 0:
        status, score, score_known = UNKNOWN, None, False
        if not message:
            message = "no comparable evidence is available"
    else:
        score = round(passed / comparable * 100, 2)
        score_known = True
        status = FAIL if failed and score < rule.threshold else (UNKNOWN if not failed and unknown else PASS)
    return DataQualityResult(rule.rule_id, rule.dimension, status, score, total, passed, failed, unknown, examples or [], message, evidence, score_known, details_out)


def _field_evidence(rows: list[Mapping[str, Any]], fields: Iterable[str]) -> bool:
    names = tuple(fields)
    return bool(rows) and bool(names) and any(_get(row, f) is not None for row in rows for f in names)


def _check_completeness(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.required_fields or rule.fields
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="required field evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for index, row in enumerate(rows):
        missing = [name for name in fields if _missing(_get(row, name))]
        if missing:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"missing_fields": missing}, index))
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
        elif key in seen:
            duplicates.update((index, seen[key]))
        else:
            seen[key] = index
    examples = [_example(rows[i], {"key_fields": list(fields)}, i) for i in sorted(duplicates)[:rule.example_limit]]
    return _result(rule, len(rows), len(rows) - len(duplicates), len(duplicates), examples=examples, details={"duplicate_rate": round(len(duplicates) / len(rows) * 100, 2)})


def _check_field_validity(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    fields = rule.fields or tuple(rule.valid_values) or tuple(rule.patterns) or tuple(rule.ranges)
    if not rows or not fields or not _field_evidence(rows, fields):
        return _result(rule, len(rows), 0, 0, message="field validity evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for index, row in enumerate(rows):
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
                try:
                    if len(bounds) >= 1 and value < bounds[0]:
                        errors.append(f"{name}:below_min")
                    if len(bounds) >= 2 and value > bounds[1]:
                        errors.append(f"{name}:above_max")
                except TypeError:
                    errors.append(f"{name}:not_numeric")
        if errors:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"errors": errors}, index))
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
    for index, row in enumerate(rows):
        errors: list[str] = []
        for name in fields:
            value = _get(row, name)
            types = _normalise_expected_type(expected.get(name))
            if _missing(value) or not types or not isinstance(value, types):
                errors.append(f"{name}:expected={expected.get(name)!r},actual={_type_name(value)}")
        if errors:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"errors": errors}, index))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_cross_source(rule: DataQualityRule, rows: list[Mapping[str, Any]], association_result: Any = None) -> DataQualityResult:
    if association_result is not None:
        data = association_result.to_dict() if hasattr(association_result, "to_dict") else dict(association_result)
        groups = data.get("groups", []) or []
        matches = data.get("matches", []) or []
        if not groups and not matches:
            return _result(rule, len(rows), 0, 0, message="association evidence is absent", evidence=False)
        passed = failed = unknown = 0
        examples: list[dict[str, Any]] = []
        for index, group in enumerate(groups):
            status = str(group.get("status", UNKNOWN))
            refs = list(group.get("record_refs", []))
            if status == "MATCHED":
                passed += 1
            elif status in {"AMBIGUOUS", "UNMATCHED"}:
                failed += 1
                if len(examples) < rule.example_limit:
                    examples.append({"detail": {"status": status, "reason": group.get("reason")}, "evidence_refs": refs})
            else:
                unknown += 1
        for match in matches:
            condition_results = match.get("condition_results", []) or []
            mismatches = [item for item in condition_results if item.get("required") and item.get("matched") is False]
            if match.get("status") == "CONFLICT" or mismatches:
                failed += 1
                if len(examples) < rule.example_limit:
                    examples.append({"detail": {"status": "cross_source_field_conflict", "conditions": mismatches}, "evidence_refs": [match.get("left_ref"), match.get("right_ref")]})
            elif match.get("status") == "UNKNOWN":
                unknown += 1
        return _result(rule, len(groups) + len(matches), passed, failed, unknown, examples, message="cross-source association results evaluated", evidence=True, details={"association_counts": data.get("counts", {}), "comparison_count": passed + failed})
    source_field = rule.source_field
    fields = rule.compare_fields or rule.fields
    if not rows or not source_field or not fields:
        return _result(rule, len(rows), 0, 0, message="source or comparison evidence is absent", evidence=False)
    sources = {_get(row, source_field) for row in rows if not _missing(_get(row, source_field))}
    if len(sources) < 2:
        return _result(rule, len(rows), 0, 0, message="at least two sources are required", evidence=False)
    groups: dict[tuple[Any, ...], list[tuple[int, Mapping[str, Any]]]] = {}
    group_fields = rule.key_fields or rule.group_fields
    if not group_fields:
        group_fields = ("id",) if any(_get(r, "id") is not None for r in rows) else tuple()
    if not group_fields:
        return _result(rule, len(rows), 0, 0, message="record identity evidence is absent", evidence=False)
    for index, row in enumerate(rows):
        key = tuple(_get(row, name) for name in group_fields)
        if not any(_missing(v) for v in key):
            groups.setdefault(key, []).append((index, row))
    compared = failed = 0
    examples: list[dict[str, Any]] = []
    for group in groups.values():
        if len({_get(row, source_field) for _, row in group}) < 2:
            continue
        compared += 1
        values = {tuple(_get(row, name) for name in fields) for _, row in group}
        if len(values) > 1:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(group[0][1], {"sources": sorted(str(_get(r, source_field)) for _, r in group), "values": list(values)}, group[0][0]))
    return _result(rule, compared, compared - failed, failed, examples=examples)


def _check_references(rule: DataQualityRule, rows: list[Mapping[str, Any]], references: Mapping[str, Any] | None) -> DataQualityResult:
    mapping = dict(references or {})
    fields = dict(rule.reference_fields)
    if not rows or not fields or not mapping:
        return _result(rule, len(rows), 0, 0, message="reference evidence is absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for index, row in enumerate(rows):
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
                examples.append(_example(row, {"errors": errors}, index))
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
    for row in rows:
        parsed = _parse_time(_get(row, rule.time_field))
        if parsed is not None:
            groups.setdefault(tuple(_get(row, f) for f in rule.group_fields), []).append(parsed)
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
    for index, row in enumerate(rows):
        missing = [name for name in fields if _missing(_get(row, name))]
        if missing:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"missing_fields": missing}, index))
        else:
            passed += 1
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_custom_regex(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    if not rows:
        return _result(rule, 0, 0, 0, message="regex evidence is absent", evidence=False)
    try:
        pattern = re.compile(str(rule.expression))
    except re.error as exc:
        return _result(rule, len(rows), 0, 0, message=f"invalid custom regex: {exc}", evidence=False)
    fields = rule.fields or tuple(rule.patterns) or rule.required_fields
    if not fields:
        return _result(rule, len(rows), 0, 0, message="custom regex fields are absent", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = 0
    for index, row in enumerate(rows):
        values = [_get(row, name) for name in fields]
        ok = all(not _missing(value) and pattern.fullmatch(str(value)) is not None for value in values)
        if ok:
            passed += 1
        else:
            failed += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"fields": list(fields), "expression": rule.expression}, index))
    return _result(rule, len(rows), passed, failed, examples=examples)


def _check_custom_python(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    handler = _PYTHON_HANDLERS.get(str(rule.python_handler))
    if handler is None:
        return _result(rule, len(rows), 0, 0, len(rows), message=f"python quality handler is not registered: {rule.python_handler}", evidence=False)
    examples: list[dict[str, Any]] = []
    passed = failed = unknown = 0
    for index, row in enumerate(rows):
        try:
            outcome = handler(row)
            if isinstance(outcome, tuple):
                ok, reason = bool(outcome[0]), str(outcome[1])
            else:
                ok, reason = bool(outcome), "registered handler evaluation"
            if ok:
                passed += 1
            else:
                failed += 1
                if len(examples) < rule.example_limit:
                    examples.append(_example(row, {"reason": reason}, index))
        except Exception as exc:
            unknown += 1
            if len(examples) < rule.example_limit:
                examples.append(_example(row, {"reason": f"handler error: {type(exc).__name__}"}, index))
    return _result(rule, len(rows), passed, failed, unknown, examples, details={"handler": rule.python_handler})


def _check_custom_sql(rule: DataQualityRule, rows: list[Mapping[str, Any]]) -> DataQualityResult:
    statement = str(rule.expression or "").strip()
    lowered = statement.lower()
    if not statement or ";" in statement or not (lowered.startswith("select ") or lowered.startswith("select\n") or lowered.startswith("with ")):
        return _result(rule, len(rows), 0, 0, 0, message="custom SQL must be one read-only SELECT or WITH statement", evidence=False)
    if re.search(r"\b(insert|update|delete|drop|alter|create|attach|pragma|replace|vacuum|reindex)\b", lowered):
        return _result(rule, len(rows), 0, 0, message="custom SQL contains a prohibited write or control token", evidence=False)
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE records(row_index INTEGER, source_id TEXT, object_key TEXT, record_json TEXT)")
        for index, row in enumerate(rows):
            connection.execute("INSERT INTO records VALUES (?, ?, ?, ?)", (index, str(row.get("source_id", row.get("source", "")) or ""), str(row.get("object_key", row.get("id", "")) or ""), json.dumps(_safe_json(row), ensure_ascii=False, default=str)))
        try:
            connection.execute("SELECT json_extract('{\"probe\":1}', '$.probe')").fetchone()
        except sqlite3.DatabaseError:
            return _result(rule, len(rows), 0, 0, len(rows), message="SQLite JSON1 is unavailable", evidence=False)
        try:
            cursor = connection.execute(statement)
            columns = [str(item[0]) for item in cursor.description or ()]
            if "row_index" not in columns:
                return _result(rule, len(rows), 0, 0, len(rows), message="custom SQL result must include row_index", evidence=False)
            failed_indexes = {int(row[columns.index("row_index")]) for row in cursor.fetchall() if str(row[columns.index("row_index")]).lstrip("-").isdigit()}
        except sqlite3.DatabaseError as exc:
            return _result(rule, len(rows), 0, 0, len(rows), message=f"custom SQL is invalid: {type(exc).__name__}", evidence=False)
    finally:
        connection.close()
    failed_indexes &= set(range(len(rows)))
    examples = [_example(rows[index], {"row_index": index}, index) for index in sorted(failed_indexes)[:rule.example_limit]]
    return _result(rule, len(rows), len(rows) - len(failed_indexes), len(failed_indexes), examples=examples, details={"sql_read_only": True})


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


def evaluate_rule(rule: DataQualityRule, records: Any, *, references: Mapping[str, Any] | None = None, association_result: Any = None) -> DataQualityResult:
    rows = _records(records)
    if rule.custom_type == "regex":
        return _check_custom_regex(rule, rows)
    if rule.custom_type == "sql":
        return _check_custom_sql(rule, rows)
    if rule.custom_type == "python":
        return _check_custom_python(rule, rows)
    checker = _CHECKERS.get(rule.dimension.lower())
    if checker is None:
        return _result(rule, len(rows), 0, 0, message=f"unsupported dimension: {rule.dimension}", evidence=False)
    if rule.dimension.lower() in {"reference_integrity", "references"}:
        return checker(rule, rows, references)
    if rule.dimension.lower() in {"cross_source_consistency", "consistency"}:
        return checker(rule, rows, association_result)
    return checker(rule, rows)


def evaluate_data_quality(records: Any, rules: Iterable[DataQualityRule] | None = None, *, references: Mapping[str, Any] | None = None, association_result: Any = None, required_fields: Sequence[str] | None = None, key_fields: Sequence[str] | None = None) -> list[DataQualityResult]:
    rows = _records(records)
    selected = list(rules or ())
    if not selected and required_fields:
        selected.append(DataQualityRule("completeness", "completeness", required_fields=tuple(required_fields)))
    if not selected and key_fields:
        selected.append(DataQualityRule("uniqueness", "uniqueness", key_fields=tuple(key_fields)))
    return [evaluate_rule(rule, rows, references=references, association_result=association_result) for rule in selected]


def evaluate_rules(records: Any, rules: Iterable[DataQualityRule] | None = None, **kwargs: Any) -> list[DataQualityResult]:
    return evaluate_data_quality(records, rules, **kwargs)


def aggregate_quality(records: Any, *, required_fields: Sequence[str] | None = None, key_fields: Sequence[str] | None = None, status_field: str = "status") -> dict[str, Any]:
    rows = _records(records)
    result: dict[str, Any] = {"completeness": None, "duplicate_rate": None, "unknown_rate": None, "record_count": len(rows)}
    if rows and required_fields:
        complete = sum(all(not _missing(_get(row, f)) for f in required_fields) for row in rows)
        result["completeness"] = round(complete / len(rows) * 100, 2)
    if rows and key_fields:
        keys = [tuple(_get(row, f) for f in key_fields) for row in rows]
        result["duplicate_rate"] = round((len(keys) - len(set(keys))) / len(rows) * 100, 2)
    if rows and any(status_field in row for row in rows):
        result["unknown_rate"] = round(sum(str(row.get(status_field)).upper() == UNKNOWN for row in rows) / len(rows) * 100, 2)
    return result


__all__ = ["DataQualityRule", "DataQualityResult", "PythonQualityHandler", "register_python_quality_handler", "evaluate_rule", "evaluate_rules", "evaluate_data_quality", "aggregate_quality", "UNKNOWN", "PASS", "FAIL", "WARN"]

"""Deterministic data observability, association, and quality metric products.

The module deliberately contains no network or model calls.  Every result is
built from supplied records and keeps evidence references instead of raw
sensitive values.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
import hashlib
import ipaddress
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from .field_mapping import get_path


_SENSITIVE_PARTS = (
    "password", "passwd", "secret", "token", "credential", "private_key",
    "privatekey", "api_key", "apikey", "access_key", "accesskey",
    "client_key", "certificate", "tls_cert", "private", "encryption_key",
    "stringdata", "raw_snippet",
)


def _sensitive(key: str) -> bool:
    lowered = str(key).lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_PARTS)


def _safe(value: Any, key: str = "") -> Any:
    if key and _sensitive(key):
        if value is None:
            return None
        if isinstance(value, str):
            return {"redacted": True, "type": "string", "length": len(value)}
        return {"redacted": True, "type": type(value).__name__}
    if isinstance(value, Mapping):
        return {str(k): _safe(v, str(k)) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _known(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "null"}


def _missing(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _record_ref(record: Mapping[str, Any], index: int) -> str:
    source = record.get("source_id", record.get("source", record.get("source_type", "")))
    if isinstance(source, Mapping):
        source = source.get("source_id") or source.get("id") or source.get("name")
    object_key = record.get("object_key", record.get("source_reference", record.get("id", record.get("name", ""))))
    return f"{str(source or 'unknown')}|{str(object_key or '')}|{index}"


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


@dataclass(frozen=True)
class AnomalyRule:
    rule_id: str
    field_path: str
    detector: str
    minimum: float | None = None
    maximum: float | None = None
    pattern: str | None = None
    severity: str = "medium"

    def __post_init__(self) -> None:
        if not str(self.rule_id).strip() or not str(self.field_path).strip():
            raise ValueError("anomaly rule requires rule_id and field_path")
        detector = str(self.detector).lower()
        if detector not in {"range", "regex", "iqr"}:
            raise ValueError(f"unsupported anomaly detector: {self.detector}")
        object.__setattr__(self, "detector", detector)
        if detector == "range" and self.minimum is None and self.maximum is None:
            raise ValueError("range anomaly rule requires minimum or maximum")
        if detector == "regex":
            if not self.pattern:
                raise ValueError("regex anomaly rule requires pattern")
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid anomaly regex: {exc}") from exc
        if detector == "iqr" and self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("anomaly minimum cannot exceed maximum")
        object.__setattr__(self, "severity", str(self.severity or "medium").lower())

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass(frozen=True)
class AnomalyRecord:
    anomaly_id: str
    anomaly_type: str
    status: str
    source_id: str = ""
    object_key: str = ""
    field_path: str = ""
    rule_id: str | None = None
    reason: str = ""
    observed_value: Any = None
    expected_value: Any = None
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_refs"] = list(self.evidence_refs)
        payload["observed_value"] = _safe(self.observed_value, self.field_path)
        payload["expected_value"] = _safe(self.expected_value, self.field_path)
        return _safe(payload)


def _anomaly_id(*parts: Any) -> str:
    raw = "|".join(json.dumps(part, ensure_ascii=False, sort_keys=True, default=str) for part in parts)
    return "anomaly-" + hashlib.sha256(raw.encode()).hexdigest()[:20]


def detect_anomalies(records: Iterable[Mapping[str, Any]], rules: Iterable[AnomalyRule]) -> list[AnomalyRecord]:
    rows = [row for row in records if isinstance(row, Mapping)]
    result: list[AnomalyRecord] = []
    for rule in rules:
        values: list[tuple[int, Mapping[str, Any], Any]] = [
            (index, row, get_path(row, rule.field_path))
            for index, row in enumerate(rows)
        ]
        numeric: list[float] = []
        if rule.detector == "iqr":
            for _, _, value in values:
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    numeric.append(float(value))
            if len(numeric) < 4:
                result.append(AnomalyRecord(
                    _anomaly_id(rule.rule_id, rule.field_path, "insufficient"),
                    "iqr", "UNKNOWN", field_path=rule.field_path, rule_id=rule.rule_id,
                    reason="IQR requires at least four numeric observations; evidence is insufficient",
                    expected_value={"minimum_samples": 4},
                ))
                continue
            ordered = sorted(numeric)
            midpoint = len(ordered) // 2
            lower_half = ordered[:midpoint]
            upper_half = ordered[midpoint + (len(ordered) % 2):]
            q1 = lower_half[len(lower_half) // 2] if len(lower_half) % 2 else (lower_half[len(lower_half) // 2 - 1] + lower_half[len(lower_half) // 2]) / 2
            q3 = upper_half[len(upper_half) // 2] if len(upper_half) % 2 else (upper_half[len(upper_half) // 2 - 1] + upper_half[len(upper_half) // 2]) / 2
            iqr = q3 - q1
            minimum, maximum = q1 - 1.5 * iqr, q3 + 1.5 * iqr
            for index, row, value in values:
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    continue
                if float(value) < minimum or float(value) > maximum:
                    result.append(AnomalyRecord(
                        _anomaly_id(rule.rule_id, _record_ref(row, index), value), "iqr", "FAIL",
                        str(row.get("source_id", row.get("source", "")) or ""),
                        str(row.get("object_key", row.get("id", row.get("name", ""))) or ""),
                        rule.field_path, rule.rule_id, "value is outside Tukey 1.5×IQR bounds", value,
                        {"minimum": minimum, "maximum": maximum, "q1": q1, "q3": q3}, (_record_ref(row, index),),
                    ))
            continue
        compiled = re.compile(rule.pattern) if rule.detector == "regex" and rule.pattern else None
        for index, row, value in values:
            if _missing(value):
                continue
            failed = False
            reason = ""
            expected: Any = None
            if rule.detector == "range":
                expected = {"minimum": rule.minimum, "maximum": rule.maximum}
                failed = ((rule.minimum is not None and float(value) < rule.minimum) or
                          (rule.maximum is not None and float(value) > rule.maximum))
                reason = "value is outside configured range"
            elif compiled is not None:
                failed = compiled.fullmatch(str(value)) is None
                expected = rule.pattern
                reason = "value does not match configured regular expression"
            if failed:
                result.append(AnomalyRecord(
                    _anomaly_id(rule.rule_id, _record_ref(row, index), value), rule.detector, "FAIL",
                    str(row.get("source_id", row.get("source", "")) or ""),
                    str(row.get("object_key", row.get("id", row.get("name", ""))) or ""),
                    rule.field_path, rule.rule_id, reason, value, expected, (_record_ref(row, index),),
                ))
    return result


@dataclass(frozen=True)
class AssociationCondition:
    field_path: str
    condition_type: str
    mode: str = "exact"
    required: bool = True
    tolerance_seconds: float | None = None
    threshold: float = 1.0
    aliases: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        allowed_types = {"entity_id", "timestamp", "ip", "port", "text"}
        allowed_modes = {"exact", "fuzzy", "semantic"}
        if not str(self.field_path).strip() or self.condition_type not in allowed_types:
            raise ValueError("association condition has unsupported field or type")
        if self.mode not in allowed_modes:
            raise ValueError(f"unsupported association mode: {self.mode}")
        if not 0 <= float(self.threshold) <= 1:
            raise ValueError("association threshold must be between 0 and 1")
        if self.condition_type == "timestamp" and self.tolerance_seconds is not None and self.tolerance_seconds < 0:
            raise ValueError("timestamp tolerance cannot be negative")
        object.__setattr__(self, "threshold", float(self.threshold))
        object.__setattr__(self, "aliases", {str(k).lower(): str(v).lower() for k, v in dict(self.aliases or {}).items()})

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass(frozen=True)
class AssociationConfig:
    source_field: str = "source"
    conditions: tuple[AssociationCondition, ...] = ()
    min_sources: int = 2
    max_candidates: int = 50

    def __post_init__(self) -> None:
        if isinstance(self.conditions, (str, Mapping)):
            raw_conditions = (self.conditions,)
        else:
            raw_conditions = tuple(self.conditions or ())
        parsed: list[AssociationCondition] = []
        for raw in raw_conditions:
            parsed.append(raw if isinstance(raw, AssociationCondition) else AssociationCondition(**dict(raw)))
        if self.min_sources < 1 or self.max_candidates < 1:
            raise ValueError("association source and candidate limits must be positive")
        object.__setattr__(self, "conditions", tuple(parsed))

    def to_dict(self) -> dict[str, Any]:
        return {"source_field": self.source_field, "conditions": [item.to_dict() for item in self.conditions], "min_sources": self.min_sources, "max_candidates": self.max_candidates}


@dataclass(frozen=True)
class AssociationMatch:
    match_id: str
    left_ref: str
    right_ref: str
    status: str
    score: float | None
    condition_results: tuple[Mapping[str, Any], ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _safe({**asdict(self), "condition_results": [dict(item) for item in self.condition_results]})


@dataclass(frozen=True)
class AssociationGroup:
    association_id: str
    record_refs: tuple[str, ...]
    source_ids: tuple[str, ...]
    status: str
    match_ids: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"record_refs": list(self.record_refs), "source_ids": list(self.source_ids), "match_ids": list(self.match_ids)}


@dataclass(frozen=True)
class AssociationResult:
    groups: tuple[AssociationGroup, ...] = ()
    matches: tuple[AssociationMatch, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)
    conditions: tuple[AssociationCondition, ...] = ()
    graph: Mapping[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": []})

    def to_dict(self) -> dict[str, Any]:
        return _safe({
            "groups": [item.to_dict() for item in self.groups],
            "matches": [item.to_dict() for item in self.matches],
            "counts": dict(self.counts),
            "conditions": [item.to_dict() for item in self.conditions],
            "graph": dict(self.graph),
        })


def _normalize_condition(value: Any, condition: AssociationCondition) -> Any:
    if _missing(value):
        return None
    if condition.condition_type == "ip":
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            return str(value).strip().lower()
    if condition.condition_type == "port":
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return str(value).strip().lower()
    if condition.condition_type == "timestamp":
        parsed = _parse_time(value)
        return parsed.timestamp() if parsed else None
    text = str(value).strip().lower()
    return text


def _semantic_tokens(value: Any, aliases: Mapping[str, str]) -> set[str]:
    tokens = re.findall(r"[a-z0-9_./-]+", str(value).lower())
    return {aliases.get(token, token) for token in tokens}


def _compare_condition(left: Mapping[str, Any], right: Mapping[str, Any], condition: AssociationCondition) -> dict[str, Any]:
    left_value = get_path(left, condition.field_path)
    right_value = get_path(right, condition.field_path)
    result: dict[str, Any] = {
        "field_path": condition.field_path,
        "condition_type": condition.condition_type,
        "mode": condition.mode,
        "required": condition.required,
        "threshold": condition.threshold,
        "matched": None,
        "score": None,
        "reason": "",
        "left_value": _safe(left_value, condition.field_path),
        "right_value": _safe(right_value, condition.field_path),
    }
    if _missing(left_value) or _missing(right_value):
        result["reason"] = "required comparison value is missing" if condition.required else "optional comparison value is missing"
        return result
    left_normal = _normalize_condition(left_value, condition)
    right_normal = _normalize_condition(right_value, condition)
    if left_normal is None or right_normal is None:
        result["reason"] = "value could not be normalized deterministically"
        return result
    if condition.condition_type == "timestamp":
        tolerance = float(condition.tolerance_seconds or 0)
        distance = abs(float(left_normal) - float(right_normal))
        result["score"] = 1.0 if distance <= tolerance else max(0.0, 1.0 - distance / max(tolerance, 1.0))
        result["matched"] = distance <= tolerance
        result["reason"] = "timestamp within tolerance" if result["matched"] else "timestamp exceeds tolerance"
        return result
    if condition.mode == "exact" or condition.condition_type in {"entity_id", "ip", "port"}:
        result["score"] = 1.0 if left_normal == right_normal else 0.0
        result["matched"] = left_normal == right_normal
        result["reason"] = "normalized exact values match" if result["matched"] else "normalized exact values differ"
        return result
    if condition.mode == "fuzzy":
        score = SequenceMatcher(None, str(left_normal), str(right_normal)).ratio()
        result["score"] = round(score, 4)
        result["matched"] = score >= condition.threshold
        result["reason"] = "deterministic fuzzy similarity meets threshold" if result["matched"] else "fuzzy similarity is below threshold"
        return result
    left_tokens = _semantic_tokens(left_normal, condition.aliases)
    right_tokens = _semantic_tokens(right_normal, condition.aliases)
    union = left_tokens | right_tokens
    score = len(left_tokens & right_tokens) / len(union) if union else 0.0
    result["score"] = round(score, 4)
    result["matched"] = score >= condition.threshold
    result["reason"] = "deterministic semantic token-Jaccard match" if result["matched"] else "semantic token-Jaccard score is below threshold"
    return result


def _component_groups(refs: Iterable[str], pairs: Iterable[tuple[str, str]]) -> list[set[str]]:
    adjacency: dict[str, set[str]] = {ref: set() for ref in refs}
    for left, right in pairs:
        adjacency.setdefault(left, set()).add(right)
        adjacency.setdefault(right, set()).add(left)
    components: list[set[str]] = []
    seen: set[str] = set()
    for ref in sorted(adjacency):
        if ref in seen:
            continue
        component: set[str] = set()
        queue = deque([ref])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            component.add(current)
            queue.extend(sorted(adjacency.get(current, ())))
        components.append(component)
    return components


def associate_records(records: Iterable[Mapping[str, Any]], config: AssociationConfig | Mapping[str, Any]) -> AssociationResult:
    cfg = config if isinstance(config, AssociationConfig) else AssociationConfig(**dict(config))
    rows = [dict(row) for row in records if isinstance(row, Mapping)]
    refs = [_record_ref(row, index) for index, row in enumerate(rows)]
    sources = [str(row.get(cfg.source_field) or row.get("source_id") or "") for row in rows]
    exact_entity = next((condition for condition in cfg.conditions if condition.condition_type == "entity_id" and condition.mode == "exact"), None)
    candidate_pairs: list[tuple[int, int]] = []
    if exact_entity:
        blocks: dict[tuple[str, Any], list[int]] = defaultdict(list)
        for index, row in enumerate(rows):
            entity = _normalize_condition(get_path(row, exact_entity.field_path), exact_entity)
            namespace = row.get("namespace", row.get("namespace_id", ""))
            if _known(entity) and _known(sources[index]):
                blocks[(str(namespace), entity)].append(index)
        for members in blocks.values():
            for left_offset, left_index in enumerate(members):
                for right_index in members[left_offset + 1:]:
                    if sources[left_index] != sources[right_index]:
                        candidate_pairs.append((left_index, right_index))
    else:
        for left_index, left_source in enumerate(sources):
            if not _known(left_source):
                continue
            for right_index in range(left_index + 1, min(len(rows), left_index + cfg.max_candidates + 1)):
                if _known(sources[right_index]) and left_source != sources[right_index]:
                    candidate_pairs.append((left_index, right_index))
    candidate_pairs = sorted(set(candidate_pairs))
    matches: list[AssociationMatch] = []
    pair_refs: list[tuple[str, str]] = []
    candidate_counts: Counter[str] = Counter()
    unknown_refs: set[str] = set()
    for left_index, right_index in candidate_pairs[: max(1, len(candidate_pairs))]:
        if len(matches) >= cfg.max_candidates * max(1, len(rows)):
            break
        condition_results = tuple(_compare_condition(rows[left_index], rows[right_index], condition) for condition in cfg.conditions)
        required = [item for item in condition_results if item.get("required")]
        unknown = [item for item in required if item.get("matched") is None]
        failed = [item for item in required if item.get("matched") is False]
        if unknown:
            status, reason = "UNKNOWN", "a required condition lacks comparable evidence"
        elif failed:
            status, reason = "CONFLICT", "one or more required conditions disagree"
        else:
            status, reason = "MATCHED", "all required association conditions matched"
        scores = [float(item["score"]) for item in condition_results if item.get("score") is not None]
        score = round(sum(scores) / len(scores), 4) if scores else None
        match_id = "match-" + hashlib.sha256(f"{refs[left_index]}|{refs[right_index]}".encode()).hexdigest()[:20]
        matches.append(AssociationMatch(match_id, refs[left_index], refs[right_index], status, score, condition_results, reason))
        candidate_counts[refs[left_index]] += 1
        candidate_counts[refs[right_index]] += 1
        if status == "UNKNOWN":
            unknown_refs.update((refs[left_index], refs[right_index]))
        if status in {"MATCHED", "CONFLICT"}:
            pair_refs.append((refs[left_index], refs[right_index]))
    matched_or_conflict = {ref for pair in pair_refs for ref in pair}
    groups: list[AssociationGroup] = []
    for component in _component_groups(refs, pair_refs):
        component_matches = [match for match in matches if match.left_ref in component and match.right_ref in component]
        component_sources = tuple(sorted({sources[refs.index(ref)] for ref in component if _known(sources[refs.index(ref)])}))
        if len(component_sources) < cfg.min_sources:
            status, reason = "UNKNOWN", "fewer than the configured minimum number of sources"
        elif any(ref in unknown_refs for ref in component) and not any(item.status == "MATCHED" for item in component_matches):
            status, reason = "UNKNOWN", "required association evidence is incomplete"
        elif any(candidate_counts[ref] > 1 for ref in component) or any(item.status == "CONFLICT" for item in component_matches):
            status, reason = "AMBIGUOUS", "multiple candidates or conflicting condition evidence"
        else:
            status, reason = "MATCHED", "records form a deterministic cross-source group"
        association_id = "association-" + hashlib.sha256("|".join(sorted(component)).encode()).hexdigest()[:20]
        groups.append(AssociationGroup(association_id, tuple(sorted(component)), component_sources, status, tuple(item.match_id for item in component_matches), reason))
    grouped = {ref for group in groups for ref in group.record_refs}
    for index, ref in enumerate(refs):
        if ref in grouped:
            continue
        source = sources[index]
        has_required = any(condition.required and _missing(get_path(rows[index], condition.field_path)) for condition in cfg.conditions)
        status = "UNKNOWN" if not _known(source) or has_required else "UNMATCHED"
        reason = "source or required condition evidence is missing" if status == "UNKNOWN" else "no cross-source candidate satisfied the blocking conditions"
        association_id = "association-" + hashlib.sha256(ref.encode()).hexdigest()[:20]
        groups.append(AssociationGroup(association_id, (ref,), (source,) if _known(source) else (), status, (), reason))
    groups.sort(key=lambda item: item.association_id)
    counts = Counter(group.status for group in groups)
    nodes = [
        {"id": ref, "record_ref": ref, "source_id": sources[index], "status": next(group.status for group in groups if ref in group.record_refs)}
        for index, ref in enumerate(refs)
    ]
    edges = [{"id": match.match_id, "source": match.left_ref, "target": match.right_ref, "status": match.status, "score": match.score} for match in matches]
    return AssociationResult(tuple(groups), tuple(sorted(matches, key=lambda item: item.match_id)), dict(sorted(counts.items())), cfg.conditions, {"nodes": nodes, "edges": edges})


@dataclass(frozen=True)
class QualityMetric:
    metric_id: str
    label: str
    status: str
    value: float | None
    total_count: int
    affected_count: int
    pass_rate: float | None = None
    unknown_reason: str | None = None
    distribution: Mapping[str, int] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    root_cause_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _safe({**asdict(self), "evidence_refs": list(self.evidence_refs), "root_cause_codes": list(self.root_cause_codes), "distribution": dict(self.distribution)})


@dataclass(frozen=True)
class QualityMetrics:
    record_count: int
    rule_pass_rate: float | None
    rule_fail_rate: float | None
    rule_unknown_rate: float | None
    metrics: tuple[QualityMetric, ...] = ()
    root_causes: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _safe({
            "record_count": self.record_count,
            "rule_pass_rate": self.rule_pass_rate,
            "rule_fail_rate": self.rule_fail_rate,
            "rule_unknown_rate": self.rule_unknown_rate,
            "metrics": [metric.to_dict() for metric in self.metrics],
            "root_causes": [dict(item) for item in self.root_causes],
        })


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, Mapping) else {}
    return {}


def _result_refs(result: Any) -> list[str]:
    item = _as_mapping(result)
    details = _as_mapping(item.get("details"))
    refs: list[str] = [str(ref) for ref in details.get("evidence_refs", []) if ref]
    for example in item.get("examples", []) or []:
        example_map = _as_mapping(example)
        refs.extend(str(ref) for ref in example_map.get("evidence_refs", example_map.get("record_refs", [])) if ref)
        detail = _as_mapping(example_map.get("detail"))
        refs.extend(str(ref) for ref in detail.get("evidence_refs", detail.get("record_refs", [])) if ref)
    return sorted(set(refs))


def build_quality_metrics(
    records: Iterable[Mapping[str, Any]],
    quality_results: Iterable[Any],
    *,
    cleaning_result: Any = None,
    mapping_result: Any = None,
    dedup_result: Any = None,
    associations: AssociationResult | Mapping[str, Any] | None = None,
    label_field: str | None = None,
) -> QualityMetrics:
    rows = [row for row in records if isinstance(row, Mapping)]
    results = [_as_mapping(item) for item in quality_results or ()]
    anomalies = list(getattr(cleaning_result, "anomalies", []) or [])
    anomaly_maps = [_as_mapping(item) for item in anomalies]
    refs_for_missing = sorted({ref for item in anomaly_maps if str(item.get("anomaly_type")) in {"missing_value", "missing_value_imputed"} for ref in item.get("evidence_refs", [])})
    missing_count = sum(str(item.get("anomaly_type")) in {"missing_value", "missing_value_imputed"} and item.get("status") != "UNKNOWN" for item in anomaly_maps)
    invalid_anomalies = [item for item in anomaly_maps if str(item.get("anomaly_type")) in {"invalid_value", "invalid_ip", "invalid_port", "invalid_timestamp_preserved"}]
    invalid_count = int(getattr(cleaning_result, "invalid_count", 0) or 0) + len(invalid_anomalies)
    mapping = _as_mapping(mapping_result)
    mapping_errors = len(mapping.get("errors", []) or [])
    rule_fail_refs = sorted({ref for result in results if str(result.get("status")) == "FAIL" for ref in _result_refs(result)})
    error_refs = sorted(set(rule_fail_refs) | {str(ref) for item in invalid_anomalies for ref in item.get("evidence_refs", [])})
    duplicate_count = int(getattr(dedup_result, "duplicate_count", 0) or 0)
    if duplicate_count == 0 and isinstance(dedup_result, Mapping):
        duplicate_count = int(dedup_result.get("duplicate_count", 0) or 0)
    root_causes: list[dict[str, Any]] = []
    def add_root(code: str, message: str, count: int, refs: Iterable[str], lineage: Iterable[str]) -> None:
        if count <= 0:
            return
        root_causes.append({"code": code, "message": message, "count": count, "record_refs": sorted(set(str(ref) for ref in refs if ref)), "lineage_node_ids": sorted(set(str(node) for node in lineage if node))})
    add_root("missing_value", "required fields are missing", missing_count, refs_for_missing, [f"anomaly:{item.get('anomaly_id')}" for item in anomaly_maps if item.get("anomaly_type") == "missing_value"])
    add_root("mapping_conversion_error", "field mapping conversion failed", mapping_errors, (), ["mapping:errors"] if mapping_errors else ())
    add_root("invalid_value", "cleaning or validation found invalid values", invalid_count, error_refs, [f"anomaly:{item.get('anomaly_id')}" for item in invalid_anomalies])
    for result in results:
        if str(result.get("status")) == "FAIL":
            refs = _result_refs(result)
            add_root(f"quality:{result.get('rule_id')}", str(result.get("message") or f"quality rule {result.get('rule_id')} failed"), int(result.get("failed_count", 0) or 0), refs, [f"quality:{result.get('rule_id')}"])
    add_root("duplicate_record", "duplicate records were deduplicated", duplicate_count, (), ["dedup:duplicates"])
    labels: Counter[str] = Counter()
    if label_field:
        for row in rows:
            value = get_path(row, label_field)
            if not _missing(value):
                labels[str(value)] += 1
    metrics: list[QualityMetric] = []
    metrics.append(QualityMetric(
        "missing_values", "缺失值", "UNKNOWN" if not rows else ("FAIL" if missing_count else "PASS"),
        None if not rows else float(missing_count), len(rows), missing_count,
        None if not rows else round((len(rows) - missing_count) / len(rows) * 100, 2),
        "no records available" if not rows else None, {}, tuple(refs_for_missing),
        ("missing_value",) if missing_count else (),
    ))
    affected_errors = invalid_count + mapping_errors + sum(int(result.get("failed_count", 0) or 0) for result in results if str(result.get("status")) == "FAIL")
    metrics.append(QualityMetric(
        "errors", "错误", "UNKNOWN" if not rows else ("FAIL" if affected_errors else "PASS"),
        None if not rows else float(affected_errors), len(rows), affected_errors,
        None if not rows else round((len(rows) - min(len(rows), affected_errors)) / len(rows) * 100, 2),
        "no records available" if not rows else None, {}, tuple(error_refs),
        tuple(sorted({str(item["code"]) for item in root_causes if item["code"] in {"invalid_value", "mapping_conversion_error"} or str(item["code"]).startswith("quality:")})),
    ))
    metrics.append(QualityMetric(
        "duplicates", "重复记录", "UNKNOWN" if not rows else ("FAIL" if duplicate_count else "PASS"),
        None if not rows else float(duplicate_count), len(rows), duplicate_count,
        None if not rows else round((len(rows) - min(len(rows), duplicate_count)) / len(rows) * 100, 2),
        "no records available" if not rows else None, {}, (), ("duplicate_record",) if duplicate_count else (),
    ))
    if not label_field:
        metrics.append(QualityMetric("ai_label_balance", "AI 标签均衡", "UNKNOWN", None, len(rows), 0, None, "label_field is not configured", dict(labels), (), ()))
    elif not labels:
        metrics.append(QualityMetric("ai_label_balance", "AI 标签均衡", "UNKNOWN", None, len(rows), 0, None, "label field has no valid labels", {}, (), ()))
    else:
        maximum, minimum = max(labels.values()), min(labels.values())
        balance = round(minimum / maximum, 4) if maximum else None
        affected = maximum - minimum
        status = "PASS" if balance is not None and balance >= 0.5 else "FAIL"
        metrics.append(QualityMetric("ai_label_balance", "AI 标签均衡", status, balance, sum(labels.values()), affected, round(balance * 100, 2) if balance is not None else None, None, (), ("ai_label_imbalance",) if status == "FAIL" else ()))
        add_root("ai_label_imbalance", "AI label distribution is imbalanced", affected, (), ["quality-metric:ai_label_balance"])
    total_rules = len(results)
    if total_rules:
        counts = Counter(str(item.get("status", "UNKNOWN")) for item in results)
        pass_rate = round(counts.get("PASS", 0) / total_rules * 100, 2)
        fail_rate = round(counts.get("FAIL", 0) / total_rules * 100, 2)
        unknown_rate = round(counts.get("UNKNOWN", 0) / total_rules * 100, 2)
    else:
        pass_rate = fail_rate = unknown_rate = None
    return QualityMetrics(len(rows), pass_rate, fail_rate, unknown_rate, tuple(metrics), tuple(root_causes))


__all__ = [
    "AnomalyRule", "AnomalyRecord", "detect_anomalies", "AssociationCondition",
    "AssociationConfig", "AssociationMatch", "AssociationGroup", "AssociationResult",
    "associate_records", "QualityMetric", "QualityMetrics", "build_quality_metrics",
]

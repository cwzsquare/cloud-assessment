"""Deterministic resource and evidence deduplication.

Duplicates retain every non-sensitive source reference.  A winner is selected
using explicit source precedence, scope, and freshness; equally ranked
conflicting values are never hidden and produce :class:`DataConflict` rows.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _safe(value: Any, key: str = "") -> Any:
    lowered = key.lower().replace("-", "_")
    if any(token in lowered for token in ("password", "passwd", "secret", "token", "private_key", "privatekey", "api_key", "apikey", "credential", "certificate", "tls_cert", "encryption_key")):
        return {"redacted": True} if value is not None else None
    if isinstance(value, Mapping):
        return {str(k): _safe(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_safe(item) for item in value]
    return value


def _source(record: Mapping[str, Any]) -> str:
    value = record.get("source") or record.get("source_type") or record.get("origin") or record.get("provider")
    if isinstance(value, Mapping):
        value = value.get("source_id") or value.get("type") or value.get("name")
    return str(value or "unknown")


def _source_ref(record: Mapping[str, Any], index: int) -> Any:
    for key in ("source_ref", "source_reference", "source_id", "source", "origin"):
        if key in record and record[key] not in (None, ""):
            return deepcopy(record[key])
    return f"record:{index}"


def _source_rank(source: str) -> int:
    lowered = source.lower()
    if "live" in lowered or "runtime" in lowered or "cluster" in lowered:
        return 3
    if "manifest" in lowered or "static" in lowered or "file" in lowered:
        return 2
    return 1


def _static_rank(record: Mapping[str, Any]) -> int:
    text = " ".join(str(record.get(key, "")) for key in ("scope", "role", "component", "kind", "name", "workload_type")).lower()
    if any(token in text for token in ("control-plane", "control_plane", "controlplane", "kube-apiserver", "kube-scheduler", "kube-controller", "etcd")):
        return 2
    if any(token in text for token in ("workload", "deployment", "daemonset", "statefulset", "pod", "job")):
        return 0
    return 1


def _timestamp(record: Mapping[str, Any]) -> datetime:
    for key in ("observed_at", "timestamp", "collected_at", "updated_at", "created_at", "last_seen"):
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                return datetime.fromtimestamp(value, timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
        if isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
            except ValueError:
                continue
    return datetime.min.replace(tzinfo=timezone.utc)


def _resource_key(record: Mapping[str, Any]) -> str:
    for key in ("resource_key", "object_key", "uid", "id", "key"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    metadata = record.get("metadata")
    if isinstance(metadata, Mapping):
        if metadata.get("uid"):
            return str(metadata["uid"])
        name = metadata.get("name")
        if name:
            namespace = metadata.get("namespace", "")
            kind = record.get("kind", record.get("type", "resource"))
            return f"{kind}/{namespace}/{name}"
    kind = record.get("kind", record.get("type", "resource"))
    namespace = record.get("namespace", "")
    name = record.get("name", "")
    if name:
        return f"{kind}/{namespace}/{name}"
    # Deterministic fallback keeps unrelated anonymous records separate.
    return "hash:" + hashlib.sha256(_json(_safe(record)).encode()).hexdigest()[:16]


def _evidence_key(record: Mapping[str, Any]) -> str:
    for key in ("evidence_key", "observation_key", "fingerprint", "object_key"):
        if record.get(key) not in (None, ""):
            return str(record[key])
    base = _resource_key(record)
    field_path = record.get("field_path", record.get("check_id", record.get("rule_id", "")))
    return f"{base}|{field_path}"


@dataclass(frozen=True)
class DataConflict:
    conflict_id: str
    object_key: str
    field_path: str
    candidate_values: list[dict[str, Any]]
    selected_source: str | None = None
    resolution_reason: str = ""
    source_references: list[Any] = field(default_factory=list)

    @property
    def candidates(self) -> list[dict[str, Any]]:
        return self.candidate_values

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeduplicationResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[DataConflict] = field(default_factory=list)
    duplicate_count: int = 0

    @property
    def deduplicated_records(self) -> list[dict[str, Any]]:
        return self.records

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records, "conflicts": [item.to_dict() for item in self.conflicts], "duplicate_count": self.duplicate_count}

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.records[index]


def _winner(entries: list[tuple[int, Mapping[str, Any]]]) -> tuple[int, Mapping[str, Any], str]:
    ranked = []
    for index, record in entries:
        ranked.append((
            _source_rank(_source(record)),
            _static_rank(record),
            _timestamp(record),
            _source(record).lower(),
            index,
            record,
        ))
    # max rank; lexical source/index tie-breakers are deterministic.  Earlier
    # input wins the final exact tie to preserve stable source order.
    ranked.sort(key=lambda item: (item[0], item[1], item[2], item[3], -item[4]), reverse=True)
    selected = ranked[0]
    reason = f"source_rank={selected[0]}, scope_rank={selected[1]}, timestamp={selected[2].isoformat()}"
    return selected[4], selected[5], reason


def _deduplicate(rows: Iterable[Mapping[str, Any]] | Mapping[str, Any], *, evidence: bool) -> DeduplicationResult:
    source_rows = [rows] if isinstance(rows, Mapping) else [row for row in rows if isinstance(row, Mapping)]
    groups: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for index, row in enumerate(source_rows):
        key = _evidence_key(row) if evidence else _resource_key(row)
        groups.setdefault(key, []).append((index, row))
    result = DeduplicationResult()
    for key in sorted(groups):
        entries = groups[key]
        selected_index, selected_row, reason = _winner(entries)
        merged = deepcopy(dict(selected_row))
        references = []
        for index, row in sorted(entries, key=lambda pair: pair[0]):
            raw_ref = row.get("source_references")
            refs = raw_ref if isinstance(raw_ref, (list, tuple, set)) else [_source_ref(row, index)]
            for ref in refs:
                if ref not in references:
                    references.append(deepcopy(ref))
        merged["source_references"] = references
        result.records.append(merged)
        result.duplicate_count += max(0, len(entries) - 1)
        if len(entries) < 2:
            continue
        selected_source = _source(selected_row)
        for field_name in sorted(set().union(*(set(row) for _, row in entries))):
            if field_name in {"source_references", "source", "source_type", "origin", "source_id", "source_ref", "source_reference"}:
                continue
            values = []
            for index, row in entries:
                candidate = _safe(row.get(field_name), field_name)
                if all(candidate != item["value"] for item in values):
                    values.append({"source": _source(row), "source_reference": _source_ref(row, index), "value": candidate})
            if len(values) < 2:
                continue
            conflict_id = hashlib.sha256(f"{key}|{field_name}|{_json(values)}".encode()).hexdigest()[:20]
            same_rank = len({(_source_rank(_source(row)), _static_rank(row), _timestamp(row)) for _, row in entries if row.get(field_name) is not None}) == 1
            conflict_reason = "same precedence rank; selected deterministically" if same_rank else f"precedence selected {selected_source}"
            result.conflicts.append(DataConflict(conflict_id, key, field_name, values, selected_source, conflict_reason, references))
    return result


def deduplicate_resources(records: Iterable[Mapping[str, Any]] | Mapping[str, Any]) -> DeduplicationResult:
    return _deduplicate(records, evidence=False)


def deduplicate_evidence(records: Iterable[Mapping[str, Any]] | Mapping[str, Any]) -> DeduplicationResult:
    return _deduplicate(records, evidence=True)


# Short aliases used by adapters.
deduplicate_resource_records = deduplicate_resources
deduplicate_records = deduplicate_resources
dedupe_resources = deduplicate_resources
dedupe_evidence = deduplicate_evidence
deduplicate_evidence_records = deduplicate_evidence

__all__ = ["DataConflict", "DeduplicationResult", "deduplicate_resources", "deduplicate_evidence", "deduplicate_records", "dedupe_resources", "dedupe_evidence", "deduplicate_resource_records", "deduplicate_evidence_records"]

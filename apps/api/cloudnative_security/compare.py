"""Pure comparison helpers for baseline/current assessment task payloads."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Mapping


STATUS_RANK = {"PASS": 0, "NOT_APPLICABLE": 0, "UNKNOWN": 1, "WARN": 2, "FAIL": 3}


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    method = getattr(value, "to_dict", None)
    if callable(method):
        converted = method()
        return converted if isinstance(converted, Mapping) else {}
    return {}
def _json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _json(v) for k, v in value.items() if not _secret_key(str(k))}
    if isinstance(value, (list, tuple, set)):
        return [_json(v) for v in value]
    if is_dataclass(value):
        return _json(asdict(value))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _secret_key(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("token", "password", "secret", "private_key", "privatekey", "encryption_key"))


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _canonical(v)) for k, v in value.items()
                            if not _volatile(str(k)) and not _secret_key(str(k))))
    if isinstance(value, (list, tuple, set)):
        return tuple(_canonical(item) for item in value)
    return value


def _volatile(name: str) -> bool:
    return name.lower() in {"updated_at", "created_at", "generated_at", "observed_at", "timestamp"}


def _items(value: Any, *keys: str) -> list[Mapping[str, Any]]:
    payload = _mapping(value)
    for wanted in keys:
        candidate = payload.get(wanted)
        if isinstance(candidate, Mapping):
            return [dict(item, **({"id": key} if "id" not in item else {}))
                    for key, item in candidate.items() if isinstance(item, Mapping)]
        if isinstance(candidate, (list, tuple, set)):
            return [item for item in candidate if isinstance(item, Mapping)]
    nested = payload.get("report")
    if isinstance(nested, Mapping):
        return _items(nested, *keys)
    return []


def _asset_key(asset: Mapping[str, Any]) -> str:
    for key in ("checkpoint_id", "checkpoint", "key", "fingerprint", "id", "uid", "asset_id"):
        if asset.get(key) not in (None, ""):
            return str(asset[key])
    kind = asset.get("kind") or asset.get("type") or "asset"
    namespace = asset.get("namespace") or asset.get("ns") or "_cluster"
    name = asset.get("name") or asset.get("resource") or asset.get("hostname")
    if name is not None:
        return f"{kind}/{namespace}/{name}"
    return repr(_canonical(asset))


def _finding_key(finding: Mapping[str, Any]) -> str:
    for key in ("fingerprint", "id", "finding_id", "key"):
        if finding.get(key) not in (None, ""):
            return str(finding[key])
    asset = finding.get("asset")
    asset_map = _mapping(asset)
    rule = finding.get("rule_id") or finding.get("rule") or finding.get("title") or "finding"
    return f"{rule}:{_asset_key(asset_map)}"


def _status(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


def _quality(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("data_quality", "quality", "quality_summary"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
    summary = payload.get("summary")
    if isinstance(summary, Mapping):
        for key in ("data_quality", "quality"):
            value = summary.get(key)
            if isinstance(value, Mapping):
                return value
    report = payload.get("report")
    if isinstance(report, Mapping):
        return _quality(report)
    return {}


def _checkpoints(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("checkpoint_scores", "checkpoints"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return [dict(item, **({"checkpoint_id": key} if "checkpoint_id" not in item and "id" not in item else {})) for key, item in value.items() if isinstance(item, Mapping)]
        if isinstance(value, (list, tuple, set)):
            return [item for item in value if isinstance(item, Mapping)]
    report = payload.get("report")
    if isinstance(report, Mapping):
        return _checkpoints(report)
    return []


def _task_id(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("task_id", payload.get("id"))
    return None if value is None else str(value)


@dataclass(frozen=True)
class DataChange:
    key: str
    before: Any = None
    after: Any = None
    delta: float | None = None
    direction: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StatusChange:
    key: str
    before: str
    after: str
    item: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TaskComparison:
    baseline_task_id: str | None
    current_task_id: str | None
    added_assets: list[dict[str, Any]] = field(default_factory=list)
    removed_assets: list[dict[str, Any]] = field(default_factory=list)
    changed_assets: list[DataChange] = field(default_factory=list)
    added_findings: list[dict[str, Any]] = field(default_factory=list)
    disappeared_findings: list[dict[str, Any]] = field(default_factory=list)
    status_regressions: list[StatusChange] = field(default_factory=list)
    status_improvements: list[StatusChange] = field(default_factory=list)
    quality_changes: list[DataChange] = field(default_factory=list)
    checkpoint_score_changes: list[DataChange] = field(default_factory=list)

    @property
    def changed_findings(self) -> list[StatusChange]:
        return [*self.status_regressions, *self.status_improvements]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()


def compare_tasks(baseline: Any, current: Any) -> TaskComparison:
    """Compare two task/report payloads without mutating either payload."""
    before = _mapping(baseline)
    after = _mapping(current)

    old_assets = { _asset_key(item): item for item in _items(before, "assets", "asset_inventory", "resources") }
    new_assets = { _asset_key(item): item for item in _items(after, "assets", "asset_inventory", "resources") }
    added_assets = [_json(new_assets[key]) for key in sorted(new_assets.keys() - old_assets.keys())]
    removed_assets = [_json(old_assets[key]) for key in sorted(old_assets.keys() - new_assets.keys())]
    changed_assets = [DataChange(key, _json(old_assets[key]), _json(new_assets[key]))
                      for key in sorted(old_assets.keys() & new_assets.keys())
                      if _canonical(old_assets[key]) != _canonical(new_assets[key])]

    old_findings = {_finding_key(item): item for item in _items(before, "findings", "issues", "violations")}
    new_findings = {_finding_key(item): item for item in _items(after, "findings", "issues", "violations")}
    added_findings = [_json(new_findings[key]) for key in sorted(new_findings.keys() - old_findings.keys())]
    disappeared_findings = [_json(old_findings[key]) for key in sorted(old_findings.keys() - new_findings.keys())]
    regressions: list[StatusChange] = []
    improvements: list[StatusChange] = []
    for key in sorted(old_findings.keys() & new_findings.keys()):
        old_status, new_status = _status(old_findings[key].get("status")), _status(new_findings[key].get("status"))
        old_rank, new_rank = STATUS_RANK.get(old_status, 1), STATUS_RANK.get(new_status, 1)
        change = StatusChange(key, old_status, new_status, _json(new_findings[key]))
        if new_rank > old_rank:
            regressions.append(change)
        elif new_rank < old_rank:
            improvements.append(change)

    quality_changes: list[DataChange] = []
    old_quality, new_quality = _quality(before), _quality(after)
    for key in sorted(set(old_quality) | set(new_quality)):
        old_value, new_value = old_quality.get(key), new_quality.get(key)
        if old_value == new_value or old_value is None or new_value is None:
            continue
        delta = None
        direction = None
        if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)) and not isinstance(old_value, bool) and not isinstance(new_value, bool):
            delta = round(new_value - old_value, 4)
            direction = "improved" if delta > 0 else "declined" if delta < 0 else "unchanged"
        quality_changes.append(DataChange(str(key), _json(old_value), _json(new_value), delta, direction))

    checkpoint_changes: list[DataChange] = []
    old_checkpoints = {_asset_key(item): item for item in _checkpoints(before)}
    new_checkpoints = {_asset_key(item): item for item in _checkpoints(after)}
    for key in sorted(old_checkpoints.keys() & new_checkpoints.keys()):
        old_value = old_checkpoints[key].get("score")
        new_value = new_checkpoints[key].get("score")
        if old_value == new_value or old_value is None or new_value is None:
            continue
        delta = None
        if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
            delta = round(new_value - old_value, 4)
        checkpoint_changes.append(DataChange(key, _json(old_value), _json(new_value), delta,
                                              "improved" if delta is not None and delta > 0 else "declined" if delta is not None and delta < 0 else None))

    return TaskComparison(_task_id(before), _task_id(after), added_assets, removed_assets,
                          changed_assets, added_findings, disappeared_findings,
                          regressions, improvements, quality_changes, checkpoint_changes)


def compare_task_results(baseline: Any, current: Any) -> TaskComparison:
    return compare_tasks(baseline, current)


def compare_assessments(baseline: Any, current: Any) -> TaskComparison:
    return compare_tasks(baseline, current)


__all__ = ["DataChange", "StatusChange", "TaskComparison", "compare_tasks", "compare_task_results", "compare_assessments"]

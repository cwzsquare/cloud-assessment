"""Istio PeerAuthentication mTLS inheritance and coverage analysis."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping

_MODES = {"STRICT", "PERMISSIVE", "DISABLE", "UNKNOWN"}


def _metadata(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    return obj.get("metadata", {}) if isinstance(obj.get("metadata"), Mapping) else obj


def _namespace(obj: Mapping[str, Any]) -> str | None:
    meta = _metadata(obj)
    return str(meta.get("namespace")) if meta.get("namespace") not in (None, "") else None


def _name(obj: Mapping[str, Any]) -> str | None:
    meta = _metadata(obj)
    value = meta.get("name", obj.get("name"))
    return str(value) if value not in (None, "") else None


def _labels(obj: Mapping[str, Any]) -> dict[str, str]:
    meta = _metadata(obj)
    labels = meta.get("labels") or obj.get("labels") or {}
    if not isinstance(labels, Mapping):
        return {}
    return {str(k): str(v) for k, v in labels.items()}


def _spec(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    return obj.get("spec", {}) if isinstance(obj.get("spec"), Mapping) else {}


def _mode(value: Any) -> str:
    text = str(value or "UNKNOWN").upper()
    return text if text in _MODES else "UNKNOWN"


def _selector(policy: Mapping[str, Any]) -> dict[str, str]:
    selector = _spec(policy).get("selector", {})
    if not isinstance(selector, Mapping):
        return {}
    labels = selector.get("matchLabels", selector.get("match_labels", selector))
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, Mapping) else {}


def _matches(selector: Mapping[str, str], labels: Mapping[str, str]) -> bool:
    return all(labels.get(key) == value for key, value in selector.items())


def _mtls(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    body = _spec(policy).get("mtls", {})
    return body if isinstance(body, Mapping) else {}


def _ports(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    body = _mtls(policy).get("portLevelMtls", _mtls(policy).get("port_level_mtls", {}))
    return body if isinstance(body, Mapping) else {}


@dataclass(frozen=True)
class MtlsPolicyProfile:
    name: str | None
    namespace: str | None
    mode: str
    selector: dict[str, str] = field(default_factory=dict)
    port_modes: dict[str, str] = field(default_factory=dict)
    scope: str = "namespace"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WorkloadMtlsProfile:
    name: str | None
    namespace: str | None
    mode: str
    port_modes: dict[str, str] = field(default_factory=dict)
    source_policy: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def mode_for_port(self, port: int | str | None = None) -> str:
        if port is None:
            return self.mode
        return self.port_modes.get(str(port), self.mode)


@dataclass(frozen=True)
class MtlsCoverageResult:
    status: str
    policies: list[MtlsPolicyProfile] = field(default_factory=list)
    workloads: list[WorkloadMtlsProfile] = field(default_factory=list)
    covered_count: int = 0
    workload_count: int = 0
    unknown_reasons: list[str] = field(default_factory=list)

    @property
    def strict(self) -> bool:
        return self.status == "STRICT"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _profile(policy: Mapping[str, Any]) -> MtlsPolicyProfile:
    namespace = _namespace(policy)
    scope = "mesh" if namespace in (None, "istio-system") and not _selector(policy) else ("workload" if _selector(policy) else "namespace")
    ports = {str(k): _mode(v.get("mode") if isinstance(v, Mapping) else v) for k, v in _ports(policy).items()}
    return MtlsPolicyProfile(_name(policy), namespace, _mode(_mtls(policy).get("mode")), _selector(policy), ports, scope)


def _policy_match(policy: MtlsPolicyProfile, workload: Mapping[str, Any]) -> bool:
    namespace = _namespace(workload)
    if policy.namespace not in (None, namespace):
        return False
    return _matches(policy.selector, _labels(workload))


def _choose(policies: list[MtlsPolicyProfile], workload: Mapping[str, Any]) -> MtlsPolicyProfile | None:
    candidates = [policy for policy in policies if _policy_match(policy, workload)]
    if not candidates:
        return None
    # Workload selectors override namespace defaults; among selectors, the most
    # specific match wins.  Stable input ordering breaks ties.
    candidates.sort(key=lambda p: (1 if p.selector else 0, len(p.selector), 1 if p.namespace not in (None, "istio-system") else 0), reverse=True)
    return candidates[0]


def _workload_items(workloads: Iterable[Mapping[str, Any]] | None) -> list[Mapping[str, Any]]:
    return [x for x in (workloads or []) if isinstance(x, Mapping)]


def analyze_mtls_coverage(
    policies: Iterable[Mapping[str, Any] | MtlsPolicyProfile],
    workloads: Iterable[Mapping[str, Any]] | None = None,
) -> MtlsCoverageResult:
    profiles = [x if isinstance(x, MtlsPolicyProfile) else _profile(x) for x in policies]
    items = _workload_items(workloads)
    unknown: list[str] = []
    results: list[WorkloadMtlsProfile] = []
    for workload in items:
        selected = _choose(profiles, workload)
        if selected is None:
            results.append(WorkloadMtlsProfile(_name(workload), _namespace(workload), "UNKNOWN", reason="no matching PeerAuthentication policy"))
            unknown.append(f"{_name(workload) or '<unnamed>'}: no matching policy")
            continue
        results.append(WorkloadMtlsProfile(selected.name if _name(workload) is None else _name(workload), _namespace(workload), selected.mode, selected.port_modes, selected.name, "selector/namespace inheritance"))
    if items:
        modes = {item.mode for item in results}
        if "UNKNOWN" in modes:
            status = "UNKNOWN"
        elif "DISABLE" in modes:
            status = "DISABLE"
        elif "PERMISSIVE" in modes:
            status = "PERMISSIVE"
        else:
            status = "STRICT"
        covered = sum(item.mode == "STRICT" for item in results)
    elif profiles:
        modes = {item.mode for item in profiles}
        status = "UNKNOWN" if "UNKNOWN" in modes else ("DISABLE" if "DISABLE" in modes else ("PERMISSIVE" if "PERMISSIVE" in modes else "STRICT"))
        covered = sum(item.mode == "STRICT" for item in profiles)
    else:
        status = "UNKNOWN"
        covered = 0
        unknown.append("no PeerAuthentication policies supplied")
    return MtlsCoverageResult(status, profiles, results, covered, len(items), unknown)


assess_mtls_coverage = analyze_mtls_coverage
check_mtls_coverage = analyze_mtls_coverage


def effective_mtls_mode(
    policies: Iterable[Mapping[str, Any] | MtlsPolicyProfile],
    namespace: str | None,
    labels: Mapping[str, str] | None = None,
    port: int | str | None = None,
) -> str:
    workload: dict[str, Any] = {"metadata": {"namespace": namespace, "labels": dict(labels or {})}}
    result = analyze_mtls_coverage(policies, [workload])
    return result.workloads[0].mode_for_port(port) if result.workloads else "UNKNOWN"

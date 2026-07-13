from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from .checkpoints import CLOUD_NATIVE_CHECKPOINTS
from .collector import ResourceIndex
from .models import AssetRef, Evidence, Finding, FindingStatus, Severity
from .rbac_matrix import build_rbac_matrix


Rule = Callable[[ResourceIndex, str], list[Finding]]


def _meta(obj: dict[str, Any]) -> dict[str, Any]:
    return obj.get("metadata", {})


def _asset(obj: dict[str, Any]) -> AssetRef:
    meta = _meta(obj)
    return AssetRef(
        kind=obj.get("kind", "Unknown"),
        name=meta.get("name", "unknown"),
        namespace=meta.get("namespace"),
        api_version=obj.get("apiVersion"),
        labels=meta.get("labels", {}) or {},
    )


def _finding(task_id: str, checkpoint_id: str, rule_id: str, title: str, status: FindingStatus, severity: Severity, asset: AssetRef | None, evidence: Evidence, remediation: str, tool_id: str = "cloud_native") -> Finding:
    status_score = {"PASS": 1.0, "WARN": 0.5, "FAIL": 0.0, "UNKNOWN": 0.0, "NOT_APPLICABLE": 1.0}[status]
    fp_src = "|".join([checkpoint_id, rule_id, asset.key if asset else "_cluster", json.dumps(evidence.observed, sort_keys=True, ensure_ascii=False, default=str)])
    fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()[:24]
    return Finding(
        id=f"finding-{fingerprint}",
        task_id=task_id,
        tool_id=tool_id,
        checkpoint_id=checkpoint_id,
        rule_id=rule_id,
        title=title,
        status=status,
        severity=severity,
        score=status_score,
        asset=asset,
        evidence=[evidence],
        remediation=remediation,
        fingerprint=fingerprint,
    )


def _cluster_finding(task_id: str, checkpoint_id: str, rule_id: str, title: str, status: FindingStatus, severity: Severity, summary: str, observed: Any, expected: Any, remediation: str) -> Finding:
    return _finding(task_id, checkpoint_id, rule_id, title, status, severity, None, Evidence(summary=summary, observed=observed, expected=expected), remediation)


def _workloads(index: ResourceIndex) -> list[dict[str, Any]]:
    return index.by_kind("Deployment") + index.by_kind("StatefulSet") + index.by_kind("DaemonSet")


def _pod_spec(obj: dict[str, Any]) -> dict[str, Any]:
    kind = obj.get("kind")
    if kind == "Pod":
        return obj.get("spec", {})
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        return obj.get("spec", {}).get("template", {}).get("spec", {})
    if kind == "CronJob":
        return obj.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    return {}


def _containers(obj: dict[str, Any]) -> list[dict[str, Any]]:
    spec = _pod_spec(obj)
    return (spec.get("initContainers") or []) + (spec.get("containers") or [])


def _container_command_args(obj: dict[str, Any]) -> list[str]:
    args: list[str] = []
    for container in _containers(obj):
        args.extend(container.get("command") or [])
        args.extend(container.get("args") or [])
    return args


def _parse_cli_flags(args: list[str]) -> dict[str, Any]:
    flags: dict[str, Any] = {}
    index = 0
    while index < len(args):
        token = str(args[index])
        if not token.startswith("--"):
            index += 1
            continue
        if "=" in token:
            key, value = token[2:].split("=", 1)
            flags[key] = value
        else:
            key = token[2:]
            next_value = args[index + 1] if index + 1 < len(args) and not str(args[index + 1]).startswith("--") else "true"
            flags[key] = next_value
            if next_value != "true":
                index += 1
        index += 1
    return flags


def _control_plane_component(index: ResourceIndex, component: str) -> list[dict[str, Any]]:
    manifests = [
        obj for obj in index.by_kind("ControlPlaneManifest")
        if obj.get("component") == component or obj.get("metadata", {}).get("labels", {}).get("component") == component
    ]
    if manifests:
        return manifests
    return [
        pod for pod in index.by_kind("Pod")
        if _meta(pod).get("name", "").startswith(component)
        or (_meta(pod).get("labels", {}) or {}).get("component") == component
    ]


def _control_plane_args(index: ResourceIndex, component: str) -> tuple[list[str], list[dict[str, Any]], str]:
    sources = _control_plane_component(index, component)
    args: list[str] = []
    for source in sources:
        if source.get("kind") == "ControlPlaneManifest":
            args.extend(source.get("command") or [])
        else:
            args.extend(_container_command_args(source))
    source_type = "static-pod-manifest" if any(source.get("kind") == "ControlPlaneManifest" for source in sources) else "kubernetes-pod"
    return args, sources, source_type


def _control_plane_evidence_status(sources: list[dict[str, Any]], has_static_manifest: bool, checks_ok: bool) -> FindingStatus:
    if not sources:
        return "UNKNOWN"
    if checks_ok:
        return "PASS"
    return "FAIL" if has_static_manifest else "WARN"


def _all_urls_https(value: Any) -> bool:
    urls = [item.strip() for item in str(value or "").split(",") if item.strip()]
    return bool(urls) and all(url.startswith("https://") for url in urls)


def _encryption_provider_config_validation(index: ResourceIndex, config_path: str | None) -> dict[str, Any] | None:
    if not config_path:
        return None
    configs = [obj for obj in index.by_kind("EncryptionProviderConfig") if obj.get("path") == config_path]
    if not configs:
        return None
    config = configs[0]
    resource_rows = config.get("resources", []) or []
    secret_rows = [
        row
        for row in resource_rows
        if any(str(resource).lower() in {"secrets", "*"} for resource in row.get("resources", []) or [])
    ]
    provider_names: list[str] = []
    for row in secret_rows:
        for provider in row.get("provider_names", []) or []:
            text = str(provider)
            if text not in provider_names:
                provider_names.append(text)
    non_identity_providers = [provider for provider in provider_names if provider != "identity"]
    covers_secrets = bool(secret_rows)
    first_provider_identity = any((row.get("provider_names") or [None])[0] == "identity" for row in secret_rows)
    strong_encryption_present = bool(non_identity_providers) and not first_provider_identity
    if covers_secrets and strong_encryption_present:
        reason = "encryption provider config collected and covers secrets"
    elif not covers_secrets:
        reason = "encryption provider config collected but does not cover secrets"
    elif first_provider_identity:
        reason = "encryption provider config collected but identity is the first provider for secrets"
    else:
        reason = "encryption provider config collected but only identity provider was found"
    return {
        "config_path": config_path,
        "config_asset": _asset(config).key,
        "resource_rows": resource_rows,
        "covers_secrets": covers_secrets,
        "provider_names": provider_names,
        "non_identity_providers": non_identity_providers,
        "first_provider_identity": first_provider_identity,
        "strong_encryption_present": strong_encryption_present,
        "reason": reason,
    }


def _ns_name(obj: dict[str, Any]) -> str:
    return _meta(obj).get("namespace", "default")


def _workload_name(obj: dict[str, Any]) -> str:
    return _meta(obj).get("name", "unknown")


def _matching_hpas(index: ResourceIndex, workload: dict[str, Any]) -> list[dict[str, Any]]:
    name = _workload_name(workload)
    kind = workload.get("kind")
    ns = _ns_name(workload)
    matches: list[dict[str, Any]] = []
    for hpa in index.by_kind("HorizontalPodAutoscaler"):
        ref = hpa.get("spec", {}).get("scaleTargetRef", {})
        if _ns_name(hpa) == ns and ref.get("kind") == kind and ref.get("name") == name:
            matches.append(hpa)
    return matches


def _hpa_scale_target(index: ResourceIndex, hpa: dict[str, Any]) -> dict[str, Any] | None:
    ref = hpa.get("spec", {}).get("scaleTargetRef", {}) or {}
    target_kind = ref.get("kind")
    target_name = ref.get("name")
    hpa_ns = _ns_name(hpa)
    if not target_kind or not target_name:
        return None
    for workload in _workloads(index) + index.by_kind("ReplicaSet"):
        if workload.get("kind") == target_kind and _workload_name(workload) == target_name and _ns_name(workload) == hpa_ns:
            return workload
    return None


def _has_hpa(index: ResourceIndex, workload: dict[str, Any]) -> bool:
    return bool(_matching_hpas(index, workload))


def _matching_pdbs(index: ResourceIndex, workload: dict[str, Any]) -> list[dict[str, Any]]:
    ns = _ns_name(workload)
    labels = workload.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}) or {}
    matches: list[dict[str, Any]] = []
    for pdb in index.by_kind("PodDisruptionBudget"):
        if _ns_name(pdb) != ns:
            continue
        match = pdb.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
        if match and all(labels.get(k) == v for k, v in match.items()):
            matches.append(pdb)
    return matches


def _has_pdb(index: ResourceIndex, workload: dict[str, Any]) -> bool:
    return bool(_matching_pdbs(index, workload))


def _workload_services(index: ResourceIndex, workload: dict[str, Any]) -> list[dict[str, Any]]:
    ns = _ns_name(workload)
    labels = workload.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}) or {}
    services: list[dict[str, Any]] = []
    for service in index.by_kind("Service"):
        selector = service.get("spec", {}).get("selector", {}) or {}
        if _ns_name(service) == ns and selector and all(labels.get(key) == value for key, value in selector.items()):
            services.append(service)
    return services


def _service_host_aliases(service: dict[str, Any]) -> set[str]:
    name = _meta(service).get("name", "")
    ns = _ns_name(service)
    aliases = {name, f"{name}.{ns}", f"{name}.{ns}.svc", f"{name}.{ns}.svc.cluster.local"}
    return {alias for alias in aliases if alias}


def _destination_rule_outlier_detection(rule: dict[str, Any], aliases: set[str]) -> bool:
    spec = rule.get("spec", {}) or {}
    host = str(spec.get("host") or "")
    if host not in aliases and host != "*":
        return False
    if spec.get("trafficPolicy", {}).get("outlierDetection"):
        return True
    return any((subset.get("trafficPolicy") or {}).get("outlierDetection") for subset in spec.get("subsets", []) or [])


def _virtual_service_resilience(virtual_service: dict[str, Any], aliases: set[str]) -> tuple[bool, bool]:
    spec = virtual_service.get("spec", {}) or {}
    hosts = {str(host) for host in spec.get("hosts", []) or []}
    routes_to_service = False
    has_timeout = False
    has_retries = False
    host_matches = "*" in hosts or bool(hosts & aliases)
    for http in spec.get("http", []) or []:
        for route in http.get("route", []) or []:
            host = str((route.get("destination") or {}).get("host") or "")
            if host in aliases or host == "*":
                routes_to_service = True
        if host_matches or routes_to_service:
            has_timeout = has_timeout or bool(http.get("timeout"))
            has_retries = has_retries or bool(http.get("retries"))
    if not host_matches and not routes_to_service:
        return False, False
    return has_timeout, has_retries


def _mesh_resilience_evidence(index: ResourceIndex, workload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    services = _workload_services(index, workload)
    destination_rules = index.by_kind("DestinationRule")
    virtual_services = index.by_kind("VirtualService")
    rows = []
    has_timeout = False
    has_retries = False
    has_outlier_detection = False
    for service in services:
        aliases = _service_host_aliases(service)
        dr_matches = [
            _asset(rule).key
            for rule in destination_rules
            if _destination_rule_outlier_detection(rule, aliases)
        ]
        vs_rows = []
        for virtual_service in virtual_services:
            vs_timeout, vs_retries = _virtual_service_resilience(virtual_service, aliases)
            if vs_timeout or vs_retries:
                vs_rows.append({"asset": _asset(virtual_service).key, "timeout": vs_timeout, "retries": vs_retries})
            has_timeout = has_timeout or vs_timeout
            has_retries = has_retries or vs_retries
        has_outlier_detection = has_outlier_detection or bool(dr_matches)
        rows.append({"service": _asset(service).key, "hosts": sorted(aliases), "virtual_services": vs_rows, "destination_rules": dr_matches})
    ok = bool(services) and has_timeout and has_retries and has_outlier_detection
    return ok, {
        "services": rows,
        "service_found": bool(services),
        "has_timeout": has_timeout,
        "has_retries": has_retries,
        "has_outlier_detection": has_outlier_detection,
    }


def _istio_present(index: ResourceIndex) -> bool:
    istio_kinds = {
        "DestinationRule",
        "VirtualService",
        "PeerAuthentication",
        "AuthorizationPolicy",
        "RequestAuthentication",
        "Gateway",
        "Sidecar",
        "EnvoyFilter",
        "ServiceEntry",
    }
    if any(index.by_kind(kind) for kind in istio_kinds):
        return True
    return any(_ns_name(obj) == "istio-system" for obj in index.objects)


def _has_resources(workload: dict[str, Any]) -> bool:
    for container in _containers(workload):
        resources = container.get("resources", {})
        if not resources.get("requests") or not resources.get("limits"):
            return False
    return True


def _resilience_status(ok: bool, tier: str) -> tuple[FindingStatus, Severity]:
    if ok:
        return "PASS", "info"
    if tier in {"business", "demo-risk"}:
        return "FAIL", "medium"
    if tier == "platform":
        return "NOT_APPLICABLE", "info"
    return "WARN", "low"


def _hpa_quality(hpa: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    spec = hpa.get("spec", {}) or {}
    min_replicas = spec.get("minReplicas")
    max_replicas = spec.get("maxReplicas")
    metrics = spec.get("metrics") or []
    behavior = spec.get("behavior") or {}
    ok = (
        isinstance(min_replicas, int)
        and min_replicas >= 2
        and isinstance(max_replicas, int)
        and max_replicas >= min_replicas
        and bool(metrics)
    )
    return ok, {"minReplicas": min_replicas, "maxReplicas": max_replicas, "metric_count": len(metrics), "has_behavior": bool(behavior)}


def _condition_status(obj: dict[str, Any], condition_type: str) -> dict[str, Any] | None:
    for condition in obj.get("status", {}).get("conditions", []) or []:
        if condition.get("type") == condition_type:
            return condition
    return None


def _metrics_api_evidence(index: ResourceIndex) -> tuple[FindingStatus, Severity, dict[str, Any]]:
    api_services = [
        api_service for api_service in index.by_kind("APIService")
        if _meta(api_service).get("name") == "v1beta1.metrics.k8s.io"
        or api_service.get("spec", {}).get("group") == "metrics.k8s.io"
    ]
    metrics_deployments = [
        deployment for deployment in index.by_kind("Deployment")
        if _ns_name(deployment) == "kube-system"
        and (
            _meta(deployment).get("name") == "metrics-server"
            or (_labels(deployment).get("app.kubernetes.io/name") == "metrics-server")
        )
    ]
    metric_object_counts = {
        "PodMetrics": len(index.by_kind("PodMetrics")),
        "NodeMetrics": len(index.by_kind("NodeMetrics")),
    }
    api_service_rows = []
    api_available = False
    for api_service in api_services:
        condition = _condition_status(api_service, "Available") or {}
        available = condition.get("status") == "True"
        api_available = api_available or available
        api_service_rows.append(
            {
                "asset": _asset(api_service).key,
                "available": available,
                "reason": condition.get("reason"),
                "message": condition.get("message"),
                "service": api_service.get("spec", {}).get("service"),
            }
        )
    deployment_rows = []
    deployment_available = False
    for deployment in metrics_deployments:
        status = deployment.get("status", {}) or {}
        available = (status.get("availableReplicas") or 0) > 0 or (status.get("readyReplicas") or 0) > 0
        deployment_available = deployment_available or available
        deployment_rows.append(
            {
                "asset": _asset(deployment).key,
                "available": available,
                "replicas": status.get("replicas"),
                "readyReplicas": status.get("readyReplicas"),
                "availableReplicas": status.get("availableReplicas"),
            }
        )
    live_metric_object_count = sum(metric_object_counts.values())
    if api_available and (deployment_available or live_metric_object_count > 0):
        status: FindingStatus = "PASS"
        severity: Severity = "info"
    elif api_services or metrics_deployments:
        status = "WARN"
        severity = "medium"
    else:
        status = "UNKNOWN"
        severity = "medium"
    return status, severity, {
        "api_services": api_service_rows,
        "metrics_server_deployments": deployment_rows,
        "metric_object_counts": metric_object_counts,
        "live_metric_object_count": live_metric_object_count,
        "api_service_available": api_available,
        "metrics_server_deployment_available": deployment_available,
    }


def _hpa_runtime_evidence(hpa: dict[str, Any]) -> tuple[FindingStatus, Severity, dict[str, Any]]:
    status_obj = hpa.get("status", {}) or {}
    able_to_scale = _condition_status(hpa, "AbleToScale") or {}
    scaling_active = _condition_status(hpa, "ScalingActive") or {}
    scaling_limited = _condition_status(hpa, "ScalingLimited") or {}
    current_metrics = status_obj.get("currentMetrics") or []
    current_replicas = status_obj.get("currentReplicas")
    desired_replicas = status_obj.get("desiredReplicas")
    last_scale_time = status_obj.get("lastScaleTime")
    runtime_fields_present = any(
        value is not None and value != []
        for value in [current_metrics, current_replicas, desired_replicas, last_scale_time, status_obj.get("conditions")]
    )
    has_live_metrics = bool(current_metrics)
    scaling_active_ok = scaling_active.get("status") == "True"
    able_to_scale_ok = able_to_scale.get("status") in {"True", None}
    scale_delta_observed = isinstance(current_replicas, int) and isinstance(desired_replicas, int) and current_replicas != desired_replicas
    trigger_evidence = bool(last_scale_time or scale_delta_observed or scaling_limited.get("reason") in {"TooFewReplicas", "TooManyReplicas", "ScaleDownStabilized"})
    if not runtime_fields_present:
        finding_status: FindingStatus = "UNKNOWN"
        severity: Severity = "medium"
    elif has_live_metrics and scaling_active_ok and able_to_scale_ok:
        finding_status = "PASS"
        severity = "info"
    else:
        finding_status = "WARN"
        severity = "medium"
    return finding_status, severity, {
        "hpa": _asset(hpa).key,
        "runtime_fields_present": runtime_fields_present,
        "has_current_metrics": has_live_metrics,
        "currentMetrics": current_metrics,
        "currentReplicas": current_replicas,
        "desiredReplicas": desired_replicas,
        "lastScaleTime": last_scale_time,
        "ableToScale": able_to_scale,
        "scalingActive": scaling_active,
        "scalingLimited": scaling_limited,
        "scale_delta_observed": scale_delta_observed,
        "trigger_evidence": trigger_evidence,
    }


def _pdb_quality(pdb: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    spec = pdb.get("spec", {}) or {}
    selector = spec.get("selector", {}) or {}
    ok = bool(selector.get("matchLabels") or selector.get("matchExpressions")) and (
        spec.get("minAvailable") is not None or spec.get("maxUnavailable") is not None
    )
    return ok, {"selector": selector, "minAvailable": spec.get("minAvailable"), "maxUnavailable": spec.get("maxUnavailable")}


def _workload_resilience_summary(
    index: ResourceIndex,
    workload: dict[str, Any],
    tier: str,
    hpas: list[dict[str, Any]],
    pdbs: list[dict[str, Any]],
    istio_present: bool,
) -> tuple[FindingStatus, Severity, dict[str, Any], str]:
    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool | None, weight: int, evidence: Any) -> None:
        checks.append({"name": name, "ok": ok, "weight": weight, "evidence": evidence})

    add_check("hpa_present", bool(hpas), 20, [_asset(hpa).key for hpa in hpas])
    hpa_quality_rows = []
    hpa_quality_ok = None
    if hpas:
        for hpa in hpas:
            ok, observed = _hpa_quality(hpa)
            hpa_quality_rows.append({"asset": _asset(hpa).key, "ok": ok, **observed})
        hpa_quality_ok = all(row["ok"] for row in hpa_quality_rows)
    add_check("hpa_quality", hpa_quality_ok, 15, hpa_quality_rows)

    add_check("pdb_present", bool(pdbs), 20, [_asset(pdb).key for pdb in pdbs])
    pdb_quality_rows = []
    pdb_quality_ok = None
    if pdbs:
        for pdb in pdbs:
            ok, observed = _pdb_quality(pdb)
            pdb_quality_rows.append({"asset": _asset(pdb).key, "ok": ok, **observed})
        pdb_quality_ok = all(row["ok"] for row in pdb_quality_rows)
    add_check("pdb_quality", pdb_quality_ok, 15, pdb_quality_rows)

    add_check("resources_present", _has_resources(workload), 20, {"containers": [container.get("name") for container in _containers(workload)]})

    mesh_observed: dict[str, Any] = {"istio_present": istio_present}
    mesh_ok: bool | None = None
    if istio_present:
        mesh_ok, mesh_evidence = _mesh_resilience_evidence(index, workload)
        mesh_observed.update(mesh_evidence)
        if not mesh_evidence.get("service_found"):
            mesh_ok = None
    add_check("service_mesh_resilience", mesh_ok, 10, mesh_observed)

    applicable = [check for check in checks if check["ok"] is not None]
    denominator = sum(check["weight"] for check in applicable)
    earned = sum(check["weight"] for check in applicable if check["ok"] is True)
    score = round(earned / denominator * 100, 2) if denominator else 0.0
    missing = [check["name"] for check in applicable if check["ok"] is False]
    not_applicable = [check["name"] for check in checks if check["ok"] is None]
    if score >= 80:
        status: FindingStatus = "PASS"
        severity: Severity = "info"
    elif tier == "platform":
        status = "NOT_APPLICABLE"
        severity = "info"
    elif tier in {"business", "demo-risk"}:
        status = "FAIL"
        severity = "medium"
    else:
        status = "WARN"
        severity = "low"
    observed = {
        "tier": tier,
        "resilience_score": score,
        "earned_weight": earned,
        "applicable_weight": denominator,
        "missing_controls": missing,
        "not_applicable_controls": not_applicable,
        "checks": checks,
    }
    remediation = "补齐 workload 的 HPA、PDB、requests/limits"
    if "service_mesh_resilience" in missing:
        remediation += "，并为服务网格流量配置 timeout/retry/outlierDetection"
    if missing:
        remediation += f"；当前缺口：{', '.join(missing)}。"
    else:
        remediation = "保持 HPA/PDB/resources 与服务网格容错配置，并在扩容演练后复核指标。"
    return status, severity, observed, remediation


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    return _meta(obj).get("labels", {}) or {}


def _selector_matches(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    match_labels = selector.get("matchLabels", {}) or {}
    if match_labels and not all(labels.get(key) == value for key, value in match_labels.items()):
        return False
    for expr in selector.get("matchExpressions", []) or []:
        key = expr.get("key")
        operator = expr.get("operator")
        values = set(expr.get("values", []) or [])
        if operator == "In" and labels.get(key) not in values:
            return False
        if operator == "NotIn" and labels.get(key) in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def _service_selects_pod(service: dict[str, Any], pods: list[dict[str, Any]]) -> bool:
    selector = service.get("spec", {}).get("selector", {}) or {}
    if not selector:
        return False
    return any(_ns_name(pod) == _ns_name(service) and all(_labels(pod).get(key) == value for key, value in selector.items()) for pod in pods)


def _ingress_backend_services(ingress: dict[str, Any]) -> set[str]:
    services: set[str] = set()

    def add_backend(backend: dict[str, Any]) -> None:
        service = backend.get("service") or {}
        if service.get("name"):
            services.add(service["name"])

    spec = ingress.get("spec", {}) or {}
    if spec.get("defaultBackend"):
        add_backend(spec["defaultBackend"])
    for rule in spec.get("rules", []) or []:
        http = rule.get("http") or {}
        for path in http.get("paths", []) or []:
            add_backend(path.get("backend") or {})
    return services


def _claim_names_for_obj(obj: dict[str, Any]) -> set[str]:
    claims = {
        vol.get("persistentVolumeClaim", {}).get("claimName")
        for vol in _pod_spec(obj).get("volumes", []) or []
        if vol.get("persistentVolumeClaim", {}).get("claimName")
    }
    if obj.get("kind") == "StatefulSet":
        sts_name = _workload_name(obj)
        replicas = _intish(obj.get("spec", {}).get("replicas"))
        replica_count = replicas if isinstance(replicas, int) and replicas > 0 else 1
        for template in obj.get("spec", {}).get("volumeClaimTemplates", []) or []:
            template_name = _meta(template).get("name")
            if template_name:
                for ordinal in range(replica_count):
                    claims.add(f"{template_name}-{sts_name}-{ordinal}")
                claims.add(template_name)
    return claims


def _storageclass_encryption_evidence(index: ResourceIndex, pvc: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    sc_name = pvc.get("spec", {}).get("storageClassName")
    storage_class = next((sc for sc in index.by_kind("StorageClass") if _meta(sc).get("name") == sc_name), None)
    params = storage_class.get("parameters", {}) if storage_class else {}
    encrypted = any(
        token in key.lower() and str(value).lower() in {"true", "1", "yes", "encrypted"}
        for key, value in params.items()
        for token in ["encrypt", "kms"]
    )
    return encrypted, {"storageClassName": sc_name, "parameters": params, "storageClassFound": bool(storage_class)}


def _storageclass_encrypted(sc: dict[str, Any]) -> bool:
    params = sc.get("parameters", {}) or {}
    return any(
        token in key.lower() and str(value).lower() in {"true", "1", "yes", "encrypted"}
        for key, value in params.items()
        for token in ["encrypt", "kms"]
    )


def _backup_snapshot_evidence(index: ResourceIndex, namespace: str | None = None, pvc_name: str | None = None) -> list[str]:
    evidence: list[str] = []
    for obj in index.by_kind("VolumeSnapshot"):
        source = obj.get("spec", {}).get("source", {}) or {}
        same_namespace = namespace is None or _ns_name(obj) == namespace
        same_claim = pvc_name is None or source.get("persistentVolumeClaimName") == pvc_name
        if same_namespace and same_claim:
            evidence.append(_asset(obj).key)
    for obj in index.by_kind("Backup") + index.by_kind("Schedule"):
        if _velero_backup_covers(obj, namespace, pvc_name=pvc_name):
            evidence.append(_asset(obj).key)
    return sorted(evidence)


def _velero_backup_template(obj: dict[str, Any]) -> dict[str, Any]:
    spec = obj.get("spec", {}) or {}
    if obj.get("kind") == "Schedule":
        return spec.get("template", {}) or {}
    return spec


def _resource_name_matches(resource: str, candidates: set[str]) -> bool:
    normalized = resource.lower()
    if normalized in {"*", "all"}:
        return True
    return normalized in candidates or normalized.rstrip("s") in {candidate.rstrip("s") for candidate in candidates}


def _velero_backup_covers(
    obj: dict[str, Any],
    namespace: str | None = None,
    *,
    pvc_name: str | None = None,
    labels: dict[str, str] | None = None,
    resource_candidates: set[str] | None = None,
) -> bool:
    if namespace is not None:
        template = _velero_backup_template(obj)
        included_ns = {str(item) for item in template.get("includedNamespaces", []) or []}
        excluded_ns = {str(item) for item in template.get("excludedNamespaces", []) or []}
        same_namespace_object = _ns_name(obj) == namespace
        if namespace in excluded_ns or "*" in excluded_ns:
            return False
        if included_ns and namespace not in included_ns and "*" not in included_ns:
            return False
        if not included_ns and not same_namespace_object and _ns_name(obj) not in {"", "velero"}:
            return False
    else:
        template = _velero_backup_template(obj)
    included_resources = {str(item).lower() for item in template.get("includedResources", []) or []}
    excluded_resources = {str(item).lower() for item in template.get("excludedResources", []) or []}
    candidates = resource_candidates or {"persistentvolumeclaims", "persistentvolumes", "pods", "statefulsets"}
    if included_resources and not any(_resource_name_matches(item, candidates) for item in included_resources):
        return False
    if excluded_resources and any(_resource_name_matches(item, candidates) for item in excluded_resources):
        return False
    selector = template.get("labelSelector") or template.get("orLabelSelectors")
    if selector:
        if isinstance(selector, list):
            if not labels or not any(_selector_matches(item, labels) for item in selector):
                return False
        elif not labels or not _selector_matches(selector, labels):
            return False
    if pvc_name and not template:
        return False
    if pvc_name and selector and not labels:
        return False
    return True


def _velero_workload_backup_covers(obj: dict[str, Any], namespace: str, labels: dict[str, str], resource_candidates: set[str]) -> bool:
    template = _velero_backup_template(obj)
    selector = template.get("labelSelector") or template.get("orLabelSelectors")
    included_ns = {str(item) for item in template.get("includedNamespaces", []) or []}
    included_resources = {str(item).lower() for item in template.get("includedResources", []) or []}
    explicit_selector = bool(selector)
    explicit_namespace_resource_scope = namespace in included_ns and bool(included_resources) and any(_resource_name_matches(item, resource_candidates) for item in included_resources)
    if not explicit_selector and not explicit_namespace_resource_scope:
        return False
    return _velero_backup_covers(obj, namespace, labels=labels, resource_candidates=resource_candidates)


def _workload_backup_snapshot_evidence(index: ResourceIndex, namespace: str, claims: list[str], labels: dict[str, str]) -> list[str]:
    evidence: set[str] = set()
    resource_candidates = {"pods", "statefulsets", "persistentvolumeclaims", "persistentvolumes"}
    for claim in claims:
        evidence.update(_backup_snapshot_evidence(index, namespace, claim))
    for obj in index.by_kind("Backup") + index.by_kind("Schedule"):
        if _velero_workload_backup_covers(obj, namespace, labels, resource_candidates):
            evidence.add(_asset(obj).key)
    return sorted(evidence)


def _has_secret_reference(obj: dict[str, Any]) -> bool:
    spec = _pod_spec(obj)
    for container in _containers(obj):
        for env in container.get("env", []) or []:
            if env.get("valueFrom", {}).get("secretKeyRef"):
                return True
        for env_from in container.get("envFrom", []) or []:
            if env_from.get("secretRef"):
                return True
    for volume in spec.get("volumes", []) or []:
        if volume.get("secret") or volume.get("csi", {}).get("driver", "").lower() == "secrets-store.csi.k8s.io":
            return True
    return False


def _secret_ref_names(obj: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    spec = _pod_spec(obj)
    for container in _containers(obj):
        for env in container.get("env", []) or []:
            name = env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
            if name:
                names.add(name)
        for env_from in container.get("envFrom", []) or []:
            name = env_from.get("secretRef", {}).get("name")
            if name:
                names.add(name)
    for volume in spec.get("volumes", []) or []:
        name = volume.get("secret", {}).get("secretName")
        if name:
            names.add(name)
    return names


def _has_csi_secret_store(obj: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
    matches: list[dict[str, Any]] = []
    for volume in _pod_spec(obj).get("volumes", []) or []:
        csi = volume.get("csi") or {}
        driver = str(csi.get("driver", "")).lower()
        if driver == "secrets-store.csi.k8s.io":
            matches.append({"volume": volume.get("name"), "driver": csi.get("driver"), "volumeAttributes": sorted((csi.get("volumeAttributes") or {}).keys())})
    return bool(matches), matches


def _pod_network_exposure(obj: dict[str, Any]) -> dict[str, Any]:
    spec = _pod_spec(obj)
    host_ports: list[dict[str, Any]] = []
    for container in _containers(obj):
        for port in container.get("ports", []) or []:
            if port.get("hostPort") is not None:
                host_ports.append(
                    {
                        "container": container.get("name"),
                        "containerPort": port.get("containerPort"),
                        "hostPort": port.get("hostPort"),
                        "protocol": port.get("protocol", "TCP"),
                    }
                )
    return {
        "hostNetwork": spec.get("hostNetwork") is True,
        "hostPorts": host_ports,
    }


DATABASE_POD_TOKENS = {
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "mongodb",
    "mongo",
    "redis",
    "clickhouse",
    "cassandra",
    "elasticsearch",
    "opensearch",
    "cockroach",
    "tidb",
    "influxdb",
    "timescaledb",
    "database",
}

DATABASE_PORTS = {5432, 3306, 27017, 6379, 9200, 9042, 8123, 8086, 26257}


def _owner_reference_kind(obj: dict[str, Any], kind: str) -> bool:
    return any(owner.get("kind") == kind for owner in _meta(obj).get("ownerReferences") or [])


def _database_pod(pod: dict[str, Any]) -> bool:
    if pod.get("kind") != "Pod" or _namespace_tier_for_name_from_object(pod) == "platform":
        return False
    labels = _labels(pod)
    annotations = _meta(pod).get("annotations", {}) or {}
    chunks = [_workload_name(pod)]
    chunks.extend(str(key) for key in labels.keys())
    chunks.extend(str(value) for value in labels.values())
    chunks.extend(str(key) for key in annotations.keys())
    chunks.extend(str(value) for value in annotations.values())
    container_chunks: list[str] = []
    database_ports: set[int] = set()
    for container in _containers(pod):
        container_chunks.append(str(container.get("name") or ""))
        container_chunks.append(str(container.get("image") or ""))
        for port in container.get("ports", []) or []:
            port_number = _intish(port.get("containerPort"))
            if isinstance(port_number, int) and port_number in DATABASE_PORTS:
                database_ports.add(port_number)
    chunks.extend(container_chunks)
    normalized = " ".join(chunks).lower()
    container_text = " ".join(container_chunks).lower()
    segments = set(re.split(r"[^a-z0-9]+", normalized))
    strong_database_signal = any(token in normalized for token in DATABASE_POD_TOKENS)
    explicit_role = str(annotations.get("cnsec.io/data-role", "")).lower() in {"data", "database", "datastore", "stateful"}
    generic_db_signal = "db" in segments and (explicit_role or bool(database_ports) or any(token in container_text for token in DATABASE_POD_TOKENS))
    return strong_database_signal or generic_db_signal


def _database_controller_workload(obj: dict[str, Any]) -> bool:
    if obj.get("kind") not in {"Deployment", "Job", "CronJob"} or _namespace_tier_for_name_from_object(obj) == "platform":
        return False
    labels = _pod_template_labels(obj)
    annotations = _meta(obj).get("annotations", {}) or {}
    chunks = [_workload_name(obj)]
    chunks.extend(str(key) for key in labels.keys())
    chunks.extend(str(value) for value in labels.values())
    chunks.extend(str(key) for key in annotations.keys())
    chunks.extend(str(value) for value in annotations.values())
    container_chunks: list[str] = []
    database_ports: set[int] = set()
    for container in _containers(obj):
        container_chunks.append(str(container.get("name") or ""))
        container_chunks.append(str(container.get("image") or ""))
        for port in container.get("ports", []) or []:
            port_number = _intish(port.get("containerPort"))
            if isinstance(port_number, int) and port_number in DATABASE_PORTS:
                database_ports.add(port_number)
    chunks.extend(container_chunks)
    normalized = " ".join(chunks).lower()
    container_text = " ".join(container_chunks).lower()
    segments = set(re.split(r"[^a-z0-9]+", normalized))
    strong_database_signal = any(token in normalized for token in DATABASE_POD_TOKENS)
    explicit_role = str(annotations.get("cnsec.io/data-role", "")).lower() in {"data", "database", "datastore", "stateful"}
    generic_db_signal = "db" in segments and (explicit_role or bool(database_ports) or any(token in container_text for token in DATABASE_POD_TOKENS))
    return strong_database_signal or generic_db_signal


def _namespace_tier_for_name_from_object(obj: dict[str, Any]) -> str:
    # CN-37 focuses on business/data workloads; platform data stores are assessed by
    # control-plane and storage checks to avoid noisy duplicate findings.
    ns_name = _ns_name(obj)
    if ns_name in PLATFORM_NAMESPACES or ns_name.startswith("kube-"):
        return "platform"
    if ns_name == "default":
        return "default"
    return "business"


def _tls_secret_refs(index: ResourceIndex, obj: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    ns = _ns_name(obj)
    ref_names = _secret_ref_names(obj)
    secrets = [secret for secret in index.by_kind("Secret") if _ns_name(secret) == ns and _meta(secret).get("name") in ref_names]
    tls_secrets = [secret for secret in secrets if secret.get("type") == "kubernetes.io/tls" or any("tls" in key.lower() or "cert" in key.lower() for key in secret.get("data_keys", []) or [])]
    return bool(tls_secrets), {"referenced_secret_names": sorted(ref_names), "tls_secret_names": [_meta(secret).get("name") for secret in tls_secrets]}


def _mtls_strict_in_namespace(index: ResourceIndex, namespace: str) -> bool:
    for obj in index.by_kind("PeerAuthentication"):
        spec = obj.get("spec", {}) or {}
        obj_ns = _ns_name(obj)
        root_namespace_mesh_policy = obj_ns == "istio-system" and "selector" not in spec
        namespace_policy = obj_ns == namespace
        if (namespace_policy or root_namespace_mesh_policy) and spec.get("mtls", {}).get("mode") == "STRICT":
            return True
    return False


def _stateful_services(index: ResourceIndex, sts: dict[str, Any]) -> list[dict[str, Any]]:
    ns = _ns_name(sts)
    selector = sts.get("spec", {}).get("selector", {}) or {}
    match_labels = selector.get("matchLabels", {}) or {}
    service_name = sts.get("spec", {}).get("serviceName")
    services: list[dict[str, Any]] = []
    for service in index.by_kind("Service"):
        if _ns_name(service) != ns:
            continue
        service_selector = service.get("spec", {}).get("selector", {}) or {}
        if _meta(service).get("name") == service_name or (match_labels and service_selector and all(service_selector.get(k) == v for k, v in match_labels.items())):
            services.append(service)
    return services


def _workload_services(index: ResourceIndex, obj: dict[str, Any]) -> list[dict[str, Any]]:
    ns = _ns_name(obj)
    selector = (obj.get("spec", {}) or {}).get("selector", {}) or {}
    match_labels = selector.get("matchLabels", {}) or {}
    template_labels = _pod_template_labels(obj)
    services: list[dict[str, Any]] = []
    for service in index.by_kind("Service"):
        if _ns_name(service) != ns:
            continue
        service_selector = service.get("spec", {}).get("selector", {}) or {}
        if match_labels and service_selector and all(service_selector.get(k) == v for k, v in match_labels.items()):
            services.append(service)
        elif template_labels and service_selector and all(template_labels.get(k) == v for k, v in service_selector.items()):
            services.append(service)
    return services


def _pod_services(index: ResourceIndex, pod: dict[str, Any]) -> list[dict[str, Any]]:
    ns = _ns_name(pod)
    labels = _labels(pod)
    services: list[dict[str, Any]] = []
    for service in index.by_kind("Service"):
        if _ns_name(service) != ns:
            continue
        selector = service.get("spec", {}).get("selector", {}) or {}
        if selector and all(labels.get(key) == value for key, value in selector.items()):
            services.append(service)
    return services


def _pod_template_labels(obj: dict[str, Any]) -> dict[str, str]:
    if obj.get("kind") == "Pod":
        return _labels(obj)
    template_labels = obj.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}) or {}
    return {str(key): str(value) for key, value in template_labels.items()}


def _networkpolicy_controls_ingress(policy: dict[str, Any]) -> bool:
    spec = policy.get("spec", {}) or {}
    policy_types = spec.get("policyTypes")
    if policy_types is None:
        return True
    return "Ingress" in policy_types


def _networkpolicy_restricts_ingress(policy: dict[str, Any]) -> bool:
    spec = policy.get("spec", {}) or {}
    if not _networkpolicy_controls_ingress(policy):
        return False
    if "ingress" not in spec or not spec.get("ingress"):
        return True
    for rule in spec.get("ingress", []) or []:
        if not rule.get("from") and not rule.get("ports"):
            return False
    return True


def _stateful_networkpolicy_evidence(network_policies: list[dict[str, Any]], sts: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    ns = _ns_name(sts)
    labels = _pod_template_labels(sts)
    policies = []
    for policy in network_policies:
        if _ns_name(policy) != ns:
            continue
        spec = policy.get("spec", {}) or {}
        selector = spec.get("podSelector", {}) or {}
        matches = _selector_matches(selector, labels)
        controls_ingress = _networkpolicy_controls_ingress(policy)
        restricts_ingress = _networkpolicy_restricts_ingress(policy)
        ingress_rules = spec.get("ingress")
        policies.append(
            {
                "name": _meta(policy).get("name"),
                "podSelector": selector,
                "matches_statefulset": matches,
                "matches_subject": matches,
                "controls_ingress": controls_ingress,
                "restricts_ingress": restricts_ingress,
                "default_deny": matches and controls_ingress and selector == {} and not ingress_rules,
            }
        )
    covered = any(policy["matches_subject"] and policy["controls_ingress"] and policy["restricts_ingress"] for policy in policies)
    return covered, {
        "namespace": ns,
        "template_labels": labels,
        "policies": policies,
        "reason": "matching restricted ingress NetworkPolicy found" if covered else "no restricted ingress NetworkPolicy selects this workload",
    }


def _pvc_consumer_subjects(index: ResourceIndex, namespace: str, pvc_name: str) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for obj in index.by_kind("StatefulSet") + index.by_kind("Pod"):
        if _ns_name(obj) != namespace:
            continue
        if pvc_name not in _claim_names_for_obj(obj):
            continue
        if obj.get("kind") == "Pod" and _owner_reference_kind(obj, "StatefulSet"):
            continue
        labels = _pod_template_labels(obj)
        subjects.append({"asset": _asset(obj).key, "kind": obj.get("kind"), "labels": labels})
    return subjects


def _pvc_namespace_isolation_evidence(index: ResourceIndex, network_policies: list[dict[str, Any]], pvc: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    ns = _ns_name(pvc)
    subjects = _pvc_consumer_subjects(index, ns, _meta(pvc).get("name", ""))
    policies: list[dict[str, Any]] = []
    for policy in network_policies:
        if _ns_name(policy) != ns:
            continue
        spec = policy.get("spec", {}) or {}
        selector = spec.get("podSelector", {}) or {}
        controls_ingress = _networkpolicy_controls_ingress(policy)
        restricts_ingress = _networkpolicy_restricts_ingress(policy)
        matched_subjects = [subject["asset"] for subject in subjects if _selector_matches(selector, subject.get("labels") or {})]
        namespace_default_deny = selector == {} and controls_ingress and not spec.get("ingress")
        policies.append(
            {
                "name": _meta(policy).get("name"),
                "podSelector": selector,
                "controls_ingress": controls_ingress,
                "restricts_ingress": restricts_ingress,
                "namespace_default_deny": namespace_default_deny,
                "matched_subjects": matched_subjects,
            }
        )
    if subjects:
        isolated = all(
            any(subject["asset"] in policy["matched_subjects"] and policy["controls_ingress"] and policy["restricts_ingress"] for policy in policies)
            for subject in subjects
        )
    else:
        isolated = any(policy["namespace_default_deny"] for policy in policies)
    return isolated, {
        "namespace": ns,
        "subjects": subjects,
        "policies": policies,
        "reason": "restricted NetworkPolicy covers PVC consumers" if isolated and subjects else "namespace default deny covers unconsumed PVC" if isolated else "no restricted NetworkPolicy covers PVC consumers",
    }


def _data_control_missing_status(tier: str) -> FindingStatus:
    return "FAIL" if tier in {"business", "demo-risk"} else "WARN"


PLATFORM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "kyverno", "trivy-system", "falco", "calico-system", "tigera-operator"}


def _namespace_tier(namespace: dict[str, Any]) -> str:
    name = _meta(namespace).get("name", "")
    labels = _labels(namespace)
    if name in PLATFORM_NAMESPACES or name.startswith("kube-"):
        return "platform"
    if labels.get("purpose") == "cnsec-demo":
        return "demo-risk"
    if name in {"default", ""}:
        return "default"
    return "business"


def _psa_mode(labels: dict[str, str]) -> str | None:
    return labels.get("pod-security.kubernetes.io/enforce") or labels.get("pod-security.kubernetes.io/audit") or labels.get("pod-security.kubernetes.io/warn")


def _has_psa(labels: dict[str, str]) -> bool:
    return any(key.startswith("pod-security.kubernetes.io/") for key in labels)


def _policy_summary(index: ResourceIndex) -> dict[str, Any]:
    policies = index.by_kind("ClusterPolicy") + index.by_kind("Policy") + index.by_kind("ValidatingAdmissionPolicy") + index.by_kind("ConstraintTemplate")
    security_policy_names: list[str] = []
    security_policy_details: list[dict[str, Any]] = []
    control_coverage: dict[str, list[str]] = {control: [] for control in POD_SECURITY_POLICY_CONTROLS}
    for policy in policies:
        controls, matched_paths = _policy_security_controls(policy)
        if controls:
            asset_key = _asset(policy).key
            security_policy_names.append(asset_key)
            for control in controls:
                control_coverage[control].append(asset_key)
            reasons = _policy_security_reasons(policy, controls)
            security_policy_details.append(
                {
                    "asset": asset_key,
                    "kind": policy.get("kind"),
                    "controls": sorted(controls),
                    "reasons": reasons,
                    "matched_paths": matched_paths[:20],
                }
            )
    covered_controls = sorted([control for control, assets in control_coverage.items() if assets])
    missing_controls = sorted([control for control, assets in control_coverage.items() if not assets])
    missing_required_controls = sorted([control for control in POD_SECURITY_REQUIRED_CONTROLS if not control_coverage[control]])
    missing_recommended_controls = sorted([control for control in POD_SECURITY_RECOMMENDED_CONTROLS if not control_coverage[control]])
    return {
        "policy_kinds": sorted({policy.get("kind", "Unknown") for policy in policies}),
        "policy_count": len(policies),
        "security_policy_count": len(security_policy_names),
        "security_policy_sample": security_policy_names[:10],
        "security_policy_details": security_policy_details[:10],
        "required_controls": POD_SECURITY_REQUIRED_CONTROLS,
        "recommended_controls": POD_SECURITY_RECOMMENDED_CONTROLS,
        "covered_controls": covered_controls,
        "missing_controls": missing_controls,
        "missing_required_controls": missing_required_controls,
        "missing_recommended_controls": missing_recommended_controls,
        "control_coverage": {control: assets[:10] for control, assets in control_coverage.items()},
        "core_control_coverage": len([control for control in POD_SECURITY_REQUIRED_CONTROLS if control_coverage[control]]),
    }


POD_SECURITY_REQUIRED_CONTROLS = [
    "run_as_non_root",
    "disallow_privilege_escalation",
    "disallow_privileged",
    "drop_capabilities",
    "seccomp_profile",
]

POD_SECURITY_RECOMMENDED_CONTROLS = [
    "disallow_host_namespaces",
    "read_only_root_filesystem",
]

POD_SECURITY_POLICY_CONTROLS = [*POD_SECURITY_REQUIRED_CONTROLS, *POD_SECURITY_RECOMMENDED_CONTROLS]


def _policy_security_controls(policy: dict[str, Any]) -> tuple[set[str], list[str]]:
    controls: set[str] = set()
    matched_paths: list[str] = []
    name = _meta(policy).get("name", "").lower()
    name_hints = {
        "run_as_non_root": ("run-as-non-root", "runasnonroot", "non-root"),
        "disallow_privilege_escalation": ("privilege-escalation", "allowprivilegeescalation"),
        "disallow_privileged": ("disallow-privileged", "privileged-containers"),
        "drop_capabilities": ("disallow-capabilities", "drop-capabilities", "capabilities"),
        "seccomp_profile": ("seccomp",),
        "disallow_host_namespaces": ("host-namespace", "host-namespaces", "hostnetwork", "hostpid", "hostipc", "host-process", "hostprocess"),
        "read_only_root_filesystem": ("read-only-root", "readonlyrootfilesystem", "ro-rootfs"),
    }
    for control, hints in name_hints.items():
        if any(hint in name for hint in hints):
            controls.add(control)
            matched_paths.append("metadata.name")

    for path, key, value in _walk_policy_fields(policy.get("spec", {}) or {}):
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        value_text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).lower()
        path_lower = path.lower()

        def add(control: str) -> None:
            controls.add(control)
            matched_paths.append(path)

        if normalized_key == "podsecurity" and "restricted" in value_text:
            for control in POD_SECURITY_REQUIRED_CONTROLS:
                add(control)
            add("disallow_host_namespaces")
        elif normalized_key == "podsecurity" and "baseline" in value_text:
            add("disallow_privileged")
            add("disallow_host_namespaces")
        if normalized_key == "runasnonroot" and _policy_truthy(value):
            add("run_as_non_root")
        if normalized_key == "allowprivilegeescalation" and _policy_falsey(value):
            add("disallow_privilege_escalation")
        if normalized_key == "privileged" and _policy_falsey(value):
            add("disallow_privileged")
        if normalized_key == "drop" and ("all" in value_text or "*" in value_text):
            add("drop_capabilities")
        if normalized_key == "capabilities" and "drop" in value_text and ("all" in value_text or "*" in value_text):
            add("drop_capabilities")
        if (normalized_key == "seccompprofile" or "seccompprofile" in path_lower or "seccomp" in value_text) and any(token in value_text for token in ("runtimedefault", "localhost", "unconfined")):
            add("seccomp_profile")
        if normalized_key in {"hostnetwork", "hostpid", "hostipc", "hostprocess"} and _policy_falsey(value):
            add("disallow_host_namespaces")
        if normalized_key == "readonlyrootfilesystem" and _policy_truthy(value):
            add("read_only_root_filesystem")
        if isinstance(value, str):
            compact = re.sub(r"[^a-z0-9=!*]", "", value.lower())
            if "runasnonroot" in compact and any(token in compact for token in ("==true", "true", "!=false")):
                add("run_as_non_root")
            if "allowprivilegeescalation" in compact and any(token in compact for token in ("==false", "false", "!=true")):
                add("disallow_privilege_escalation")
            if "privileged" in compact and any(token in compact for token in ("==false", "false", "!=true")):
                add("disallow_privileged")
            if "capabilities" in compact and "drop" in compact and ("all" in compact or "*" in compact):
                add("drop_capabilities")
            if "seccompprofile" in compact and any(token in compact for token in ("runtimedefault", "localhost", "unconfined")):
                add("seccomp_profile")
            if any(token in compact for token in ("hostnetwork", "hostpid", "hostipc", "hostprocess")) and any(token in compact for token in ("==false", "false", "!=true")):
                add("disallow_host_namespaces")
            if "readonlyrootfilesystem" in compact and any(token in compact for token in ("==true", "true", "!=false")):
                add("read_only_root_filesystem")

    return controls, sorted(set(matched_paths))


def _policy_security_reasons(policy: dict[str, Any], controls: set[str]) -> dict[str, str]:
    text = json.dumps(policy.get("spec", {}) or {}, ensure_ascii=False, sort_keys=True, default=str).lower()
    reasons: dict[str, str] = {}
    for control in sorted(controls):
        if "podsecurity" in text and "restricted" in text and control in POD_SECURITY_REQUIRED_CONTROLS:
            reasons[control] = "Kyverno podSecurity restricted"
        elif control == "disallow_host_namespaces" and "podsecurity" in text and "restricted" in text:
            reasons[control] = "Kyverno podSecurity restricted"
        else:
            reasons[control] = "matched policy field or CEL/pattern expression"
    return reasons


def _policy_truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.lower() in {"true", "yes", "1"}
    return False


def _policy_falsey(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.lower() in {"false", "no", "0"}
    return False


def _context_policy_summary(index: ResourceIndex) -> dict[str, Any]:
    policies = index.by_kind("ClusterPolicy") + index.by_kind("Policy") + index.by_kind("ValidatingAdmissionPolicy")
    vap_bindings: dict[str, list[str]] = defaultdict(list)
    for binding in index.by_kind("ValidatingAdmissionPolicyBinding"):
        policy_name = str((binding.get("spec", {}) or {}).get("policyName") or "")
        if policy_name:
            vap_bindings[policy_name].append(_asset(binding).key)
    matches: list[dict[str, Any]] = []
    unbound_validating_policies: list[dict[str, Any]] = []
    signal_counts: dict[str, int] = defaultdict(int)
    for policy in policies:
        signals, matched_paths = _context_policy_signals(policy.get("spec", {}) or {})
        if signals:
            normalized_signals = sorted(signals)
            if policy.get("kind") == "ValidatingAdmissionPolicy":
                binding_assets = sorted(vap_bindings.get(_meta(policy).get("name", ""), []))
                if not binding_assets:
                    unbound_validating_policies.append(
                        {
                            "asset": _asset(policy).key,
                            "kind": policy.get("kind"),
                            "signals": normalized_signals,
                            "matched_paths": matched_paths[:20],
                        }
                    )
                    continue
            else:
                binding_assets = []
            matches.append({"asset": _asset(policy).key, "kind": policy.get("kind"), "signals": normalized_signals, "matched_paths": matched_paths[:20], "binding_assets": binding_assets})
            for signal in normalized_signals:
                signal_counts[signal] += 1
    required_contexts = ["env", "label", "namespace", "subject"]
    covered_contexts = sorted(signal_counts)
    return {
        "policy_kinds": sorted({policy.get("kind", "Unknown") for policy in policies}),
        "policy_count": len(policies),
        "validating_policy_binding_count": len(index.by_kind("ValidatingAdmissionPolicyBinding")),
        "context_policy_count": len(matches),
        "context_policy_sample": matches[:10],
        "unbound_validating_policies": unbound_validating_policies[:10],
        "required_contexts": required_contexts,
        "covered_contexts": covered_contexts,
        "missing_required_contexts": [signal for signal in required_contexts if signal not in signal_counts],
        "signal_coverage": {signal: signal_counts.get(signal, 0) for signal in required_contexts},
    }


def _permission_query_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    rows = matrix.get("rows", []) or []
    by_subject: dict[str, dict[str, Any]] = {}
    by_resource: dict[str, dict[str, Any]] = {}
    for row in rows:
        subject = str(row.get("subject") or "unknown")
        subject_entry = by_subject.setdefault(
            subject,
            {
                "subject": subject,
                "row_count": 0,
                "roles": set(),
                "bindings": set(),
                "resources": set(),
                "verbs": set(),
                "dangerous_rows": 0,
            },
        )
        subject_entry["row_count"] += 1
        subject_entry["roles"].add(f"{row.get('role_kind')}/{row.get('role_name')}")
        subject_entry["bindings"].add(f"{row.get('binding_kind')}/{row.get('binding_namespace') or '_cluster'}/{row.get('binding_name')}")
        subject_entry["resources"].update(row.get("resources") or [])
        subject_entry["verbs"].update(row.get("verbs") or [])
        if row.get("dangerous"):
            subject_entry["dangerous_rows"] += 1
        for resource in row.get("resources") or []:
            normalized = str(resource)
            resource_entry = by_resource.setdefault(
                normalized,
                {
                    "resource": normalized,
                    "row_count": 0,
                    "subjects": set(),
                    "verbs": set(),
                    "dangerous_rows": 0,
                },
            )
            resource_entry["row_count"] += 1
            resource_entry["subjects"].add(subject)
            resource_entry["verbs"].update(row.get("verbs") or [])
            if row.get("dangerous"):
                resource_entry["dangerous_rows"] += 1
    return {
        "queryable": bool(rows),
        "row_count": len(rows),
        "subject_count": len(by_subject),
        "resource_count": len(by_resource),
        "query_dimensions": ["subject", "resource", "verb", "binding", "role", "scope"],
        "subject_index_sample": [
            {
                **entry,
                "roles": sorted(entry["roles"])[:20],
                "bindings": sorted(entry["bindings"])[:20],
                "resources": sorted(entry["resources"])[:20],
                "verbs": sorted(entry["verbs"])[:20],
            }
            for entry in sorted(by_subject.values(), key=lambda item: (-item["dangerous_rows"], -item["row_count"], item["subject"]))[:10]
        ],
        "resource_index_sample": [
            {
                **entry,
                "subjects": sorted(entry["subjects"])[:20],
                "verbs": sorted(entry["verbs"])[:20],
            }
            for entry in sorted(by_resource.values(), key=lambda item: (-item["dangerous_rows"], -item["row_count"], item["resource"]))[:10]
        ],
    }


def _walk_policy_fields(value: Any, path: str = "spec") -> list[tuple[str, str, Any]]:
    fields: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            fields.append((child_path, str(key), item))
            fields.extend(_walk_policy_fields(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            fields.extend(_walk_policy_fields(item, f"{path}[{index}]"))
    return fields


def _context_policy_signals(spec: dict[str, Any]) -> tuple[set[str], list[str]]:
    signals: set[str] = set()
    matched_paths: list[str] = []
    env_keys = {"env", "environment", "stage", "tenant"}
    for path, key, value in _walk_policy_fields(spec):
        path_lower = path.lower()
        key_lower = key.lower()
        value_text = str(value).lower() if isinstance(value, str) else ""
        if key_lower in {"namespaceselector", "namespaces"} or "request.namespace" in value_text:
            signals.add("namespace")
            matched_paths.append(path)
        if key_lower in {"matchlabels", "matchexpressions", "labelselector", "objectselector", "namespaceselector", "labels"} or path_lower.endswith("metadata.labels") or "metadata.labels." in path_lower or "metadata.labels" in value_text:
            signals.add("label")
            matched_paths.append(path)
        if key_lower in env_keys or (".labels." in path_lower and any(token in key_lower for token in env_keys)) or ("metadata.labels" in value_text and any(token in value_text for token in env_keys)):
            signals.add("env")
            matched_paths.append(path)
        if key_lower in {"userinfo", "username", "groups", "subjects", "subject", "serviceaccountname"} or "request.userinfo" in value_text:
            signals.add("subject")
            matched_paths.append(path)
    return signals, sorted(set(matched_paths))


def _workload_namespaces(index: ResourceIndex) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for workload in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        counts[_ns_name(workload)] += 1
    return counts


def _namespace_tier_for_name(index: ResourceIndex, namespace: str | None) -> str:
    ns_name = namespace or "default"
    namespace_obj = next((ns for ns in index.by_kind("Namespace") if _meta(ns).get("name") == ns_name), None)
    if namespace_obj:
        return _namespace_tier(namespace_obj)
    if ns_name in PLATFORM_NAMESPACES or ns_name.startswith("kube-"):
        return "platform"
    if ns_name == "default":
        return "default"
    return "business"


def _service_account_automount(index: ResourceIndex, namespace: str | None, name: str | None) -> bool | None:
    sa_name = name or "default"
    ns = namespace or "default"
    for service_account in index.by_kind("ServiceAccount"):
        if _ns_name(service_account) == ns and _meta(service_account).get("name") == sa_name:
            return service_account.get("automountServiceAccountToken")
    return None


def _auth_subjects(index: ResourceIndex) -> list[dict[str, Any]]:
    subjects = list(_workloads(index) + index.by_kind("Job") + index.by_kind("CronJob"))
    for pod in index.by_kind("Pod"):
        owner_refs = _meta(pod).get("ownerReferences") or []
        if not owner_refs or _static_control_plane_pod(pod):
            subjects.append(pod)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for subject in subjects:
        key = _asset(subject).key
        if key in seen:
            continue
        seen.add(key)
        deduped.append(subject)
    return deduped


def _static_control_plane_pod(pod: dict[str, Any]) -> bool:
    return _ns_name(pod) == "kube-system" and any(_workload_name(pod).startswith(prefix) for prefix in ("kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"))


def _pod_posture_subjects(index: ResourceIndex) -> list[dict[str, Any]]:
    subjects = list(_workloads(index))
    for pod in index.by_kind("Pod"):
        owner_refs = _meta(pod).get("ownerReferences") or []
        if not owner_refs or _static_control_plane_pod(pod):
            subjects.append(pod)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for subject in subjects:
        key = _asset(subject).key
        if key in seen:
            continue
        seen.add(key)
        deduped.append(subject)
    return deduped


def _sa_token_status(index: ResourceIndex, obj: dict[str, Any]) -> tuple[FindingStatus, Severity, dict[str, Any]]:
    spec = _pod_spec(obj)
    pod_automount = spec.get("automountServiceAccountToken")
    service_account_name = spec.get("serviceAccountName") or "default"
    service_account_automount = _service_account_automount(index, _ns_name(obj), service_account_name)
    effective = pod_automount if pod_automount is not None else service_account_automount
    tier = _namespace_tier_for_name(index, _ns_name(obj))
    if effective is False:
        status: FindingStatus = "PASS"
        severity: Severity = "info"
        reason = "explicitly disabled"
    elif tier == "platform":
        status = "NOT_APPLICABLE"
        severity = "info"
        reason = "platform workload reviewed separately for API access requirement"
    else:
        status = "WARN"
        severity = "medium"
        reason = "business workload should opt out unless Kubernetes API access is required"
    return status, severity, {
        "tier": tier,
        "pod_automount": pod_automount,
        "serviceAccountName": service_account_name,
        "serviceAccountAutomount": service_account_automount,
        "effective_automount": effective,
        "reason": reason,
    }


def _immutable_principle_status(ok: bool, tier: str) -> tuple[FindingStatus, Severity]:
    if ok:
        return "PASS", "info"
    if tier == "platform":
        return "NOT_APPLICABLE", "info"
    if tier in {"business", "demo-risk"}:
        return "WARN", "medium"
    return "WARN", "low"


def _immutability_status(ok: bool, tier: str) -> tuple[FindingStatus, Severity]:
    if ok:
        return "PASS", "info"
    if tier in {"business", "demo-risk"}:
        return "FAIL", "high"
    if tier == "platform":
        return "NOT_APPLICABLE", "info"
    return "WARN", "low"


def _container_ssh_evidence(container: dict[str, Any]) -> dict[str, Any]:
    ports = container.get("ports") or []
    command_args = [str(item) for item in (container.get("command") or []) + (container.get("args") or [])]
    command_text = " ".join(command_args).lower()
    exposed_ports = [
        {
            "name": port.get("name"),
            "containerPort": port.get("containerPort"),
            "protocol": port.get("protocol"),
        }
        for port in ports
        if port.get("containerPort") == 22 or str(port.get("name", "")).lower() == "ssh"
    ]
    sshd_markers = [item for item in command_args if "sshd" in item.lower() or "openssh-server" in item.lower()]
    return {
        "container": container.get("name"),
        "exposed_ssh_ports": exposed_ports,
        "command": command_args,
        "sshd_markers": sshd_markers,
        "runs_sshd": bool(sshd_markers) or "sshd" in command_text or "openssh-server" in command_text,
        "exposes_ssh_port": bool(exposed_ports),
    }


def _exec_rbac_risk_rows(index: ResourceIndex) -> list[dict[str, Any]]:
    matrix = build_rbac_matrix(index)
    risks: list[dict[str, Any]] = []
    for row in matrix.get("business_dangerous_rows", []):
        resources = set(row.get("resources") or [])
        verbs = set(row.get("verbs") or [])
        reasons = set(row.get("danger_reasons") or [])
        exec_resource = "pods/exec" in resources or "*" in resources or "pods exec" in reasons
        can_create_exec = bool(verbs & {"create", "update", "patch", "*"})
        if exec_resource and can_create_exec:
            risks.append(
                {
                    "subject": row.get("subject"),
                    "binding": f"{row.get('binding_kind')}/{row.get('binding_namespace') or '_cluster'}/{row.get('binding_name')}",
                    "role": f"{row.get('role_kind')}/{row.get('role_name')}",
                    "resources": row.get("resources"),
                    "verbs": row.get("verbs"),
                    "danger_reasons": row.get("danger_reasons"),
                    "risk_level": row.get("risk_level"),
                    "system_managed": row.get("system_managed"),
                }
            )
    return risks


def _template_security_summary(obj: dict[str, Any]) -> dict[str, Any]:
    non_root_ok, non_root_evidence = _run_as_non_root_ok(obj)
    container_results: list[dict[str, Any]] = []
    for container in _containers(obj):
        sc = container.get("securityContext", {}) or {}
        resources = container.get("resources", {}) or {}
        limits = resources.get("limits", {}) or {}
        requests = resources.get("requests", {}) or {}
        result = {
            "name": container.get("name"),
            "allowPrivilegeEscalation": sc.get("allowPrivilegeEscalation"),
            "readOnlyRootFilesystem": sc.get("readOnlyRootFilesystem"),
            "dropCapabilities": sc.get("capabilities", {}).get("drop", []) or [],
            "has_requests": bool(requests),
            "has_limits": bool(limits),
            "image": container.get("image"),
        }
        result["ok"] = (
            sc.get("allowPrivilegeEscalation") is False
            and sc.get("readOnlyRootFilesystem") is True
            and "ALL" in result["dropCapabilities"]
            and result["has_requests"]
            and result["has_limits"]
        )
        container_results.append(result)
    return {
        "run_as_non_root": non_root_ok,
        "run_as_evidence": non_root_evidence,
        "containers": container_results,
        "all_containers_hardened": bool(container_results) and all(row["ok"] for row in container_results),
    }


def _deployment_rollout_summary(deployment: dict[str, Any]) -> dict[str, Any]:
    spec = deployment.get("spec", {}) or {}
    strategy = spec.get("strategy", {}) or {}
    strategy_type = strategy.get("type", "RollingUpdate")
    rolling = strategy.get("rollingUpdate", {}) or {}
    replicas = spec.get("replicas", 1)
    max_unavailable = rolling.get("maxUnavailable", "25%") if strategy_type == "RollingUpdate" else None
    max_surge = rolling.get("maxSurge", "25%") if strategy_type == "RollingUpdate" else None
    safe = strategy_type == "RollingUpdate" and max_unavailable not in {replicas, "100%", 100} and max_surge not in {0, "0", "0%"}
    return {
        "strategy_type": strategy_type,
        "replicas": replicas,
        "maxUnavailable": max_unavailable,
        "maxSurge": max_surge,
        "minReadySeconds": spec.get("minReadySeconds"),
        "progressDeadlineSeconds": spec.get("progressDeadlineSeconds"),
        "safe": safe,
    }


def _run_as_non_root_ok(obj: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    spec = _pod_spec(obj)
    pod_sc = spec.get("securityContext", {}) or {}
    containers = _containers(obj)
    pod_non_root = pod_sc.get("runAsNonRoot") is True or (isinstance(pod_sc.get("runAsUser"), int) and pod_sc.get("runAsUser") > 0)
    container_results = []
    for container in containers:
        sc = container.get("securityContext", {}) or {}
        ok = sc.get("runAsNonRoot") is True or (isinstance(sc.get("runAsUser"), int) and sc.get("runAsUser") > 0)
        container_results.append({"name": container.get("name"), "runAsNonRoot": sc.get("runAsNonRoot"), "runAsUser": sc.get("runAsUser"), "ok": ok})
    container_non_root = bool(container_results) and all(item["ok"] for item in container_results)
    return pod_non_root or container_non_root, {"pod": {"runAsNonRoot": pod_sc.get("runAsNonRoot"), "runAsUser": pod_sc.get("runAsUser")}, "containers": container_results}


def _spec_hash(obj: dict[str, Any]) -> str:
    spec = _pod_spec(obj)
    canonical = json.dumps(spec, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _spec_hash_baseline_annotation(obj: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    annotations = (_meta(obj).get("annotations", {}) or {}) | (obj.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {}) or {})
    for key in ("cnsec.io/spec-hash", "cnsec.io/spec_hash", "security.cnsec.io/spec-hash", "spec-hash"):
        value = annotations.get(key)
        if value:
            return str(value), {"source": "annotation", "key": key}
    return None, None


def _spec_hash_baseline(index: ResourceIndex, obj: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    annotation_baseline, annotation_source = _spec_hash_baseline_annotation(obj)
    if annotation_baseline:
        return annotation_baseline, annotation_source
    asset = _asset(obj)
    candidates = index.by_kind("SpecHashBaseline") + [
        item for item in index.by_kind("Asset")
        if item.get("spec_hash") or item.get("specHash") or item.get("spec", {}).get("spec_hash") or item.get("spec", {}).get("specHash")
    ]
    for candidate in candidates:
        spec = candidate.get("spec", {}) or {}
        target = spec.get("asset") or spec.get("target") or candidate.get("asset") or {}
        target_kind = target.get("kind") or spec.get("kind") or candidate.get("asset_kind") or candidate.get("assetKind") or _meta(candidate).get("labels", {}).get("asset_kind")
        target_namespace = target.get("namespace") or spec.get("namespace") or candidate.get("namespace") or candidate.get("asset_namespace") or candidate.get("assetNamespace") or _meta(candidate).get("labels", {}).get("asset_namespace")
        target_name = target.get("name") or spec.get("name") or candidate.get("asset_name") or candidate.get("assetName") or _meta(candidate).get("labels", {}).get("asset_name")
        baseline = spec.get("spec_hash") or spec.get("specHash") or candidate.get("spec_hash") or candidate.get("specHash")
        if target_kind == asset.kind and (target_namespace or None) == asset.namespace and target_name == asset.name and baseline:
            return str(baseline), {"source": candidate.get("kind"), "asset": _asset(candidate).key}
    return None, None


def _config_secret_references(index: ResourceIndex) -> dict[str, set[tuple[str, str]]]:
    refs = {"ConfigMap": set(), "Secret": set()}
    for obj in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        ns = _ns_name(obj)
        spec = _pod_spec(obj)
        for volume in spec.get("volumes", []) or []:
            if volume.get("configMap", {}).get("name"):
                refs["ConfigMap"].add((ns, volume["configMap"]["name"]))
            if volume.get("secret", {}).get("secretName"):
                refs["Secret"].add((ns, volume["secret"]["secretName"]))
        for container in _containers(obj):
            for env_from in container.get("envFrom", []) or []:
                if env_from.get("configMapRef", {}).get("name"):
                    refs["ConfigMap"].add((ns, env_from["configMapRef"]["name"]))
                if env_from.get("secretRef", {}).get("name"):
                    refs["Secret"].add((ns, env_from["secretRef"]["name"]))
            for env in container.get("env", []) or []:
                value_from = env.get("valueFrom", {}) or {}
                if value_from.get("configMapKeyRef", {}).get("name"):
                    refs["ConfigMap"].add((ns, value_from["configMapKeyRef"]["name"]))
                if value_from.get("secretKeyRef", {}).get("name"):
                    refs["Secret"].add((ns, value_from["secretKeyRef"]["name"]))
    return refs


def check_microservice_resilience(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    istio_present = _istio_present(index)
    metrics_status, metrics_severity, metrics_observed = _metrics_api_evidence(index)
    findings.append(
        _cluster_finding(
            task_id,
            "CN-6",
            "CN-ELAS-001-metrics-api",
            "metrics-server / metrics API 可用性检查",
            metrics_status,
            metrics_severity,
            "HPA 依赖 metrics-server 或 metrics.k8s.io API 提供运行态指标",
            metrics_observed,
            "metrics.k8s.io APIService Available and metrics-server ready",
            "安装并验证 metrics-server，确保 v1beta1.metrics.k8s.io APIService Available，且 kubectl top 或 HPA currentMetrics 能返回实时指标。",
        )
    )
    for workload in _workloads(index):
        if workload.get("kind") == "DaemonSet":
            continue
        asset = _asset(workload)
        tier = _namespace_tier_for_name(index, asset.namespace)
        hpas = _matching_hpas(index, workload)
        pdbs = _matching_pdbs(index, workload)
        summary_status, summary_severity, summary_observed, summary_remediation = _workload_resilience_summary(index, workload, tier, hpas, pdbs, istio_present)
        findings.append(
            _finding(
                task_id,
                "CN-6",
                "CN-ELAS-001-workload-resilience-score",
                f"{asset.key} 微服务弹性综合评分",
                summary_status,
                summary_severity,
                asset,
                Evidence(
                    "按 HPA、PDB、resources 和服务网格容错配置计算单个 workload 弹性评分",
                    asset,
                    "workload/HPA/PDB/Istio resilience controls",
                    summary_observed,
                    "resilience_score>=80 and no critical missing controls",
                ),
                summary_remediation,
            )
        )
        for rule_id, ok, label in [
            ("CN-ELAS-001-hpa-present", bool(hpas), "配置 HPA"),
            ("CN-ELAS-001-pdb-present", bool(pdbs), "配置 PDB"),
            ("CN-ELAS-001-resources-present", _has_resources(workload), "配置 requests/limits"),
        ]:
            status, severity = _resilience_status(ok, tier)
            findings.append(_finding(task_id, "CN-6", rule_id, f"{asset.key} {label}检查", status, severity, asset, Evidence(f"{asset.key} {label}: {ok}", asset, observed={"configured": ok, "tier": tier}, expected=True), f"为业务 workload {asset.key} 补充 {label}；平台组件缺失时记录高可用部署或托管例外依据。"))
        for hpa in hpas:
            ok, observed = _hpa_quality(hpa)
            status, severity = _resilience_status(ok, tier)
            findings.append(_finding(task_id, "CN-6", "CN-ELAS-001-hpa-quality", f"{asset.key} HPA 配置质量检查", status, severity, asset, Evidence("HPA 应声明 min/max 副本和指标，避免单副本弹性窗口", asset, "HorizontalPodAutoscaler.spec", {"tier": tier, "hpa": _asset(hpa).key, **observed}, "minReplicas>=2, maxReplicas>=minReplicas, metrics present"), "为 HPA 设置 minReplicas>=2、合理 maxReplicas 和明确指标；高级场景补充 behavior 稳定窗口。"))
            runtime_status, runtime_severity, runtime_observed = _hpa_runtime_evidence(hpa)
            findings.append(
                _finding(
                    task_id,
                    "CN-6",
                    "CN-ELAS-001-hpa-runtime",
                    f"{asset.key} HPA 运行态指标/触发证据检查",
                    runtime_status,
                    runtime_severity,
                    asset,
                    Evidence(
                        "HPA status 应包含 currentMetrics、当前/期望副本和 ScalingActive 状态；demo 环境可通过 lastScaleTime、desired/current 差异或 ScalingLimited 证明触发链路",
                        asset,
                        "HorizontalPodAutoscaler.status",
                        {"tier": tier, **runtime_observed},
                        "ScalingActive=True with currentMetrics and replica status",
                    ),
                    "确认 metrics-server 可用，并在 demo namespace 执行轻量负载触发 HPA 后采集 currentMetrics、desiredReplicas/currentReplicas、lastScaleTime 或 ScalingLimited 证据。",
                )
            )
        for pdb in pdbs:
            ok, observed = _pdb_quality(pdb)
            status, severity = _resilience_status(ok, tier)
            findings.append(_finding(task_id, "CN-6", "CN-ELAS-001-pdb-quality", f"{asset.key} PDB 配置质量检查", status, severity, asset, Evidence("PDB 应具备有效 selector 和 minAvailable/maxUnavailable", asset, "PodDisruptionBudget.spec", {"tier": tier, "pdb": _asset(pdb).key, **observed}, "selector plus minAvailable/maxUnavailable"), "为 PDB 配置明确 selector，并设置 minAvailable 或 maxUnavailable。"))
        if istio_present:
            ok, observed = _mesh_resilience_evidence(index, workload)
            if not observed["service_found"]:
                status: FindingStatus = "NOT_APPLICABLE"
                severity: Severity = "info"
                expected = "workload has Service before mesh route policy applies"
            else:
                status, severity = _resilience_status(ok, tier)
                expected = "timeout, retries, and outlierDetection configured"
            findings.append(_finding(task_id, "CN-6", "CN-ELAS-001-service-mesh-resilience", f"{asset.key} 服务网格容错配置检查", status, severity, asset, Evidence("安装 Istio 时应为服务配置 VirtualService timeout/retries 与 DestinationRule outlierDetection；无关联 Service 的 workload 不适用该路由策略检查", asset, "VirtualService.spec.http/DestinationRule.spec.trafficPolicy", {"tier": tier, **observed}, expected), "为业务服务配置 VirtualService timeout/retries 和 DestinationRule outlierDetection；无关联 Service 时补充服务发现或标注不适用。"))
    if not istio_present:
        findings.append(_cluster_finding(task_id, "CN-6", "CN-ELAS-001-service-mesh-resilience", "服务网格容错配置检查", "NOT_APPLICABLE", "info", "未发现 Istio VirtualService/DestinationRule，跳过服务网格 timeout/retry/outlierDetection 检查", {"virtual_services": 0, "destination_rules": 0}, "Istio resources present when mesh is installed", "如使用 Istio，应采集 VirtualService/DestinationRule 并配置 timeout、retry、outlierDetection。"))
    if not findings:
        findings.append(_cluster_finding(task_id, "CN-6", "CN-ELAS-001-no-workload", "未发现可评估 workload", "UNKNOWN", "info", "未采集到 Deployment/StatefulSet", [], "至少需要采集工作负载对象。", "确认采集权限或 manifest 输入。"))
    return findings


def check_immutable_deployment_principle(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _pod_posture_subjects(index):
        asset = _asset(obj)
        tier = _namespace_tier_for_name(index, asset.namespace)
        for container in _containers(obj):
            image = container.get("image", "")
            mutable = image.endswith(":latest") or (":" not in image and "@" not in image) or ("@" not in image)
            image_status, image_severity = _immutable_principle_status(not mutable, tier)
            findings.append(_finding(task_id, "CN-22", "CN-IMM-001-image-pinned-digest", f"{asset.key} 镜像可追溯检查", image_status, image_severity, asset, Evidence("镜像未固定 digest 会降低可追溯性；平台组件镜像发布方式单独复核，不计入业务不可变基线得分", asset, "spec.template.spec.containers[].image", {"tier": tier, "image": image, "mutable": mutable}, "image@sha256:..."), "使用不可变 digest 引用镜像，至少避免 latest。"))
            rootfs = container.get("securityContext", {}).get("readOnlyRootFilesystem")
            rootfs_status, rootfs_severity = _immutability_status(rootfs is True, tier)
            findings.append(_finding(task_id, "CN-22", "CN-IMM-001-rootfs-readonly", f"{asset.key} 根文件系统只读检查", rootfs_status, rootfs_severity, asset, Evidence("业务容器根文件系统应只读；平台组件兼容性例外单独复核，不计入业务不可变基线得分", asset, "securityContext.readOnlyRootFilesystem", {"tier": tier, "readOnlyRootFilesystem": rootfs}, True), "设置 securityContext.readOnlyRootFilesystem=true。"))
            ssh_evidence = _container_ssh_evidence(container)
            ssh_risk = ssh_evidence["exposes_ssh_port"] or ssh_evidence["runs_sshd"]
            findings.append(_finding(task_id, "CN-22", "CN-IMM-001-no-ssh-container", f"{asset.key} 容器 SSH/sshd 检查", "FAIL" if ssh_risk else "PASS", "high" if ssh_risk else "info", asset, Evidence("不可变容器不应暴露 22 端口或运行 sshd/openssh-server", asset, "containers[].ports/command/args", ssh_evidence, "no containerPort 22 and no sshd process"), "移除容器内 SSH 服务，使用审计受控的 kubectl exec、临时调试容器或节点级运维通道。"))
    for service in index.by_kind("Service"):
        ports = service.get("spec", {}).get("ports", []) or []
        exposed_ssh = any((p.get("port") == 22 or p.get("targetPort") == 22 or str(p.get("name", "")).lower() == "ssh") for p in ports)
        findings.append(_finding(task_id, "CN-22", "CN-IMM-001-no-ssh-service", f"{_asset(service).key} SSH 暴露检查", "FAIL" if exposed_ssh else "PASS", "high", _asset(service), Evidence("Service 不应暴露 SSH", _asset(service), "spec.ports", ports, "no tcp/22"), "移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。"))
    exec_risks = _exec_rbac_risk_rows(index)
    findings.append(_cluster_finding(task_id, "CN-22", "CN-IMM-001-exec-rbac", "普通主体 pods/exec 修改路径检查", "FAIL" if exec_risks else "PASS", "critical" if exec_risks else "info", "不可变部署不应给普通/业务主体宽泛 pods/exec 权限", exec_risks[:50], "no business subject can create pods/exec", "移除普通主体的 pods/exec create/update/patch 权限；调试访问应临时授权、带审批和过期标记。"))
    return findings


def check_container_immutability_controls(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for obj in _pod_posture_subjects(index):
        asset = _asset(obj)
        tier = _namespace_tier_for_name(index, asset.namespace)
        run_as_non_root, run_as_evidence = _run_as_non_root_ok(obj)
        status, severity = _immutability_status(run_as_non_root, tier)
        findings.append(_finding(task_id, "CN-23", "CN-IMM-002-run-as-non-root", f"{asset.key} 非 root 运行检查", status, severity, asset, Evidence("业务容器应设置 runAsNonRoot；平台组件缺失时作为兼容性复核项", asset, "spec.securityContext/runAsUser", {"tier": tier, **run_as_evidence}, True), "设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID；平台组件记录例外依据。"))
        for container in _containers(obj):
            rootfs = container.get("securityContext", {}).get("readOnlyRootFilesystem")
            status, severity = _immutability_status(rootfs is True, tier)
            findings.append(_finding(task_id, "CN-23", "CN-IMM-002-rootfs-readonly", f"{asset.key} 只读根文件系统管控检查", status, severity, asset, Evidence("业务容器应设置 readOnlyRootFilesystem=true；平台组件缺失时作为兼容性复核项", asset, "containers[].securityContext.readOnlyRootFilesystem", {"tier": tier, "container": container.get("name"), "readOnlyRootFilesystem": rootfs}, True), "设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。"))
            ape = container.get("securityContext", {}).get("allowPrivilegeEscalation")
            status, severity = _immutability_status(ape is False, tier)
            findings.append(_finding(task_id, "CN-23", "CN-IMM-002-no-privilege-escalation", f"{asset.key} 禁止提权检查", status, severity, asset, Evidence("业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项", asset, "containers[].securityContext.allowPrivilegeEscalation", {"tier": tier, "container": container.get("name"), "allowPrivilegeEscalation": ape}, False), "设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。"))
    for workload in _workloads(index):
        asset = _asset(workload)
        tier = _namespace_tier_for_name(index, asset.namespace)
        current_hash = _spec_hash(workload)
        baseline, baseline_source = _spec_hash_baseline(index, workload)
        if baseline:
            status = "PASS" if baseline == current_hash else "FAIL"
            severity: Severity = "info" if status == "PASS" else "high"
        else:
            status = "WARN" if tier in {"business", "demo-risk"} else "PASS"
            severity = "medium" if status == "WARN" else "info"
        findings.append(_finding(task_id, "CN-23", "CN-IMM-002-spec-hash-baseline", f"{asset.key} spec hash 基线检查", status, severity, asset, Evidence("首次扫描应记录 workload spec hash，二次扫描用于识别漂移；支持注解基线和历史 Asset/SpecHashBaseline 基线", asset, "metadata.annotations.cnsec.io/spec-hash or Asset.spec_hash", {"tier": tier, "baseline": baseline, "baseline_source": baseline_source, "current_hash": current_hash}, "baseline equals current hash"), "为业务 workload 写入 cnsec.io/spec-hash 基线或持久化 Asset.spec_hash；发现 hash 漂移时走变更审批或回滚。"))
    for job in index.by_kind("Job"):
        tier = _namespace_tier_for_name(index, _ns_name(job))
        ttl = job.get("spec", {}).get("ttlSecondsAfterFinished")
        if ttl:
            status: FindingStatus = "PASS"
            severity: Severity = "info"
        elif tier == "platform":
            status = "NOT_APPLICABLE"
            severity = "info"
        elif tier == "demo-risk":
            status = "FAIL"
            severity = "medium"
        else:
            status = "WARN"
            severity = "low"
        findings.append(_finding(task_id, "CN-23", "CN-IMM-002-job-ttl", f"{_asset(job).key} Job TTL 检查", status, severity, _asset(job), Evidence("Job 应配置完成后清理 TTL；平台安全组件的临时扫描 Job 单独复核，不计入业务不可变基线得分", _asset(job), "spec.ttlSecondsAfterFinished", {"tier": tier, "ttlSecondsAfterFinished": ttl}, ">0"), "为一次性 Job 设置 ttlSecondsAfterFinished。"))
    for pod in index.by_kind("Pod"):
        phase = str((pod.get("status", {}) or {}).get("phase") or "")
        if phase not in {"Succeeded", "Failed"}:
            continue
        asset = _asset(pod)
        tier = _namespace_tier_for_name(index, asset.namespace)
        owner_refs = _meta(pod).get("ownerReferences") or []
        age_hours = _object_age_hours(pod)
        if tier == "platform":
            status = "NOT_APPLICABLE"
            severity = "info"
        elif tier == "default":
            status = "WARN"
            severity = "low"
        else:
            status = "FAIL"
            severity = "medium"
        findings.append(
            _finding(
                task_id,
                "CN-23",
                "CN-IMM-002-completed-pod-cleanup",
                f"{asset.key} Completed/Failed Pod 清理检查",
                status,
                severity,
                asset,
                Evidence(
                    "Completed/Failed Pod 会破坏不可变环境整洁度，应由 Job TTL 或控制器自动清理",
                    asset,
                    "status.phase/metadata.ownerReferences",
                    {"tier": tier, "phase": phase, "ownerReferences": owner_refs, "age_hours": age_hours},
                    "no lingering Succeeded/Failed pods in business namespaces",
                ),
                "为一次性任务配置 Job TTL，清理 Completed/Failed Pod，避免残留调试或失败副本长期存在。",
            )
        )
    stale_window_hours = 6.0
    for rs in index.by_kind("ReplicaSet"):
        asset = _asset(rs)
        tier = _namespace_tier_for_name(index, asset.namespace)
        owner_name = _owner_reference_name(rs, "Deployment")
        if not owner_name:
            continue
        revision = _intish((_meta(rs).get("annotations", {}) or {}).get("deployment.kubernetes.io/revision"))
        status_block = rs.get("status", {}) or {}
        replica_counts = {
            "spec_replicas": _intish((rs.get("spec", {}) or {}).get("replicas")),
            "replicas": _intish(status_block.get("replicas")),
            "readyReplicas": _intish(status_block.get("readyReplicas")),
            "availableReplicas": _intish(status_block.get("availableReplicas")),
        }
        active = any((value or 0) > 0 for value in replica_counts.values() if value is not None)
        age_hours = _object_age_hours(rs)
        stale = bool(not active and revision is not None and (age_hours is None or age_hours >= stale_window_hours))
        if stale:
            if tier == "platform":
                status = "NOT_APPLICABLE"
                severity = "info"
            elif tier == "default":
                status = "WARN"
                severity = "low"
            else:
                status = "FAIL"
                severity = "medium"
        else:
            status = "PASS" if tier != "platform" else "NOT_APPLICABLE"
            severity = "info"
        findings.append(
            _finding(
                task_id,
                "CN-23",
                "CN-IMM-002-stale-replicaset",
                f"{asset.key} 旧 ReplicaSet 清理检查",
                status,
                severity,
                asset,
                Evidence(
                    "Deployment rollout 后长期保留的旧 ReplicaSet 会增加漂移与误回滚面，近期 rollout 的 0 副本 ReplicaSet 作为缓冲窗口内例外",
                    asset,
                    "metadata.ownerReferences/metadata.annotations/status.replicas",
                    {
                        "tier": tier,
                        "ownerDeployment": owner_name,
                        "revision": revision,
                        "replica_counts": replica_counts,
                        "age_hours": age_hours,
                        "stale_window_hours": stale_window_hours,
                        "stale": stale,
                    },
                    "only current or recently rolled out ReplicaSets remain",
                ),
                "清理长期 0 副本旧 ReplicaSet；保留最近一次回滚缓冲所需对象时记录保留依据。",
            )
        )
    refs = _config_secret_references(index)
    for kind in ("ConfigMap", "Secret"):
        for obj in index.by_kind(kind):
            asset = _asset(obj)
            tier = _namespace_tier_for_name(index, asset.namespace)
            if tier == "platform":
                continue
            if kind == "ConfigMap" and asset.name == "kube-root-ca.crt":
                continue
            owner_refs = _meta(obj).get("ownerReferences") or []
            referenced = (asset.namespace or "default", asset.name) in refs[kind]
            service_account_secret = kind == "Secret" and str(obj.get("type", "")).startswith("kubernetes.io/service-account-token")
            if referenced or owner_refs or service_account_secret:
                status = "PASS"
            else:
                status = "WARN" if tier != "demo-risk" else "FAIL"
            findings.append(_finding(task_id, "CN-23", f"CN-IMM-002-orphan-{kind.lower()}", f"{asset.key} 孤儿 {kind} 检查", status, "medium" if status == "FAIL" else "low", asset, Evidence("业务 ConfigMap/Secret 应被 workload 引用或有 ownerReference；Secret 仅保留脱敏元信息", asset, "metadata/refs", {"tier": tier, "referenced": referenced, "ownerReferences": owner_refs, "data_key_count": obj.get("data_key_count")}, "referenced or owned"), f"清理未引用的 {kind}，或补充 ownerReference/保留原因标注。"))
    return findings


def check_scaling_security(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    policy_kinds = {"ClusterPolicy", "Policy", "ValidatingAdmissionPolicy", "ConstraintTemplate"}
    policy = _policy_summary(index)
    has_policy = bool(index.kinds() & policy_kinds)
    has_any_security_policy = policy["security_policy_count"] > 0
    has_security_policy = policy["core_control_coverage"] >= len(POD_SECURITY_REQUIRED_CONTROLS)
    admission_status: FindingStatus = "PASS" if has_security_policy else "WARN" if (has_policy or has_any_security_policy) else "FAIL"
    findings.append(_cluster_finding(task_id, "CN-24", "CN-ELAS-002-admission-policy-present", "准入策略覆盖检查", admission_status, "high" if admission_status == "FAIL" else "medium" if admission_status == "WARN" else "info", "检查 Kyverno/Gatekeeper/VAP 是否存在并完整覆盖核心 Pod 安全约束", policy, "required pod security controls covered", "安装并启用 Pod 安全准入策略，至少覆盖 runAsNonRoot、禁止提权、禁用特权容器、drop ALL capabilities、seccompProfile。"))
    workload_counts = _workload_namespaces(index)
    namespace_rows: list[dict[str, Any]] = []
    for ns in index.by_kind("Namespace"):
        ns_name = _meta(ns).get("name", "default")
        labels = _meta(ns).get("labels", {}) or {}
        tier = _namespace_tier(ns)
        workload_count = workload_counts.get(ns_name, 0)
        has_psa = _has_psa(labels)
        if has_psa:
            status: FindingStatus = "PASS"
            severity: Severity = "info"
        elif tier == "demo-risk" or (tier == "business" and workload_count > 0):
            status = "FAIL"
            severity = "medium"
        elif tier == "platform":
            status = "NOT_APPLICABLE"
            severity = "info"
        elif tier == "default" and workload_count == 0:
            status = "NOT_APPLICABLE"
            severity = "info"
        else:
            status = "WARN"
            severity = "low" if tier in {"platform", "default"} else "medium"
        namespace_rows.append({"namespace": ns_name, "tier": tier, "has_psa": has_psa, "psa_mode": _psa_mode(labels), "workload_count": workload_count})
        findings.append(_finding(task_id, "CN-24", "CN-ELAS-002-psa-labels", f"{_asset(ns).key} PSA label 检查", status, severity, _asset(ns), Evidence("Namespace 应启用 PSA labels；平台组件 namespace 缺失时作为复核项，承载业务 workload 的 namespace 缺失为失败", _asset(ns), "metadata.labels", {"tier": tier, "labels": labels, "workload_count": workload_count}, "pod-security labels"), "为业务 namespace 设置 enforce/audit/warn PSA labels；平台 namespace 记录豁免依据或补充审计模式。"))
    unprotected_workload_namespaces = [
        row for row in namespace_rows
        if row["workload_count"] > 0 and not row["has_psa"] and row["tier"] in {"business", "demo-risk", "default"}
    ]
    platform_review_namespaces = [
        row for row in namespace_rows
        if row["workload_count"] > 0 and not row["has_psa"] and row["tier"] == "platform"
    ]
    inheritance_status: FindingStatus
    inheritance_severity: Severity
    if any(row["tier"] == "demo-risk" for row in unprotected_workload_namespaces):
        inheritance_status = "FAIL"
        inheritance_severity = "high"
    elif unprotected_workload_namespaces:
        inheritance_status = "WARN"
        inheritance_severity = "medium"
    else:
        inheritance_status = "PASS" if (has_security_policy or any(row["has_psa"] for row in namespace_rows if row["workload_count"] > 0)) else "UNKNOWN"
        inheritance_severity = "info"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-24",
            "CN-ELAS-002-workload-policy-inheritance",
            "扩缩容工作负载策略继承检查",
            inheritance_status,
            inheritance_severity,
            "新 Pod 由 HPA/Deployment/StatefulSet 扩容创建时应继承 namespace PSA 或准入策略",
            {
                "policy": policy,
                "workload_namespaces": namespace_rows,
                "unprotected_workload_namespaces": unprotected_workload_namespaces,
                "platform_review_namespaces": platform_review_namespaces,
            },
            "business workload namespaces protected by PSA/admission policy",
            "为业务工作负载 namespace 启用 PSA restricted/baseline 或等价 Kyverno/Gatekeeper/VAP 策略，确保扩容后新 Pod 自动继承约束。",
        )
    )
    for deployment in index.by_kind("Deployment"):
        asset = _asset(deployment)
        tier = _namespace_tier_for_name(index, asset.namespace)
        rollout = _deployment_rollout_summary(deployment)
        if rollout["safe"]:
            status = "PASS"
            severity = "info"
        elif tier in {"business", "demo-risk"}:
            status = "FAIL"
            severity = "medium"
        elif tier == "platform":
            status = "NOT_APPLICABLE"
            severity = "info"
        else:
            status = "WARN"
            severity = "low"
        findings.append(
            _finding(
                task_id,
                "CN-24",
                "CN-ELAS-002-rollout-strategy",
                f"{asset.key} rollout strategy 安全检查",
                status,
                severity,
                asset,
                Evidence("Deployment 应使用可控 RollingUpdate，避免 Recreate 或全量不可用导致扩缩容期间策略绕过/服务中断", asset, "spec.strategy/spec.minReadySeconds", rollout, "RollingUpdate with bounded maxUnavailable/maxSurge"),
                "为 Deployment 配置 RollingUpdate、合理 maxUnavailable/maxSurge，并设置 minReadySeconds/progressDeadlineSeconds 便于灰度与回滚。",
            )
        )
    for hpa in index.by_kind("HorizontalPodAutoscaler"):
        asset = _asset(hpa)
        target = _hpa_scale_target(index, hpa)
        if not target:
            findings.append(
                _finding(
                    task_id,
                    "CN-24",
                    "CN-ELAS-002-hpa-template-inheritance",
                    f"{asset.key} HPA 目标模板继承检查",
                    "FAIL",
                    "high",
                    asset,
                    Evidence("HPA 应能定位 scaleTargetRef 并复用同一 Pod 安全规则包", asset, "spec.scaleTargetRef", hpa.get("spec", {}).get("scaleTargetRef", {}), "target workload exists"),
                    "修正 HPA scaleTargetRef，确保扩容目标存在并纳入同一准入/PSA/模板安全检查。",
                )
            )
            continue
        target_asset = _asset(target)
        tier = _namespace_tier_for_name(index, target_asset.namespace)
        template_security = _template_security_summary(target)
        target_ns = next((ns for ns in index.by_kind("Namespace") if _meta(ns).get("name") == target_asset.namespace), None)
        has_namespace_psa = bool(target_ns and _has_psa(_meta(target_ns).get("labels", {}) or {}))
        inherited = has_namespace_psa or has_security_policy
        hardened = template_security["run_as_non_root"] and template_security["all_containers_hardened"]
        if inherited and hardened:
            status = "PASS"
            severity = "info"
        elif tier in {"business", "demo-risk"}:
            status = "FAIL"
            severity = "high"
        else:
            status = "WARN"
            severity = "medium"
        findings.append(
            _finding(
                task_id,
                "CN-24",
                "CN-ELAS-002-hpa-template-inheritance",
                f"{asset.key} HPA 扩容模板安全继承检查",
                status,
                severity,
                asset,
                Evidence(
                    "HPA 扩容后的 Pod template 应继承 namespace PSA/准入策略并满足基础安全上下文",
                    asset,
                    "spec.scaleTargetRef/template.spec.securityContext",
                    {"target": target_asset.key, "namespace_psa": has_namespace_psa, "security_policy": has_security_policy, "template_security": template_security},
                    "PSA/admission inherited and template hardened",
                ),
                "为 HPA 目标 workload 配置非 root、禁止提权、只读根文件系统、drop ALL capabilities、requests/limits，并确保 namespace PSA 或准入策略覆盖扩容 Pod。",
            )
        )
    return findings


RESOURCEQUOTA_REQUIRED_HARD = ("pods", "requests.cpu", "requests.memory", "limits.cpu", "limits.memory")


def _resourcequota_quality(quotas: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    covered: set[str] = set()
    for quota in quotas:
        hard = quota.get("spec", {}).get("hard", {}) or {}
        quota_covered = {key for key in RESOURCEQUOTA_REQUIRED_HARD if key in hard}
        covered.update(quota_covered)
        rows.append({"name": _meta(quota).get("name"), "hard": hard, "covered": sorted(quota_covered)})
    missing = [key for key in RESOURCEQUOTA_REQUIRED_HARD if key not in covered]
    return {"quotas": rows, "covered": sorted(covered), "missing": missing, "complete": not missing}


def _limitrange_defaults_quality(limits: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    has_default = {"cpu": False, "memory": False}
    has_default_request = {"cpu": False, "memory": False}
    for limit_range in limits:
        for item in limit_range.get("spec", {}).get("limits", []) or []:
            if item.get("type") != "Container":
                continue
            default = item.get("default", {}) or {}
            default_request = item.get("defaultRequest", {}) or {}
            for resource in ("cpu", "memory"):
                has_default[resource] = has_default[resource] or resource in default
                has_default_request[resource] = has_default_request[resource] or resource in default_request
            rows.append({"name": _meta(limit_range).get("name"), "default": default, "defaultRequest": default_request})
    missing = []
    for resource in ("cpu", "memory"):
        if not has_default[resource]:
            missing.append(f"default.{resource}")
        if not has_default_request[resource]:
            missing.append(f"defaultRequest.{resource}")
    return {"limitranges": rows, "missing": missing, "complete": not missing}


def _priorityclass_governance(index: ResourceIndex) -> dict[str, Any]:
    priority_classes = {str(_meta(item).get("name")): item for item in index.by_kind("PriorityClass")}
    rows = [
        {
            "name": name,
            "value": item.get("value"),
            "globalDefault": item.get("globalDefault"),
            "system_class": name.startswith("system-"),
        }
        for name, item in sorted(priority_classes.items())
    ]
    subjects = []
    for obj in _workloads(index) + index.by_kind("Job") + index.by_kind("CronJob"):
        tier = _namespace_tier_for_name(index, _ns_name(obj))
        if tier not in {"business", "demo-risk", "default"}:
            continue
        priority_class_name = _pod_spec(obj).get("priorityClassName")
        subjects.append(
            {
                "asset": _asset(obj).key,
                "tier": tier,
                "priorityClassName": priority_class_name,
                "defined": bool(priority_class_name and priority_class_name in priority_classes),
                "system_class": bool(priority_class_name and str(priority_class_name).startswith("system-")),
            }
        )
    for pod in index.by_kind("Pod"):
        if _meta(pod).get("ownerReferences"):
            continue
        tier = _namespace_tier_for_name(index, _ns_name(pod))
        if tier not in {"business", "demo-risk", "default"}:
            continue
        priority_class_name = _pod_spec(pod).get("priorityClassName")
        subjects.append(
            {
                "asset": _asset(pod).key,
                "tier": tier,
                "priorityClassName": priority_class_name,
                "defined": bool(priority_class_name and priority_class_name in priority_classes),
                "system_class": bool(priority_class_name and str(priority_class_name).startswith("system-")),
            }
        )
    missing_usage = [
        row for row in subjects
        if not row["priorityClassName"] or not row["defined"] or row["system_class"]
    ]
    return {
        "priority_classes": rows,
        "business_workloads": subjects,
        "missing_usage": missing_usage,
        "has_priority_classes": bool(priority_classes),
        "has_business_workloads": bool(subjects),
        "complete": bool(subjects) and bool(priority_classes) and not missing_usage,
    }


def check_resource_policy_governance(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    namespaces = [_meta(ns).get("name") for ns in index.by_kind("Namespace")]
    namespace_governance: list[dict[str, Any]] = []
    for ns in namespaces:
        quotas = [q for q in index.by_kind("ResourceQuota") if _ns_name(q) == ns]
        limits = [l for l in index.by_kind("LimitRange") if _ns_name(l) == ns]
        tier = _namespace_tier_for_name(index, ns)
        strict_namespace = tier in {"business", "demo-risk"}
        quota_quality = _resourcequota_quality(quotas)
        quota_status: FindingStatus = "PASS" if quota_quality["complete"] else "FAIL" if strict_namespace else "NOT_APPLICABLE"
        quota_severity: Severity = "info" if quota_status in {"PASS", "NOT_APPLICABLE"} else "medium"
        findings.append(_cluster_finding(task_id, "CN-25", "CN-ELAS-003-resourcequota", f"{ns} ResourceQuota 检查", quota_status, quota_severity, f"{ns} ResourceQuota 应限制 pods 与 CPU/Memory requests/limits", {"count": len(quotas), "tier": tier, **quota_quality}, "pods, requests.cpu, requests.memory, limits.cpu, limits.memory", "为业务 namespace 配置覆盖 pods、requests.cpu、requests.memory、limits.cpu、limits.memory 的 ResourceQuota。"))
        limit_quality = _limitrange_defaults_quality(limits)
        limit_status: FindingStatus = "PASS" if limit_quality["complete"] else "FAIL" if strict_namespace else "NOT_APPLICABLE"
        limit_severity: Severity = "info" if limit_status in {"PASS", "NOT_APPLICABLE"} else "medium"
        findings.append(_cluster_finding(task_id, "CN-25", "CN-ELAS-003-limitrange", f"{ns} LimitRange 检查", limit_status, limit_severity, f"{ns} LimitRange 应设置 Container 默认 requests/limits", {"count": len(limits), "tier": tier, **limit_quality}, "default/defaultRequest cpu and memory", "为业务 namespace 配置 LimitRange Container default/defaultRequest CPU 与内存。"))
        if strict_namespace:
            namespace_governance.append(
                {
                    "namespace": ns,
                    "tier": tier,
                    "resourcequota_complete": quota_quality["complete"],
                    "limitrange_complete": limit_quality["complete"],
                }
            )
    daemonsets = index.by_kind("DaemonSet")
    findings.append(_cluster_finding(task_id, "CN-25", "CN-ELAS-003-daemonset-coverage", "DaemonSet 节点覆盖检查", "PASS" if daemonsets else "UNKNOWN", "info", "用于节点纳管的 DaemonSet 数量", len(daemonsets), ">=1", "部署 CNI/Falco/日志采集等 DaemonSet 纳管节点。"))
    node_names = sorted(_meta(node).get("name", "") for node in index.by_kind("Node") if _meta(node).get("name"))
    daemonset_rows: list[dict[str, Any]] = []
    for daemonset in daemonsets:
        status_block = daemonset.get("status", {}) or {}
        desired = _intish(status_block.get("desiredNumberScheduled"))
        current = _intish(status_block.get("currentNumberScheduled"))
        ready = _intish(status_block.get("numberReady"))
        ds_pods = [
            pod for pod in index.by_kind("Pod")
            if _owner_reference_name(pod, "DaemonSet") == _meta(daemonset).get("name") and _ns_name(pod) == _ns_name(daemonset)
        ]
        pod_nodes = sorted({str((pod.get("spec", {}) or {}).get("nodeName")) for pod in ds_pods if (pod.get("spec", {}) or {}).get("nodeName")})
        if pod_nodes:
            complete = bool(node_names) and set(node_names).issubset(set(pod_nodes))
        elif desired is not None or current is not None:
            complete = bool(node_names) and desired is not None and current is not None and desired > 0 and current >= desired
        else:
            complete = bool(node_names)
        daemonset_rows.append(
            {
                "asset": _asset(daemonset).key,
                "desiredNumberScheduled": desired,
                "currentNumberScheduled": current,
                "numberReady": ready,
                "node_names": node_names,
                "pod_nodes": pod_nodes,
                "complete": complete,
            }
        )
    daemonset_governance_status: FindingStatus = "PASS" if (node_names and any(row["complete"] for row in daemonset_rows)) else "UNKNOWN" if not node_names else "FAIL"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-25",
            "CN-ELAS-003-daemonset-governance",
            "节点 DaemonSet 自动纳管检查",
            daemonset_governance_status,
            "info" if daemonset_governance_status == "PASS" else "medium",
            "至少一个节点级 DaemonSet 应证明新节点加入后会自动被安全/网络/观测组件纳管",
            {"node_count": len(node_names), "node_names": node_names, "governance_scope": "node auto governance", "daemonsets": daemonset_rows[:20]},
            "at least one DaemonSet covers all nodes",
            "部署并验证 CNI、Falco、日志采集等 DaemonSet 覆盖全部节点，确保新节点加入后自动纳管。",
        )
    )
    priority_observed = _priorityclass_governance(index)
    if priority_observed["complete"]:
        priority_status: FindingStatus = "PASS"
    elif priority_observed["has_business_workloads"]:
        priority_status = "FAIL"
    else:
        priority_status = "WARN"
    findings.append(_cluster_finding(task_id, "CN-25", "CN-ELAS-003-priorityclass", "PriorityClass 优先级治理检查", priority_status, "medium", "PriorityClass 应定义业务优先级并被业务 workload 引用，防止资源争抢时无序驱逐", priority_observed, "business workloads use defined non-system PriorityClass", "定义系统、业务和批处理等 PriorityClass，并在关键 workload 中引用非 system-* 优先级类。"))
    resource_rule_tokens = {"pods", "nodes", "deployments", "statefulsets", "daemonsets", "jobs"}
    admission_rows: list[dict[str, Any]] = []
    for policy in index.by_kind("ValidatingAdmissionPolicy") + index.by_kind("ClusterPolicy") + index.by_kind("Policy"):
        text = json.dumps(policy.get("spec", {}) or {}, ensure_ascii=False, sort_keys=True, default=str).lower()
        matched_resources = sorted({token for token in resource_rule_tokens if token in text})
        if matched_resources:
            admission_rows.append(
                {
                    "asset": _asset(policy).key,
                    "kind": policy.get("kind"),
                    "resources": matched_resources,
                }
            )
    pod_policy_present = any("pods" in row["resources"] for row in admission_rows)
    node_policy_present = any("nodes" in row["resources"] for row in admission_rows)
    if pod_policy_present and (node_policy_present or any(row["complete"] for row in daemonset_rows)):
        admission_status: FindingStatus = "PASS"
    elif admission_rows:
        admission_status = "WARN"
    else:
        admission_status = "FAIL"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-25",
            "CN-ELAS-003-admission-governance",
            "新 Pod/节点准入治理检查",
            admission_status,
            "info" if admission_status == "PASS" else "high" if admission_status == "FAIL" else "medium",
            "准入策略应覆盖 Pod/Node 等新资源的创建或更新，证明新增对象会自动套用治理策略",
            {
                "policy_count": len(admission_rows),
                "policy_sample": admission_rows[:20],
                "pod_policy_present": pod_policy_present,
                "node_policy_present": node_policy_present,
                "daemonset_node_governance": daemonset_rows[:20],
                "business_namespace_governance": namespace_governance,
            },
            "admission policy covers pods and nodes",
            "为 Pod/Node 配置 ValidatingAdmissionPolicy、Kyverno 或等效准入策略，确保新对象自动继承安全与资源治理。",
        )
    )
    return findings


DANGEROUS_VERBS = {"*", "bind", "escalate", "impersonate"}
DANGEROUS_RESOURCES = {"*", "secrets", "pods/exec", "roles", "clusterroles", "rolebindings", "clusterrolebindings"}
TRUSTED_SCALE_ACTOR_TOKENS = (
    "horizontal-pod-autoscaler",
    "hpa-controller",
    "deployment-controller",
    "replicaset-controller",
    "statefulset-controller",
    "system:serviceaccount:kube-system",
    "system:kube-controller-manager",
    "ci",
    "cicd",
    "argocd",
    "flux",
)


def _rules_with_danger(index: ResourceIndex) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    dangerous = []
    for role in index.by_kind("Role") + index.by_kind("ClusterRole"):
        for rule in role.get("rules", []) or []:
            verbs = set(rule.get("verbs", []) or [])
            resources = set(rule.get("resources", []) or [])
            if verbs & DANGEROUS_VERBS or ({"list", "watch", "get"} & verbs and resources & {"secrets", "*"}) or ("create" in verbs and resources & {"pods/exec", "*"}) or resources & DANGEROUS_RESOURCES and "*" in verbs:
                dangerous.append((role, rule))
    return dangerous


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _event_timestamp(obj: dict[str, Any]) -> datetime | None:
    meta = _meta(obj)
    for key in ("eventTime", "lastTimestamp", "firstTimestamp", "time", "timestamp"):
        parsed = _parse_timestamp(obj.get(key))
        if parsed:
            return parsed
    for key in ("creationTimestamp",):
        parsed = _parse_timestamp(meta.get(key))
        if parsed:
            return parsed
    return None


def _owner_reference_name(obj: dict[str, Any], kind: str) -> str | None:
    for owner in _meta(obj).get("ownerReferences") or []:
        if owner.get("kind") == kind and owner.get("name"):
            return str(owner.get("name"))
    return None


def _object_age_hours(obj: dict[str, Any]) -> float | None:
    timestamp = _event_timestamp(obj)
    if not timestamp:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - timestamp).total_seconds() / 3600, 0.0)


def _scale_event_actor(obj: dict[str, Any]) -> str | None:
    user = obj.get("user")
    if isinstance(user, dict):
        return user.get("username")
    if isinstance(user, str):
        return user
    for key in ("actor", "username", "reportingController", "source", "manager"):
        if obj.get(key):
            return str(obj[key])
    return None


def _scale_event_target(obj: dict[str, Any]) -> dict[str, Any]:
    target = obj.get("target") or obj.get("objectRef") or obj.get("regarding") or obj.get("involvedObject") or {}
    if not isinstance(target, dict):
        target = {}
    ns = target.get("namespace") or _ns_name(obj)
    kind = target.get("kind") or target.get("resource") or obj.get("target_kind") or obj.get("resource")
    name = target.get("name") or obj.get("target_name") or obj.get("workload")
    kind_map = {"deployments": "Deployment", "deployment": "Deployment", "statefulsets": "StatefulSet", "statefulset": "StatefulSet", "replicasets": "ReplicaSet", "replicaset": "ReplicaSet"}
    normalized_kind = kind_map.get(str(kind).lower(), kind) if kind else kind
    return {"namespace": ns, "kind": normalized_kind, "name": name}


def _replica_transition_from_text(text: str) -> tuple[int | None, int | None]:
    transition_patterns = [
        r"\bfrom\s+(?P<current>\d+)\s+to\s+(?P<desired>\d+)\b",
        r"\b(?:current|old)\s*replicas?\s*(?:=|:)\s*(?P<current>\d+)\b.*?\b(?:desired|new|target)\s*replicas?\s*(?:=|:)\s*(?P<desired>\d+)\b",
    ]
    for pattern in transition_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            current = match.groupdict().get("current")
            desired = match.groupdict().get("desired")
            return int(current) if current is not None else None, int(desired) if desired is not None else None
    return None, None


def _replicas_from_text(text: str) -> int | None:
    _, desired = _replica_transition_from_text(text)
    if desired is not None:
        return desired
    patterns = [
        r"\b(?:desired|target|scaled\s+(?:up|down)\s+to|to)\s+(?P<count>\d+)\s*(?:replicas?)?\b",
        r"\breplicas?\s*(?:=|:)\s*(?P<count>\d+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return int(match.group("count"))
    return None


def _first_present(obj: dict[str, Any], *paths: tuple[str, ...] | str) -> Any:
    for path in paths:
        keys = (path,) if isinstance(path, str) else path
        current: Any = obj
        found = True
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                found = False
                break
            current = current[key]
        if found:
            return current
    return None


def _scale_events(index: ResourceIndex) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in index.by_kind("ScaleEvent") + index.by_kind("AuditLogEvent") + index.by_kind("Event"):
        text = " ".join(str(obj.get(key, "")) for key in ("reason", "message", "verb", "action", "event_type", "operation"))
        target = _scale_event_target(obj)
        subresource = (obj.get("objectRef") or {}).get("subresource") if isinstance(obj.get("objectRef"), dict) else None
        is_scale = (
            obj.get("kind") == "ScaleEvent"
            or subresource == "scale"
            or "scale" in text.lower()
            or "replica" in text.lower()
            or "扩缩" in text
            or "扩容" in text
        )
        if not is_scale:
            continue
        current_replicas = _first_present(obj, "current_replicas", "currentReplicas", "old_replicas", ("requestObject", "status", "replicas"))
        desired_replicas = _first_present(obj, "desired_replicas", "desiredReplicas", "new_replicas", ("requestObject", "spec", "replicas"), ("responseObject", "spec", "replicas"))
        parsed_current, parsed_desired = _replica_transition_from_text(text)
        if current_replicas is None:
            current_replicas = parsed_current
        if desired_replicas is None:
            desired_replicas = parsed_desired if parsed_desired is not None else _replicas_from_text(text)
        rows.append(
            {
                "asset": _asset(obj).key,
                "namespace": target.get("namespace"),
                "kind": target.get("kind"),
                "name": target.get("name"),
                "actor": _scale_event_actor(obj),
                "reason": obj.get("reason") or obj.get("event_type") or obj.get("verb") or obj.get("action"),
                "message": obj.get("message") or obj.get("raw"),
                "current_replicas": current_replicas,
                "desired_replicas": desired_replicas,
                "timestamp": _event_timestamp(obj),
                "source_kind": obj.get("kind"),
            }
        )
    return rows


def _actor_trusted_for_scale(actor: str | None) -> bool:
    if not actor:
        return False
    lowered = actor.lower()
    return any(token in lowered for token in TRUSTED_SCALE_ACTOR_TOKENS)


def _scale_role_system_managed(index: ResourceIndex, role: dict[str, Any]) -> bool:
    asset = _asset(role)
    name = asset.name
    labels = _labels(role)
    if (
        _namespace_tier_for_name(index, asset.namespace) == "platform"
        or name.startswith("system:")
        or name in {"admin", "edit", "cluster-admin"}
        or labels.get("kubernetes.io/bootstrapping") == "rbac-defaults"
        or labels.get("rbac.authorization.k8s.io/aggregate-to-edit") == "true"
        or labels.get("rbac.authorization.k8s.io/aggregate-to-admin") == "true"
    ):
        return True
    subjects = _role_binding_subjects(index, role)
    return bool(subjects) and all(_rbac_subject_system_managed(index, subject) for subject in subjects)


def _role_binding_subjects(index: ResourceIndex, role: dict[str, Any]) -> list[dict[str, Any]]:
    role_asset = _asset(role)
    role_kind = role.get("kind")
    subjects: list[dict[str, Any]] = []
    for binding in index.by_kind("RoleBinding") + index.by_kind("ClusterRoleBinding"):
        role_ref = binding.get("roleRef") or {}
        if role_ref.get("kind") != role_kind or role_ref.get("name") != role_asset.name:
            continue
        if role_kind == "Role" and _ns_name(binding) != role_asset.namespace:
            continue
        for subject in binding.get("subjects", []) or []:
            subjects.append({**subject, "binding": _asset(binding).key})
    return subjects


def _rbac_subject_system_managed(index: ResourceIndex, subject: dict[str, Any]) -> bool:
    kind = subject.get("kind")
    name = str(subject.get("name") or "")
    namespace = subject.get("namespace")
    if kind == "ServiceAccount":
        return _namespace_tier_for_name(index, namespace) == "platform" or name.startswith("system:")
    if kind in {"Group", "User"}:
        if name in {"system:authenticated", "system:unauthenticated", "system:anonymous"}:
            return False
        return name.startswith("system:")
    return False


def _intish(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _hpa_bounds_status(hpa: dict[str, Any]) -> tuple[FindingStatus, Severity, dict[str, Any]]:
    spec = hpa.get("spec", {}) or {}
    min_replicas = _intish(spec.get("minReplicas", 1))
    max_replicas = _intish(spec.get("maxReplicas"))
    reasons: list[str] = []
    if max_replicas is None:
        reasons.append("maxReplicas missing or invalid")
    elif max_replicas > 50:
        reasons.append("maxReplicas > 50")
    if min_replicas is None:
        reasons.append("minReplicas invalid")
    elif min_replicas < 1:
        reasons.append("minReplicas < 1")
    elif min_replicas < 2:
        reasons.append("minReplicas < 2")
    if isinstance(min_replicas, int) and isinstance(max_replicas, int) and max_replicas < min_replicas:
        reasons.append("maxReplicas < minReplicas")
    if any(reason in reasons for reason in ["maxReplicas missing or invalid", "maxReplicas > 50", "minReplicas invalid", "minReplicas < 1", "maxReplicas < minReplicas"]):
        return "FAIL", "high", {"minReplicas": min_replicas, "maxReplicas": max_replicas, "reasons": reasons}
    if reasons:
        return "WARN", "medium", {"minReplicas": min_replicas, "maxReplicas": max_replicas, "reasons": reasons}
    return "PASS", "info", {"minReplicas": min_replicas, "maxReplicas": max_replicas, "reasons": []}


def _resourcequota_evidence(index: ResourceIndex, namespace: str, max_replicas: int | None = None) -> dict[str, Any]:
    quotas = [quota for quota in index.by_kind("ResourceQuota") if _ns_name(quota) == namespace]
    quality = _resourcequota_quality(quotas)
    rows: list[dict[str, Any]] = []
    pod_quotas: list[int] = []
    for quota in quotas:
        hard = quota.get("spec", {}).get("hard", {}) or {}
        pod_quota = _intish(hard.get("pods"))
        if pod_quota is not None:
            pod_quotas.append(pod_quota)
        rows.append(
            {
                "name": _meta(quota).get("name"),
                "hard": hard,
                "pods": pod_quota,
                "covered": [key for key in RESOURCEQUOTA_REQUIRED_HARD if key in hard],
            }
        )
    min_pod_quota = min(pod_quotas) if pod_quotas else None
    reasons: list[str] = []
    if quality["missing"]:
        reasons.append("ResourceQuota missing required hard limits: " + ", ".join(quality["missing"]))
    if min_pod_quota is None:
        reasons.append("pods quota missing or invalid")
    high_hpa_max = isinstance(max_replicas, int) and max_replicas > 50
    pod_quota_caps_high_hpa = not high_hpa_max or (min_pod_quota is not None and min_pod_quota <= 50)
    if high_hpa_max and not pod_quota_caps_high_hpa:
        reasons.append("pods quota does not cap abnormal HPA maxReplicas")
    return {
        "namespace": namespace,
        "quotas": rows,
        "quality": quality,
        "has_pod_quota": min_pod_quota is not None,
        "has_compute_quota": all(key in quality["covered"] for key in ("requests.cpu", "requests.memory", "limits.cpu", "limits.memory")),
        "min_pod_quota": min_pod_quota,
        "hpa_max_replicas": max_replicas,
        "pod_quota_caps_high_hpa": pod_quota_caps_high_hpa,
        "reasons": reasons,
        "complete": not reasons,
    }


def check_scaling_behavior_defense(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for hpa in index.by_kind("HorizontalPodAutoscaler"):
        status, severity, bounds = _hpa_bounds_status(hpa)
        findings.append(_finding(task_id, "CN-26", "CN-ELAS-004-hpa-max", f"{_asset(hpa).key} HPA 副本边界检查", status, severity, _asset(hpa), Evidence("HPA 应设置合理 minReplicas/maxReplicas，避免异常扩容或单副本弹性窗口", _asset(hpa), "spec.minReplicas/spec.maxReplicas", bounds, "minReplicas>=2 and maxReplicas<=50"), "结合 ResourceQuota 设置合理 minReplicas/maxReplicas。"))
        quota = _resourcequota_evidence(index, _ns_name(hpa), bounds.get("maxReplicas"))
        tier = _namespace_tier_for_name(index, _ns_name(hpa))
        quota_ok = quota["complete"]
        if quota_ok:
            quota_status: FindingStatus = "PASS"
            quota_severity: Severity = "info"
        elif tier in {"business", "demo-risk"}:
            quota_status = "FAIL"
            quota_severity = "high"
        else:
            quota_status = "WARN"
            quota_severity = "medium"
        findings.append(_finding(task_id, "CN-26", "CN-ELAS-004-resourcequota-guardrail", f"{_asset(hpa).key} ResourceQuota 扩容护栏检查", quota_status, quota_severity, _asset(hpa), Evidence("HPA 所在 namespace 应有完整 pods 与 CPU/Memory requests/limits ResourceQuota；当 HPA maxReplicas 过高时，pods quota 应形成二级上限", _asset(hpa), "ResourceQuota.spec.hard", quota, "pods, requests.cpu, requests.memory, limits.cpu, limits.memory; high maxReplicas capped by pods quota <= 50"), "为启用 HPA 的业务 namespace 配置完整 pods、requests.cpu、requests.memory、limits.cpu、limits.memory ResourceQuota；对高 maxReplicas 场景设置能实际限制异常扩容的 pods quota。"))
    scale_risks = []
    for role in index.by_kind("Role") + index.by_kind("ClusterRole"):
        for rule in role.get("rules", []) or []:
            resources = set(rule.get("resources") or [])
            verbs = set(rule.get("verbs") or [])
            scale_resource = any(resource in {"*", "deployments/scale", "statefulsets/scale", "replicasets/scale"} or str(resource).endswith("/scale") for resource in resources)
            if scale_resource and verbs & {"*", "update", "patch"}:
                scale_risks.append({"role": _asset(role).key, "resources": sorted(resources), "verbs": sorted(verbs), "system_managed": _scale_role_system_managed(index, role)})
    business_scale_risks = [row for row in scale_risks if not row["system_managed"]]
    system_scale_review = [row for row in scale_risks if row["system_managed"]]
    if business_scale_risks:
        rbac_status: FindingStatus = "FAIL"
        rbac_severity: Severity = "high"
    elif system_scale_review:
        rbac_status = "NOT_APPLICABLE"
        rbac_severity = "info"
    else:
        rbac_status = "PASS"
        rbac_severity = "info"
    findings.append(_cluster_finding(task_id, "CN-26", "CN-ELAS-004-scale-rbac", "scale 子资源权限检查", rbac_status, rbac_severity, "具备 scale 修改权限的角色", {"business_scale_risks": business_scale_risks, "system_scale_review": system_scale_review, "total": len(scale_risks)}, "only trusted autoscaler/CI roles can update scale", "限制 deployments/scale/statefulsets/scale update/patch 权限，仅授予 CI/CD 或自动伸缩控制器；系统内置角色单独复核绑定范围。"))
    scale_events = _scale_events(index)
    findings.append(_cluster_finding(task_id, "CN-26", "CN-ELAS-004-scale-event-source", "扩缩容事件/审计源覆盖检查", "PASS" if scale_events else "UNKNOWN", "info", "识别到的 scale 事件数量", {"scale_event_count": len(scale_events), "source_kinds": sorted({row["source_kind"] for row in scale_events})}, ">0 scale event or audit source", "接入 Kubernetes Event 或 apiserver audit log，用于识别异常扩缩容。"))
    suspicious: list[dict[str, Any]] = []
    grouped: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for row in scale_events:
        key = (row.get("namespace"), row.get("kind"), row.get("name"))
        grouped[key].append(row)
        reasons: list[str] = []
        desired = row.get("desired_replicas")
        current = row.get("current_replicas")
        if isinstance(desired, str) and desired.isdigit():
            desired = int(desired)
        if isinstance(current, str) and current.isdigit():
            current = int(current)
        if isinstance(desired, int) and desired > 50:
            reasons.append("desired replicas > 50")
        if isinstance(desired, int) and isinstance(current, int) and desired - current >= 10:
            reasons.append("replica jump >= 10")
        if row.get("actor") and not _actor_trusted_for_scale(row.get("actor")):
            reasons.append("untrusted scale actor")
        if reasons:
            suspicious.append({**{k: v for k, v in row.items() if k != "timestamp"}, "timestamp": row.get("timestamp").isoformat() if row.get("timestamp") else None, "reasons": reasons})
    for key, rows in grouped.items():
        timed = sorted([row for row in rows if row.get("timestamp")], key=lambda item: item["timestamp"])
        for index_pos, row in enumerate(timed):
            window = [candidate for candidate in timed[index_pos:] if (candidate["timestamp"] - row["timestamp"]).total_seconds() <= 600]
            window_alertworthy = False
            for candidate in window:
                actor = candidate.get("actor")
                desired = candidate.get("desired_replicas")
                current = candidate.get("current_replicas")
                if isinstance(desired, str) and desired.isdigit():
                    desired = int(desired)
                if isinstance(current, str) and current.isdigit():
                    current = int(current)
                if (actor and not _actor_trusted_for_scale(actor)) or (isinstance(desired, int) and desired > 50) or (isinstance(desired, int) and isinstance(current, int) and desired - current >= 10):
                    window_alertworthy = True
                    break
            if len(window) >= 3 and window_alertworthy:
                suspicious.append({"namespace": key[0], "kind": key[1], "name": key[2], "reasons": ["scale changes >= 3 within 10m"], "event_count": len(window), "first_seen": row["timestamp"].isoformat(), "last_seen": window[-1]["timestamp"].isoformat()})
                break
    if scale_events:
        status: FindingStatus = "FAIL" if suspicious else "PASS"
    else:
        status = "UNKNOWN"
    findings.append(_cluster_finding(task_id, "CN-26", "CN-ELAS-004-abnormal-scale-events", "异常扩缩容事件检查", status, "high" if status == "FAIL" else "info", "Event/AuditLog 中的异常 scale 行为", suspicious, "no untrusted actor, high replica target, burst scale window", "启用审计日志并告警：非 CI/CD/HPA 主体修改 scale、短时间频繁扩缩、目标副本数异常增大。"))
    return findings


def check_lifecycle_governance(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for job in index.by_kind("Job"):
        ttl = job.get("spec", {}).get("ttlSecondsAfterFinished")
        ttl_ok = isinstance(_intish(ttl), int) and _intish(ttl) > 0
        tier = _namespace_tier_for_name(index, _ns_name(job))
        strict_lifecycle = tier in {"business", "demo-risk"}
        if ttl_ok:
            status: FindingStatus = "PASS"
            severity: Severity = "info"
        elif tier == "platform":
            status = "NOT_APPLICABLE"
            severity = "info"
        elif strict_lifecycle:
            status = "FAIL"
            severity = "medium"
        else:
            status = "WARN"
            severity = "low"
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-job-ttl", f"{_asset(job).key} Job 生命周期检查", status, severity, _asset(job), Evidence("Job 完成后应自动清理；业务/demo-risk Job 缺少 TTL 表示弹性资源残留风险", _asset(job), "spec.ttlSecondsAfterFinished", {"tier": tier, "ttlSecondsAfterFinished": ttl}, ">0"), "设置 ttlSecondsAfterFinished。"))
    for cronjob in index.by_kind("CronJob"):
        spec = cronjob.get("spec", {}) or {}
        history = {
            "successfulJobsHistoryLimit": spec.get("successfulJobsHistoryLimit"),
            "failedJobsHistoryLimit": spec.get("failedJobsHistoryLimit"),
            "concurrencyPolicy": spec.get("concurrencyPolicy"),
        }
        reasons: list[str] = []
        if not isinstance(history["successfulJobsHistoryLimit"], int) or history["successfulJobsHistoryLimit"] > 3:
            reasons.append("successfulJobsHistoryLimit missing or > 3")
        if not isinstance(history["failedJobsHistoryLimit"], int) or history["failedJobsHistoryLimit"] > 3:
            reasons.append("failedJobsHistoryLimit missing or > 3")
        if history["concurrencyPolicy"] not in {"Forbid", "Replace"}:
            reasons.append("concurrencyPolicy allows overlapping jobs")
        ok = (
            isinstance(history["successfulJobsHistoryLimit"], int)
            and history["successfulJobsHistoryLimit"] <= 3
            and isinstance(history["failedJobsHistoryLimit"], int)
            and history["failedJobsHistoryLimit"] <= 3
            and history["concurrencyPolicy"] in {"Forbid", "Replace"}
        )
        tier = _namespace_tier_for_name(index, _ns_name(cronjob))
        strict_lifecycle = tier in {"business", "demo-risk"}
        status = "PASS" if ok else "FAIL" if strict_lifecycle else "WARN"
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-cronjob-retention", f"{_asset(cronjob).key} CronJob 保留策略检查", status, "medium" if status != "PASS" else "info", _asset(cronjob), Evidence("CronJob 应限制历史任务并避免无限并发；业务/demo-risk CronJob 缺少保留策略会造成 Job/Pod 残留", _asset(cronjob), "spec", {"tier": tier, **history, "reasons": reasons}, "history<=3 and concurrencyPolicy Forbid/Replace"), "设置 successfulJobsHistoryLimit/failedJobsHistoryLimit，并将 concurrencyPolicy 设置为 Forbid 或 Replace。"))
    for ns in index.by_kind("Namespace"):
        meta = _meta(ns)
        terminating = bool(meta.get("deletionTimestamp") and meta.get("finalizers"))
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-namespace-finalizer", f"{_asset(ns).key} Namespace 终止状态检查", "FAIL" if terminating else "PASS", "medium", _asset(ns), Evidence("Namespace 不应长期卡在 terminating/finalizer 状态", _asset(ns), "metadata.deletionTimestamp/finalizers", {"deletionTimestamp": meta.get("deletionTimestamp"), "finalizers": meta.get("finalizers")}, "no stuck finalizers"), "排查并清理阻塞 namespace 删除的 finalizer 或残留资源。"))
    bound_pvcs: set[tuple[str | None, str]] = set()
    for obj in index.by_kind("Pod") + _workloads(index) + index.by_kind("Job") + index.by_kind("CronJob"):
        namespace = _ns_name(obj)
        for claim_name in _claim_names_for_obj(obj):
            bound_pvcs.add((namespace, claim_name))
    for pvc in index.by_kind("PersistentVolumeClaim"):
        asset = _asset(pvc)
        owner_refs = _meta(pvc).get("ownerReferences") or []
        backup_evidence = _backup_snapshot_evidence(index, asset.namespace, asset.name)
        used = (asset.namespace, asset.name) in bound_pvcs
        retained = used or bool(owner_refs) or bool(backup_evidence)
        tier = _namespace_tier_for_name(index, asset.namespace)
        status = "PASS" if retained else "FAIL" if tier in {"business", "demo-risk"} else "WARN"
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-orphan-pvc", f"{asset.key} PVC 残留检查", status, "medium" if status != "PASS" else "info", asset, Evidence("PVC 应有关联 Pod/Workload、ownerReference 或备份/快照策略，避免弹性资源释放后数据残留无人负责", asset, "metadata.name/ownerReferences/VolumeSnapshot", {"tier": tier, "referenced": used, "ownerReferences": owner_refs, "backup_evidence": backup_evidence}, "referenced, owned, or backup evidence present"), "清理孤儿 PVC，或补充 ownerReference、保留原因标注和备份/快照策略。"))
    for pv in index.by_kind("PersistentVolume"):
        phase = pv.get("status", {}).get("phase")
        stale = phase in {"Released", "Failed"}
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-stale-pv", f"{_asset(pv).key} PV 回收状态检查", "WARN" if stale else "PASS", "medium", _asset(pv), Evidence("PV Released/Failed 状态可能表示残留数据或回收失败", _asset(pv), "status.phase", phase, "Available/Bound or documented retention"), "确认 PV 回收策略、清理残留数据，或标注保留原因。"))
    pods = index.by_kind("Pod")
    for service in index.by_kind("Service"):
        service_type = service.get("spec", {}).get("type")
        has_selector = bool(service.get("spec", {}).get("selector"))
        selects_pod = _service_selects_pod(service, pods) if has_selector else True
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-orphan-service", f"{_asset(service).key} Service 选择器检查", "PASS" if selects_pod else "FAIL", "medium", _asset(service), Evidence("Service selector 应匹配存活 Pod，避免入口残留", _asset(service), "spec.selector", service.get("spec", {}).get("selector"), "selector matches pods"), f"确认 {service_type or 'ClusterIP'} Service 是否仍需保留；无后端时清理或修正 selector。"))
    service_names_by_ns = {(_ns_name(service), _meta(service).get("name")) for service in index.by_kind("Service")}
    for ingress in index.by_kind("Ingress"):
        backends = _ingress_backend_services(ingress)
        missing = sorted(name for name in backends if (_ns_name(ingress), name) not in service_names_by_ns)
        findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-orphan-ingress", f"{_asset(ingress).key} Ingress 后端检查", "PASS" if not missing else "FAIL", "medium", _asset(ingress), Evidence("Ingress backend 应引用存在的 Service", _asset(ingress), "spec.rules[].http.paths[].backend.service.name", missing, "all backend services exist"), "清理无后端 Ingress 或修正 backend service。"))
    for pod in pods:
        owner_refs = _meta(pod).get("ownerReferences") or []
        phase = pod.get("status", {}).get("phase")
        standalone = not owner_refs and _ns_name(pod) not in {"kube-system", "kube-public", "kube-node-lease"}
        completed = phase in {"Succeeded", "Failed"}
        if standalone or completed:
            tier = _namespace_tier_for_name(index, _ns_name(pod))
            status = "FAIL" if tier in {"business", "demo-risk"} else "WARN"
            findings.append(_finding(task_id, "CN-27", "CN-ELAS-005-pod-owner-lifecycle", f"{_asset(pod).key} Pod owner/lifecycle 检查", status, "medium" if status == "FAIL" else "low", _asset(pod), Evidence("业务 Pod 应由控制器管理，完成态 Pod 应被清理", _asset(pod), "metadata.ownerReferences/status.phase", {"tier": tier, "ownerReferences": owner_refs, "phase": phase, "standalone": standalone, "completed": completed}, "controller-owned active pod"), "使用 Deployment/Job/CronJob 管理 Pod，并清理完成态或孤儿 Pod。"))
    if not findings:
        findings.append(_cluster_finding(task_id, "CN-27", "CN-ELAS-005-no-lifecycle-objects", "生命周期对象采集检查", "UNKNOWN", "info", "未采集 Job/PVC", [], "Job/PVC objects", "扩大采集范围。"))
    return findings


def check_authentication_mechanisms(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    anon_bindings = []
    anon_public_review = []
    for binding in index.by_kind("RoleBinding") + index.by_kind("ClusterRoleBinding"):
        for subject in binding.get("subjects", []) or []:
            if subject.get("name") in {"system:anonymous", "system:unauthenticated"}:
                binding_key = _asset(binding).key
                binding_name = _meta(binding).get("name", "")
                binding_ns = _ns_name(binding)
                safe_public_binding = (
                    (binding.get("kind"), binding_ns, binding_name) == ("RoleBinding", "kube-public", "kubeadm:bootstrap-signer-clusterinfo")
                    or (binding.get("kind"), None, binding_name) == ("ClusterRoleBinding", None, "system:public-info-viewer")
                )
                row = {
                    "binding": binding_key,
                    "subject": subject.get("name"),
                    "namespace": binding_ns,
                    "roleRef": binding.get("roleRef"),
                }
                if safe_public_binding:
                    row["reason"] = "read-only public discovery/bootstrap exception"
                    anon_public_review.append(row)
                else:
                    anon_bindings.append(row)
    anon_status: FindingStatus = "FAIL" if anon_bindings else "NOT_APPLICABLE" if anon_public_review else "PASS"
    anon_severity: Severity = "critical" if anon_bindings else "info"
    findings.append(_cluster_finding(task_id, "CN-28", "CN-IAM-001-anonymous-binding", "匿名主体绑定检查", anon_status, anon_severity, "匿名/未认证主体绑定", {"dangerous_bindings": anon_bindings, "public_discovery_review": anon_public_review}, [], "删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding；仅保留经论证的公开发现/引导只读例外。"))
    for subject in _auth_subjects(index):
        status, severity, observed = _sa_token_status(index, subject)
        findings.append(
            _finding(
                task_id,
                "CN-28",
                "CN-IAM-001-sa-token-automount",
                f"{_asset(subject).key} SA token 自动挂载检查",
                status,
                severity,
                _asset(subject),
                Evidence(
                    "业务 workload 默认不应自动挂载 ServiceAccount token；平台控制器按 API 访问需求单独复核，controller 管理的 Pod 由其 workload 模板代表",
                    _asset(subject),
                    "spec.automountServiceAccountToken/serviceAccount.automountServiceAccountToken",
                    observed,
                    "effective automount false for business workloads",
                ),
                "不需要访问 API 的 workload 设置 automountServiceAccountToken=false；需要 API 权限的组件记录用途并最小化 RBAC。",
            )
        )
    mtls = [obj for obj in index.objects if obj.get("kind") == "PeerAuthentication"]
    strict = any(obj.get("spec", {}).get("mtls", {}).get("mode") == "STRICT" for obj in mtls)
    mtls_status: FindingStatus = "PASS" if strict else "NOT_APPLICABLE" if not mtls else "WARN"
    mtls_severity: Severity = "info" if mtls_status in {"PASS", "NOT_APPLICABLE"} else "medium"
    findings.append(_cluster_finding(task_id, "CN-28", "CN-IAM-001-mtls-strict", "服务网格 mTLS STRICT 检查", mtls_status, mtls_severity, "Istio PeerAuthentication STRICT", {"peer_authentication_count": len(mtls), "strict": strict}, True, "如使用 Istio，应启用 STRICT mTLS；未安装 Istio 时标注为不适用。"))
    api_args, api_sources, api_source_type = _control_plane_args(index, "kube-apiserver")
    api_flags = _parse_cli_flags(api_args)
    authn_observed = {
        "source_type": api_source_type,
        "source_count": len(api_sources),
        "flags_seen": sorted(api_flags),
        "oidc_issuer_url": api_flags.get("oidc-issuer-url"),
        "oidc_client_id": api_flags.get("oidc-client-id"),
        "authentication_config": api_flags.get("authentication-config"),
        "authentication_token_webhook_config_file": api_flags.get("authentication-token-webhook-config-file"),
        "requestheader_client_ca_file": api_flags.get("requestheader-client-ca-file"),
        "proxy_client_cert_file": api_flags.get("proxy-client-cert-file"),
        "proxy_client_key_file": api_flags.get("proxy-client-key-file"),
        "client_ca_file": api_flags.get("client-ca-file"),
        "service_account_issuer": api_flags.get("service-account-issuer"),
    }
    has_oidc = bool(authn_observed["oidc_issuer_url"] and authn_observed["oidc_client_id"])
    has_external_auth = bool(
        has_oidc
        or authn_observed["authentication_config"]
        or authn_observed["authentication_token_webhook_config_file"]
        or (
            authn_observed["requestheader_client_ca_file"]
            and authn_observed["proxy_client_cert_file"]
            and authn_observed["proxy_client_key_file"]
        )
    )
    if has_external_auth:
        authn_status: FindingStatus = "PASS"
        authn_reason = "external authn evidence collected from kube-apiserver flags"
    elif api_sources and (authn_observed["client_ca_file"] or authn_observed["service_account_issuer"]):
        authn_status = "NOT_APPLICABLE"
        authn_reason = "cluster uses built-in client cert/service-account auth; no external IdP configured"
    elif any(source.get("kind") == "ControlPlaneManifest" for source in api_sources):
        authn_status = "WARN"
        authn_reason = "static apiserver manifest collected but no OIDC/external auth evidence found"
    else:
        authn_status = "UNKNOWN"
        authn_reason = "no kube-apiserver authn evidence collected"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-28",
            "CN-IAM-001-external-auth-evidence",
            "OIDC/外部认证证据检查",
            authn_status,
            "info" if authn_status in {"PASS", "NOT_APPLICABLE"} else "medium",
            "kube-apiserver 应提供 OIDC、webhook、front-proxy 或明确的本地认证依据",
            {**authn_observed, "has_oidc": has_oidc, "has_external_auth": has_external_auth, "reason": authn_reason},
            "OIDC/external auth configured or local auth basis documented from apiserver flags",
            "如需企业统一身份，配置 OIDC/webhook/front-proxy；否则至少保留 apiserver client CA 与 service-account issuer 等本地认证依据。",
        )
    )
    secure_port = _intish(api_flags.get("secure-port"))
    if secure_port is None and api_sources:
        secure_port = 6443
    insecure_port = _intish(api_flags.get("insecure-port"))
    insecure_enabled = bool((insecure_port or 0) > 0 or api_flags.get("insecure-bind-address"))
    tls_observed = {
        "source_type": api_source_type,
        "source_count": len(api_sources),
        "flags_seen": sorted(api_flags),
        "client-ca-file": api_flags.get("client-ca-file"),
        "tls-cert-file": api_flags.get("tls-cert-file"),
        "tls-private-key-file": api_flags.get("tls-private-key-file"),
        "secure_port": secure_port,
        "insecure_port": insecure_port,
        "insecure_bind_address": api_flags.get("insecure-bind-address"),
    }
    has_tls = bool(tls_observed["tls-cert-file"] and tls_observed["tls-private-key-file"] and secure_port and secure_port > 0 and not insecure_enabled)
    if has_tls:
        tls_status: FindingStatus = "PASS"
        tls_reason = "apiserver TLS cert/key and secure port evidence collected"
    elif any(source.get("kind") == "ControlPlaneManifest" for source in api_sources):
        tls_status = "FAIL"
        tls_reason = "static apiserver manifest collected but TLS evidence is incomplete or insecure serving is enabled"
    elif api_sources:
        tls_status = "WARN"
        tls_reason = "apiserver evidence is partial and does not prove TLS-only serving"
    else:
        tls_status = "UNKNOWN"
        tls_reason = "no kube-apiserver serving evidence collected"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-28",
            "CN-IAM-001-apiserver-tls",
            "API Server TLS 证据检查",
            tls_status,
            "info" if tls_status == "PASS" else "high" if tls_status == "FAIL" else "medium",
            "kube-apiserver 应提供 TLS 证书、私钥和 secure-port 证据，且不应启用 insecure 监听",
            {**tls_observed, "has_tls": has_tls, "reason": tls_reason},
            "tls-cert-file, tls-private-key-file, secure-port>0, no insecure-port",
            "确保 kube-apiserver 使用 TLS 证书/私钥并仅暴露 secure-port；禁用任何 insecure 监听。",
        )
    )
    return findings


def check_dynamic_access_control(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings: list[Finding] = []
    matrix = build_rbac_matrix(index)
    business_rows = matrix.get("business_dangerous_rows", [])
    system_rows = matrix.get("system_dangerous_rows", [])
    expiry_missing_rows = matrix.get("expiry_missing_rows", [])
    resource_coverage = matrix.get("required_resource_coverage", {})
    query_summary = _permission_query_summary(matrix)
    missing_resources = resource_coverage.get("missing_resources", [])
    if matrix.get("summary", {}).get("matrix_row_count", 0) == 0:
        coverage_status: FindingStatus = "UNKNOWN"
        coverage_severity: Severity = "medium"
    elif missing_resources:
        coverage_status = "WARN"
        coverage_severity = "medium"
    else:
        coverage_status = "PASS"
        coverage_severity = "info"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-29",
            "CN-IAM-002-permission-matrix-coverage",
            "主体-资源-动作权限矩阵覆盖检查",
            coverage_status,
            coverage_severity,
            "RBAC 矩阵应覆盖 Pod/Service/ConfigMap/Secret/Ingress/Namespace 并支持按主体/资源查询",
            resource_coverage,
            "required resource coverage complete",
            "补充 Role/ClusterRole/Binding 采集权限，确保权限矩阵覆盖 Pod、Service、ConfigMap、Secret、Ingress、Namespace 等标书关注对象。",
        )
    )
    findings.append(
        _cluster_finding(
            task_id,
            "CN-29",
            "CN-IAM-002-permission-queryability",
            "主体/资源权限查询能力检查",
            "PASS" if query_summary["queryable"] else "UNKNOWN",
            "info" if query_summary["queryable"] else "medium",
            "权限矩阵应支持按 subject/resource/verb/binding/role/scope 维度查询，便于定位过度授权和提权路径",
            query_summary,
            "matrix query by subject/resource available",
            "保留 RBAC rows 明细，并在报告/UI 中支持按主体、资源和动作用例检索权限。",
        )
    )
    for row in business_rows[:50]:
        asset = AssetRef(
            kind=row.get("binding_kind", "Binding"),
            name=row.get("binding_name", "unknown"),
            namespace=row.get("binding_namespace"),
            labels={"subject": row.get("subject", "unknown"), "role": f"{row.get('role_kind')}/{row.get('role_name')}"},
        )
        severity: Severity = "critical" if row.get("risk_level") == "critical" else "high"
        findings.append(
            _finding(
                task_id,
                "CN-29",
                "CN-IAM-002-dangerous-rbac",
                f"{row.get('subject')} 高危 RBAC 授权",
                "FAIL",
                severity,
                asset,
                Evidence(
                    "绑定后的主体权限矩阵发现业务/非系统主体高危授权",
                    asset,
                    "rbac_matrix.rows[]",
                    {
                        "subject": row.get("subject"),
                        "role": f"{row.get('role_kind')}/{row.get('role_name')}",
                        "binding": f"{row.get('binding_kind')}/{row.get('binding_namespace') or '_cluster'}/{row.get('binding_name')}",
                        "resources": row.get("resources"),
                        "verbs": row.get("verbs"),
                        "aggregation_source_role": row.get("aggregation_source_role"),
                        "danger_reasons": row.get("danger_reasons"),
                        "risk_level": row.get("risk_level"),
                    },
                    "least privilege and scoped subject",
                ),
                "移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限；避免绑定 system:authenticated 等宽泛主体。",
            )
        )
    if not business_rows:
        findings.append(_cluster_finding(task_id, "CN-29", "CN-IAM-002-dangerous-rbac", "业务主体高危 RBAC 授权检查", "PASS", "info", "未发现绑定到业务/非系统主体的高危 RBAC 规则", matrix.get("summary", {}), "0 business dangerous rows", "持续按最小权限审计 RBAC。"))
    if system_rows:
        findings.append(
            _cluster_finding(
                task_id,
                "CN-29",
                "CN-IAM-002-system-rbac-review",
                "系统控制器高危 RBAC 权限复核",
                "NOT_APPLICABLE",
                "info",
                "系统组件/安全组件存在高危能力，作为运行所需权限单独复核，不计为业务 critical",
                {
                    "count": len(system_rows),
                    "sample": [
                        {
                            "subject": row.get("subject"),
                            "role": f"{row.get('role_kind')}/{row.get('role_name')}",
                            "resources": row.get("resources"),
                            "verbs": row.get("verbs"),
                            "danger_reasons": row.get("danger_reasons"),
                        }
                        for row in system_rows[:10]
                    ],
                },
                "documented system controller permissions",
                "保留 kube-system/Kyverno/Trivy/Calico 等控制器权限白名单依据，升级组件时重新复核。",
            )
        )
    else:
        findings.append(_cluster_finding(task_id, "CN-29", "CN-IAM-002-system-rbac-review", "系统控制器高危 RBAC 权限复核", "PASS", "info", "未发现系统控制器高危授权", [], [], "持续复核系统组件权限。"))
    if expiry_missing_rows:
        findings.append(
            _cluster_finding(
                task_id,
                "CN-29",
                "CN-IAM-002-temporary-grant-expiry",
                "临时/高危授权过期标记检查",
                "WARN",
                "high",
                "高危业务授权缺少 expires/ttl 等过期标记",
                [
                    {
                        "subject": row.get("subject"),
                        "binding": f"{row.get('binding_kind')}/{row.get('binding_namespace') or '_cluster'}/{row.get('binding_name')}",
                        "role": f"{row.get('role_kind')}/{row.get('role_name')}",
                        "risk_level": row.get("risk_level"),
                        "expiry_marker": row.get("expiry_marker"),
                        "role_expiry_marker": row.get("role_expiry_marker"),
                        "effective_expiry_marker": row.get("effective_expiry_marker"),
                    }
                    for row in expiry_missing_rows[:20]
                ],
                "valid future expiry annotation for temporary/high-risk grants",
                "为临时或高危授权添加可解析且未过期的 expires-at 注解，并由准入策略或定时清理任务回收。",
            )
        )
    else:
        findings.append(_cluster_finding(task_id, "CN-29", "CN-IAM-002-temporary-grant-expiry", "临时/高危授权过期标记检查", "PASS", "info", "未发现缺少过期标记的高危业务授权", [], [], "继续要求高危临时授权带过期标记。"))
    context_policy = _context_policy_summary(index)
    context_status: FindingStatus = "PASS" if context_policy["context_policy_count"] else "WARN"
    findings.append(_cluster_finding(task_id, "CN-29", "CN-IAM-002-context-policy", "动态上下文准入策略检查", context_status, "medium", "准入策略应包含 namespace/label/env/subject 等动态上下文条件", context_policy, "context-aware admission policy present", "增加基于 namespace、label、env/tenant、userInfo/subject 的准入控制策略。"))
    return findings


def check_identity_hardening(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings = []
    ssh_services = []
    for service in index.by_kind("Service"):
        ports = service.get("spec", {}).get("ports", []) or []
        exposed_ssh = any((p.get("port") == 22 or p.get("targetPort") == 22 or str(p.get("name", "")).lower() == "ssh") for p in ports)
        if exposed_ssh:
            ssh_services.append(_asset(service).key)
        findings.append(_finding(task_id, "CN-30", "CN-IAM-003-no-ssh-service", f"{_asset(service).key} SSH Service 暴露检查", "FAIL" if exposed_ssh else "PASS", "high", _asset(service), Evidence("身份安全强化要求不暴露 SSH 服务", _asset(service), "spec.ports", ports, "no tcp/22"), "移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。"))
    ssh_pods = []
    for obj in index.by_kind("Pod") + _workloads(index):
        for container in _containers(obj):
            ports = container.get("ports", []) or []
            args = " ".join((container.get("command") or []) + (container.get("args") or []))
            exposes_ssh = any(p.get("containerPort") == 22 or str(p.get("name", "")).lower() == "ssh" for p in ports) or "sshd" in args.lower()
            if exposes_ssh:
                ssh_pods.append(_asset(obj).key)
                findings.append(_finding(task_id, "CN-30", "CN-IAM-003-no-ssh-container", f"{_asset(obj).key} SSH 容器暴露检查", "FAIL", "high", _asset(obj), Evidence("容器不应运行 sshd 或暴露 22 端口", _asset(obj), "containers[].ports/args", {"ports": ports, "args": args}, "no sshd/tcp22"), "删除容器内 sshd，使用 Kubernetes 原生审计访问路径。"))
    if not ssh_pods:
        findings.append(_cluster_finding(task_id, "CN-30", "CN-IAM-003-no-ssh-container", "SSH 容器暴露检查", "PASS", "info", "未发现暴露 22 端口或 sshd 的容器", [], [], "持续禁止镜像内置 sshd。"))
    falco_events = _falco_events(index)
    auth_events = _authlog_events(index)
    audit_events = index.by_kind("AuditLogEvent")
    auth_sources = index.by_kind("AuthLogSource")
    falco_running = any(obj.get("kind") in {"Pod", "DaemonSet"} and _ns_name(obj) == "falco" for obj in index.objects)
    brute_force_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in auth_events:
        if event.get("event_type") == "ssh_failed_password":
            brute_force_by_ip[str(event.get("remote_ip", "unknown"))].append(event)
    for remote_ip, events in sorted(brute_force_by_ip.items()):
        if len(events) >= 3:
            findings.append(_finding(task_id, "CN-30", "CN-IAM-003-authlog-ssh-bruteforce", f"{remote_ip} SSH 暴破行为", "FAIL", "high", _asset(events[0]), Evidence("auth.log 识别到同一来源多次 SSH 登录失败", _asset(events[0]), "AuthLogEvent.remote_ip", {"remote_ip": remote_ip, "failed_count": len(events), "users": sorted({event.get("user") for event in events})}, "<3 failures/source"), "封禁来源 IP，关闭节点 SSH 暴露，改用堡垒机或受审计的临时访问。"))
    login_risks: list[dict[str, Any]] = []
    incidents: list[dict[str, Any]] = []
    for event in auth_events:
        event_type = str(event.get("event_type") or "")
        auth_method = str(event.get("auth_method") or "")
        remote_ip = str(event.get("remote_ip") or "")
        user = str(event.get("user") or "")
        private_ip = False
        try:
            ip_obj = ipaddress.ip_address(remote_ip)
            private_ip = bool(ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
        except ValueError:
            private_ip = False
        reasons: list[str] = []
        if "accepted" in event_type or "success" in event_type or event.get("outcome") == "success":
            if auth_method.lower() == "password" or "password" in event_type:
                reasons.append("ssh password login succeeded")
            if user == "root":
                reasons.append("root login succeeded")
            if remote_ip and not private_ip:
                reasons.append("login from public or untrusted remote IP")
        row = {
            "time": event.get("time") or _event_time(event),
            "event_type": event_type,
            "user": user,
            "remote_ip": remote_ip,
            "auth_method": auth_method,
            "asset": _asset(event).key,
            "reasons": reasons,
        }
        incidents.append(row)
        if reasons:
            login_risks.append(row)
    exec_rows: list[dict[str, Any]] = []
    exec_risks: list[dict[str, Any]] = []
    for event in audit_events:
        ref = event.get("objectRef") or {}
        resource = str(ref.get("resource") or event.get("resource") or "").lower()
        subresource = str(ref.get("subresource") or event.get("subresource") or "").lower()
        request_uri = str(event.get("requestURI") or event.get("requestUri") or "").lower()
        if resource not in {"pods", "pods/exec"} and "/exec" not in request_uri:
            continue
        if subresource != "exec" and resource != "pods/exec" and "/exec" not in request_uri:
            continue
        namespace = ref.get("namespace") or _ns_name(event)
        pod_name = ref.get("name") or _meta(event).get("name")
        actor = (event.get("user") or {}).get("username") or event.get("actor")
        tier = _namespace_tier_for_name(index, namespace)
        row = {
            "time": _event_time(event),
            "actor": actor,
            "namespace": namespace,
            "pod": pod_name,
            "resource": resource,
            "subresource": subresource or "exec",
            "requestURI": event.get("requestURI") or event.get("requestUri"),
            "tier": tier,
            "reasons": [],
        }
        incidents.append({**row, "event_type": "pod_exec"})
        exec_rows.append(row)
        if tier != "platform" and not str(actor or "").startswith("system:"):
            row["reasons"] = ["container exec by non-system subject"]
            exec_risks.append(row)
    source_present = bool(falco_events or auth_events or audit_events or auth_sources or falco_running)
    findings.append(
        _cluster_finding(
            task_id,
            "CN-30",
            "CN-IAM-003-identity-incident-ledger",
            "身份安全持续审计事件台账",
            "PASS" if source_present else "UNKNOWN",
            "info" if source_present else "medium",
            "归一化 auth.log、apiserver audit 与 Falco 身份事件，形成连续身份安全台账",
            {
                "source_present": source_present,
                "auth_event_count": len(auth_events),
                "audit_event_count": len(audit_events),
                "falco_event_count": len(falco_events),
                "incidents": incidents[:100],
            },
            "normalized identity incident ledger",
            "持续接入 auth.log、apiserver audit log 或等效身份审计源，保留用户、来源 IP、目标 Pod/节点和时间等关键信息。",
        )
    )
    findings.append(
        _cluster_finding(
            task_id,
            "CN-30",
            "CN-IAM-003-container-exec-audit",
            "容器 exec 审计检查",
            "FAIL" if exec_risks else "PASS" if audit_events else "UNKNOWN",
            "high" if exec_risks else "info" if audit_events else "medium",
            "应能从 audit log 识别容器 exec 行为，并区分业务主体与系统控制器",
            {"audit_event_count": len(audit_events), "exec_events": exec_rows[:50], "risks": exec_risks[:50]},
            "no unapproved business pod exec activity",
            "开启并保留 apiserver audit log；对业务主体的 pod exec 建立审批、告警和过期访问控制。",
        )
    )
    findings.append(
        _cluster_finding(
            task_id,
            "CN-30",
            "CN-IAM-003-abnormal-login",
            "异常登录行为检查",
            "FAIL" if login_risks else "PASS" if (auth_events or auth_sources) else "UNKNOWN",
            "high" if login_risks else "info" if (auth_events or auth_sources) else "medium",
            "应识别 root 登录、口令登录成功、来自公网/未知来源的 SSH 成功登录等异常身份事件",
            {"auth_event_count": len(auth_events), "auth_source_count": len(auth_sources), "risks": login_risks[:50]},
            "no root/password/public-ip SSH success and no repeated failed logins",
            "禁止 root 和口令 SSH 登录；对公网来源、成功登录和暴破行为建立告警与处置流程。",
        )
    )
    findings.append(_cluster_finding(task_id, "CN-30", "CN-IAM-003-falco-or-authlog", "身份安全审计日志源检查", "PASS" if source_present else "UNKNOWN", "info", "Falco/auth/audit 事件或 Falco 工作负载", {"falco_events": len(falco_events), "auth_events": len(auth_events), "audit_events": len(audit_events), "auth_sources": len(auth_sources), "falco_running": falco_running}, "event source configured", "接入 Falco webhook、auth.log 或 audit log 作为持续审计数据源。"))
    return findings


def check_etcd_security(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings = []
    api_args, api_sources, api_source_type = _control_plane_args(index, "kube-apiserver")
    etcd_args, etcd_sources, etcd_source_type = _control_plane_args(index, "etcd")
    api_flags = _parse_cli_flags(api_args)
    etcd_flags = _parse_cli_flags(etcd_args)

    apiserver_sources_summary = [{"kind": source.get("kind"), "name": _meta(source).get("name"), "path": source.get("path")} for source in api_sources]
    etcd_sources_summary = [{"kind": source.get("kind"), "name": _meta(source).get("name"), "path": source.get("path")} for source in etcd_sources]
    api_has_manifest = any(source.get("kind") == "ControlPlaneManifest" for source in api_sources)
    etcd_has_manifest = any(source.get("kind") == "ControlPlaneManifest" for source in etcd_sources)
    if api_has_manifest and etcd_has_manifest:
        source_status: FindingStatus = "PASS"
        source_reason = "apiserver and etcd static pod manifests collected"
    elif api_sources or etcd_sources:
        source_status = "WARN"
        source_reason = "control-plane evidence is partial or mirror-pod-only"
    else:
        source_status = "UNKNOWN"
        source_reason = "no control-plane command evidence collected"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-35",
            "CN-PER-001-control-plane-source",
            "Control-plane static pod 证据源检查",
            source_status,
            "info",
            "kubeadm static pod manifest 或 mirror pod 采集状态",
            {
                "apiserver_sources": apiserver_sources_summary,
                "etcd_sources": etcd_sources_summary,
                "apiserver_static_manifest": api_has_manifest,
                "etcd_static_manifest": etcd_has_manifest,
                "reason": source_reason,
            },
            "static pod manifest preferred",
            "自建集群启用 control-plane collector；托管集群补充云厂商控制面配置证据。",
        )
    )

    etcd_tls_checks = {
        "client_cert_auth": str(etcd_flags.get("client-cert-auth", "")).lower() == "true",
        "peer_client_cert_auth": str(etcd_flags.get("peer-client-cert-auth", "")).lower() == "true",
        "client_urls_https": _all_urls_https(etcd_flags.get("listen-client-urls")),
        "peer_urls_https": _all_urls_https(etcd_flags.get("listen-peer-urls")),
        "cert_file": bool(etcd_flags.get("cert-file")),
        "key_file": bool(etcd_flags.get("key-file")),
        "peer_cert_file": bool(etcd_flags.get("peer-cert-file")),
        "peer_key_file": bool(etcd_flags.get("peer-key-file")),
        "trusted_ca_file": bool(etcd_flags.get("trusted-ca-file")),
        "peer_trusted_ca_file": bool(etcd_flags.get("peer-trusted-ca-file")),
    }
    etcd_evidence_flags = {
        "client-cert-auth": etcd_flags.get("client-cert-auth"),
        "peer-client-cert-auth": etcd_flags.get("peer-client-cert-auth"),
        "listen-client-urls": etcd_flags.get("listen-client-urls"),
        "listen-peer-urls": etcd_flags.get("listen-peer-urls"),
        "cert-file": etcd_flags.get("cert-file"),
        "key-file": etcd_flags.get("key-file"),
        "peer-cert-file": etcd_flags.get("peer-cert-file"),
        "peer-key-file": etcd_flags.get("peer-key-file"),
        "trusted-ca-file": etcd_flags.get("trusted-ca-file"),
        "peer-trusted-ca-file": etcd_flags.get("peer-trusted-ca-file"),
    }
    etcd_tls_ok = all(etcd_tls_checks.values())
    findings.append(
        _cluster_finding(
            task_id,
            "CN-35",
            "CN-PER-001-etcd-tls",
            "etcd TLS/client-cert-auth 检查",
            _control_plane_evidence_status(etcd_sources, etcd_has_manifest, etcd_tls_ok),
            "high",
            f"etcd flags from {etcd_source_type}",
            {"checks": etcd_tls_checks, "flags": etcd_evidence_flags, "static_manifest": etcd_has_manifest, "reason": "complete etcd TLS/cert evidence present" if etcd_tls_ok else "partial control-plane evidence lacks complete etcd TLS flags" if etcd_sources and not etcd_has_manifest else "static pod manifest lacks complete etcd TLS flags" if etcd_sources else "no etcd command evidence collected"},
            "client/peer TLS and cert auth enabled",
            "启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。",
        )
    )

    api_etcd_checks = {
        "etcd_servers_https": _all_urls_https(api_flags.get("etcd-servers")),
        "etcd_cafile": bool(api_flags.get("etcd-cafile")),
        "etcd_certfile": bool(api_flags.get("etcd-certfile")),
        "etcd_keyfile": bool(api_flags.get("etcd-keyfile")),
    }
    findings.append(
        _cluster_finding(
            task_id,
            "CN-35",
            "CN-PER-001-apiserver-etcd-client-cert",
            "API Server 到 etcd 双向 TLS 检查",
            _control_plane_evidence_status(api_sources, api_has_manifest, all(api_etcd_checks.values())),
            "high",
            f"kube-apiserver etcd flags from {api_source_type}",
            {"checks": api_etcd_checks, "flags": {key: api_flags.get(key) for key in ["etcd-servers", "etcd-cafile", "etcd-certfile", "etcd-keyfile"]}, "static_manifest": api_has_manifest, "reason": "complete apiserver->etcd TLS flags present" if all(api_etcd_checks.values()) else "partial control-plane evidence lacks complete apiserver->etcd TLS flags" if api_sources and not api_has_manifest else "static pod manifest lacks complete apiserver->etcd TLS flags" if api_sources else "no apiserver command evidence collected"},
            "https etcd endpoint with CA/cert/key",
            "为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。",
        )
    )

    encryption_config = api_flags.get("encryption-provider-config")
    api_source_kinds = sorted({str(source.get("kind", "unknown")) for source in api_sources})
    encryption_validation = _encryption_provider_config_validation(index, str(encryption_config) if encryption_config else None)
    if encryption_config and encryption_validation:
        if encryption_validation["covers_secrets"] and encryption_validation["strong_encryption_present"]:
            encryption_status = "PASS"
            encryption_reason = encryption_validation["reason"]
        else:
            encryption_status = "FAIL"
            encryption_reason = encryption_validation["reason"]
    elif encryption_config:
        encryption_status = "UNKNOWN"
        encryption_reason = "encryption provider config flag present but file content was not collected"
    elif any(source.get("kind") == "ControlPlaneManifest" for source in api_sources):
        encryption_status = "FAIL"
        encryption_reason = "static pod manifest is available and lacks --encryption-provider-config"
    elif api_sources:
        encryption_status = "WARN"
        encryption_reason = "apiserver evidence is partial and lacks --encryption-provider-config"
    else:
        encryption_status = "UNKNOWN"
        encryption_reason = "no apiserver command evidence collected"
    findings.append(
        _cluster_finding(
            task_id,
            "CN-35",
            "CN-PER-001-secret-encryption",
            "Secret 静态加密检查",
            encryption_status,
            "high",
            f"kube-apiserver encryption-provider-config from {api_source_type}",
            {
                "encryption_provider_config": encryption_config,
                "apiserver_flags_seen": sorted(api_flags),
                "apiserver_source_kinds": api_source_kinds,
                "apiserver_sources": apiserver_sources_summary,
                "source_type": api_source_type,
                "config_validation": encryption_validation,
                "reason": encryption_reason,
            },
            "--encryption-provider-config",
            "配置 Kubernetes encryption provider/KMS 加密 Secret。",
        )
    )
    return findings


def check_pv_security(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings = []
    pvcs_by_name_ns = {(_ns_name(pvc), _meta(pvc).get("name")): pvc for pvc in index.by_kind("PersistentVolumeClaim")}
    for sc in index.by_kind("StorageClass"):
        params = sc.get("parameters", {}) or {}
        encrypted = _storageclass_encrypted(sc)
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-storageclass-encryption", f"{_asset(sc).key} 加密参数检查", "PASS" if encrypted else "WARN", "medium", _asset(sc), Evidence("StorageClass 应声明加密/KMS 参数", _asset(sc), "parameters", params, "encryption/KMS enabled"), "为 StorageClass 配置加密参数或记录底层存储默认加密证据。"))
        vbm = sc.get("volumeBindingMode")
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-volume-binding-mode", f"{_asset(sc).key} 绑定模式检查", "PASS" if vbm == "WaitForFirstConsumer" else "WARN", "low", _asset(sc), Evidence("建议使用 WaitForFirstConsumer 降低拓扑错配", _asset(sc), "volumeBindingMode", vbm, "WaitForFirstConsumer"), "设置 volumeBindingMode=WaitForFirstConsumer。"))
        reclaim_policy = sc.get("reclaimPolicy")
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-storageclass-reclaim-policy", f"{_asset(sc).key} 回收策略检查", "PASS" if reclaim_policy == "Retain" else "WARN", "medium", _asset(sc), Evidence("持久化业务 StorageClass 建议使用 Retain 或记录自动删除例外", _asset(sc), "reclaimPolicy", reclaim_policy, "Retain"), "为关键数据 StorageClass 设置 reclaimPolicy=Retain，或记录 Delete 策略的备份和审批依据。"))
        allow_expansion = sc.get("allowVolumeExpansion")
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-volume-expansion", f"{_asset(sc).key} 在线扩容能力检查", "PASS" if allow_expansion is True else "WARN", "low", _asset(sc), Evidence("支持扩容可降低手工迁移和临时挂载风险", _asset(sc), "allowVolumeExpansion", allow_expansion, True), "启用 allowVolumeExpansion，或记录该存储后端不支持扩容的限制。"))
        snapshot_classes = [
            _asset(vsc).key
            for vsc in index.by_kind("VolumeSnapshotClass")
            if not vsc.get("driver") or vsc.get("driver") == sc.get("provisioner")
        ]
        backup_evidence = _backup_snapshot_evidence(index)
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-snapshot-backup-evidence", f"{_asset(sc).key} 快照/备份能力检查", "PASS" if (snapshot_classes or backup_evidence) else "WARN", "medium", _asset(sc), Evidence("StorageClass 应具备 CSI VolumeSnapshotClass、VolumeSnapshot 或 Velero 备份证据", _asset(sc), "VolumeSnapshotClass/Backup/Schedule", {"snapshot_classes": snapshot_classes, "backup_evidence": backup_evidence}, "snapshot or backup evidence"), "部署 CSI 快照类、Velero 备份计划，或补充等效备份平台证据。"))
    for pv in index.by_kind("PersistentVolume"):
        spec = pv.get("spec", {})
        risky = "hostPath" in spec or "local" in spec
        claim_ref = spec.get("claimRef", {}) or {}
        claim_namespace = claim_ref.get("namespace")
        claim_name = claim_ref.get("name")
        bound_pvc = pvcs_by_name_ns.get((claim_namespace, claim_name)) if claim_namespace and claim_name else None
        encrypted = False
        encryption_evidence: dict[str, Any] | None = None
        backup_evidence: list[str] = []
        if bound_pvc:
            encrypted, encryption_evidence = _storageclass_encryption_evidence(index, bound_pvc)
            backup_evidence = _backup_snapshot_evidence(index, claim_namespace, claim_name)
        if risky and not (encrypted and backup_evidence):
            hostpath_status: FindingStatus = "FAIL"
            hostpath_severity: Severity = "high"
        elif risky:
            hostpath_status = "PASS"
            hostpath_severity = "info"
        else:
            hostpath_status = "PASS"
            hostpath_severity = "info"
        findings.append(
            _finding(
                task_id,
                "CN-36",
                "CN-PER-002-hostpath-local-pv",
                f"{_asset(pv).key} PV 类型检查",
                hostpath_status,
                hostpath_severity,
                _asset(pv),
                Evidence(
                    "hostPath/local PV 需要额外隔离和备份证明",
                    _asset(pv),
                    "spec",
                    {
                        "hostPath": spec.get("hostPath"),
                        "local": spec.get("local"),
                        "claimRef": claim_ref,
                        "encrypted": encrypted,
                        "encryption_evidence": encryption_evidence,
                        "backup_evidence": backup_evidence,
                    },
                    "managed encrypted CSI or documented local-PV compensating controls",
                ),
                "优先使用托管加密 CSI 卷；如受限于实验环境必须使用 hostPath/local PV，应补充绑定 PVC 的加密、备份和节点隔离证据。",
            )
        )
        pv_reclaim_policy = spec.get("persistentVolumeReclaimPolicy")
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-pv-reclaim-policy", f"{_asset(pv).key} PV 回收策略检查", "PASS" if pv_reclaim_policy == "Retain" else "WARN", "medium", _asset(pv), Evidence("PV 回收策略应避免误删关键数据", _asset(pv), "spec.persistentVolumeReclaimPolicy", pv_reclaim_policy, "Retain"), "关键业务 PV 使用 Retain；Delete 策略需有自动化备份和恢复演练记录。"))
        access_modes = spec.get("accessModes", []) or []
        rwx = "ReadWriteMany" in access_modes
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-pv-access-mode", f"{_asset(pv).key} PV 访问模式检查", "WARN" if rwx else "PASS", "medium" if rwx else "info", _asset(pv), Evidence("PV 访问模式应遵循最小共享面，RWX 需要额外访问控制", _asset(pv), "spec.accessModes", access_modes, "RWO/RWOP or justified RWX"), "避免不必要的 ReadWriteMany；如需共享读写，补充 namespace、NetworkPolicy 和应用级权限控制。"))
    for pvc in index.by_kind("PersistentVolumeClaim"):
        asset = _asset(pvc)
        encrypted, encryption_evidence = _storageclass_encryption_evidence(index, pvc)
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-pvc-storage-encryption", f"{asset.key} PVC 存储加密继承检查", "PASS" if encrypted else "WARN", "medium", asset, Evidence("PVC 应继承加密/KMS StorageClass", asset, "spec.storageClassName", encryption_evidence, "encrypted StorageClass"), "为 PVC 绑定加密 StorageClass，或补充底层存储默认加密证明。"))
        access_modes = pvc.get("spec", {}).get("accessModes", []) or []
        rwx = "ReadWriteMany" in access_modes
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-pvc-access-mode", f"{asset.key} PVC 访问模式检查", "WARN" if rwx else "PASS", "medium" if rwx else "info", asset, Evidence("PVC 访问模式应遵循最小共享面", asset, "spec.accessModes", access_modes, "RWO/RWOP or justified RWX"), "避免不必要的 ReadWriteMany；共享卷需记录业务理由和隔离控制。"))
        backup_evidence = _backup_snapshot_evidence(index, asset.namespace, asset.name)
        findings.append(_finding(task_id, "CN-36", "CN-PER-002-pvc-backup-evidence", f"{asset.key} PVC 快照/备份证据检查", "PASS" if backup_evidence else "WARN", "medium", asset, Evidence("PVC 应有关联 VolumeSnapshot 或 namespace 级备份计划", asset, "VolumeSnapshot/Backup/Schedule", backup_evidence, "snapshot or backup evidence"), "为关键 PVC 配置 CSI VolumeSnapshot、Velero Schedule，或补充等效备份证据。"))
    if not findings:
        findings.append(_cluster_finding(task_id, "CN-36", "CN-PER-002-no-storage", "存储资源采集检查", "UNKNOWN", "info", "未采集 StorageClass/PV", [], "storage objects", "扩大存储资源采集范围。"))
    return findings


def check_stateful_data_security(index: ResourceIndex, task_id: str) -> list[Finding]:
    findings = []
    network_policies = index.by_kind("NetworkPolicy")
    pvcs_by_name_ns = {(_ns_name(pvc), _meta(pvc).get("name")): pvc for pvc in index.by_kind("PersistentVolumeClaim")}
    workload_inventory: list[dict[str, Any]] = []
    pvc_inventory: list[dict[str, Any]] = []
    for sts in index.by_kind("StatefulSet"):
        asset = _asset(sts)
        ns = _ns_name(sts)
        tier = _namespace_tier_for_name(index, ns)
        np_covers_statefulset, np_evidence = _stateful_networkpolicy_evidence(network_policies, sts)
        np_status: FindingStatus = "PASS" if np_covers_statefulset else _data_control_missing_status(tier)
        np_evidence["tier"] = tier
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-stateful-networkpolicy", f"{asset.key} 网络隔离检查", np_status, "high" if np_status == "FAIL" else "medium" if np_status == "WARN" else "info", asset, Evidence("有状态服务应被 Ingress NetworkPolicy 覆盖，不能只依赖 namespace 内任意策略", asset, "NetworkPolicy.spec.podSelector", np_evidence, "NetworkPolicy selects StatefulSet pods and controls Ingress"), "为数据库/有状态服务配置默认拒绝和精确允许的 NetworkPolicy，确保 podSelector 覆盖对应 StatefulSet。"))
        services = _stateful_services(index, sts)
        exposed_services = [
            {"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP"), "ports": service.get("spec", {}).get("ports", [])}
            for service in services
            if service.get("spec", {}).get("type") in {"NodePort", "LoadBalancer"}
        ]
        if exposed_services:
            service_status: FindingStatus = "FAIL"
            service_reason = "external Service exposure"
        elif services:
            service_status = "PASS"
            service_reason = "ClusterIP/headless Service only"
        else:
            service_status = "WARN"
            service_reason = "no matching Service evidence"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-database-service-exposure", f"{asset.key} 数据库 Service 暴露检查", service_status, "high" if service_status == "FAIL" else "medium" if service_status == "WARN" else "info", asset, Evidence("数据库/有状态服务不应通过 NodePort/LoadBalancer 直接暴露；未匹配到 Service 时作为证据缺口复核", asset, "Service.spec.type", {"services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services], "service_found": bool(services), "exposed": exposed_services, "reason": service_reason}, "ClusterIP/headless service with no NodePort/LoadBalancer exposure"), "将数据库 Service 限制为 ClusterIP/headless，并通过 NetworkPolicy 控制访问来源；未发现关联 Service 时补充服务发现或暴露面证明。"))
        network_exposure = _pod_network_exposure(sts)
        host_exposed = network_exposure["hostNetwork"] or bool(network_exposure["hostPorts"])
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pod-network-exposure", f"{asset.key} Pod 主机网络暴露检查", "FAIL" if host_exposed else "PASS", "high" if host_exposed else "info", asset, Evidence("有状态服务不应通过 hostNetwork/hostPort 绕过 Service 与 NetworkPolicy 暴露", asset, "spec.template.spec.hostNetwork/containers[].ports[].hostPort", network_exposure, {"hostNetwork": False, "hostPorts": []}), "移除 StatefulSet 的 hostNetwork/hostPort；需要节点级端口时使用受控 Service、NetworkPolicy 和审计例外。"))
        has_secret = _has_secret_reference(sts)
        csi_secret_store, csi_evidence = _has_csi_secret_store(sts)
        secret_status: FindingStatus = "PASS" if (has_secret or csi_secret_store) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-secret-reference", f"{asset.key} Secret/CSI 引用检查", secret_status, "high" if secret_status == "FAIL" else "medium", asset, Evidence("有状态服务敏感配置应来自 Secret 或 CSI Secret Store", asset, "podSpec", {"tier": tier, "secret_refs": sorted(_secret_ref_names(sts)), "csi_secret_store": csi_evidence, "reason": "secret or CSI Secret Store present" if secret_status == "PASS" else "business data workload lacks Secret/CSI secret evidence" if secret_status == "FAIL" else "secret evidence missing or incomplete"}, "secretKeyRef/envFrom/secret volume/CSI secret"), "使用 Secret、External Secrets 或 CSI Secret Store 管理数据库口令和证书。"))
        tls_secret, tls_evidence = _tls_secret_refs(index, sts)
        mtls_strict = _mtls_strict_in_namespace(index, ns)
        tls_status: FindingStatus = "PASS" if (tls_secret or mtls_strict) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-tls-or-mtls", f"{asset.key} TLS/mTLS 证据检查", tls_status, "high" if tls_status == "FAIL" else "medium", asset, Evidence("有状态服务应具备 TLS Secret 或服务网格 mTLS STRICT 证据", asset, "Secret.type/PeerAuthentication", {"tier": tier, "tls_secret": tls_evidence, "mtls_strict": mtls_strict, "reason": "TLS Secret or mTLS STRICT present" if tls_status == "PASS" else "business data workload lacks TLS/mTLS evidence" if tls_status == "FAIL" else "TLS/mTLS evidence missing or incomplete"}, "TLS secret or mTLS STRICT"), "为数据库启用 TLS 证书 Secret，或通过服务网格启用 STRICT mTLS。"))
        plaintext = []
        for c in _containers(sts):
            for env in c.get("env", []) or []:
                name = env.get("name", "").lower()
                if any(token in name for token in ["password", "secret", "token", "key"]) and "value" in env:
                    plaintext.append(env.get("name"))
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-no-plaintext-env", f"{asset.key} 明文环境变量检查", "FAIL" if plaintext else "PASS", "high" if plaintext else "info", asset, Evidence("敏感配置不应以明文 env value 暴露", asset, "containers[].env", plaintext, "valueFrom Secret/CSI"), "使用 Secret 引用或 CSI Secret Store，避免明文 env。"))
        claims = sorted(_claim_names_for_obj(sts))
        encryption_evidence = []
        encrypted_claims = 0
        for claim in claims:
            pvc = pvcs_by_name_ns.get((ns, claim))
            if not pvc:
                continue
            encrypted, evidence = _storageclass_encryption_evidence(index, pvc)
            encrypted_claims += int(encrypted)
            encryption_evidence.append({"claim": claim, **evidence})
        if claims and encryption_evidence:
            encryption_ok = encrypted_claims == len(encryption_evidence)
            status: FindingStatus = "PASS" if encryption_ok else _data_control_missing_status(tier)
        else:
            status = "UNKNOWN"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pvc-encryption-evidence", f"{asset.key} PVC 加密证据检查", status, "high" if status == "FAIL" else "medium", asset, Evidence("有状态服务 PVC 应有关联 StorageClass 加密/KMS 证据", asset, "pvc.storageClass.parameters", {"tier": tier, "claims": claims, "encryption_evidence": encryption_evidence, "encrypted_claims": encrypted_claims, "reason": "all referenced PVCs have encryption evidence" if status == "PASS" else "referenced business PVC lacks encryption/KMS evidence" if status == "FAIL" else "PVC encryption evidence unavailable or incomplete"}, "all referenced PVC encrypted or documented"), "为 StatefulSet 使用带加密/KMS 参数的 StorageClass，或补充底层存储默认加密证明。"))
        kms_or_csi = csi_secret_store or any(
            any(
                ("kms" in key.lower() or "key" in key.lower()) and str(value).strip().lower() not in {"", "false", "0", "none", "null"}
                for key, value in (item.get("parameters") or {}).items()
            )
            for item in encryption_evidence
        )
        kms_status: FindingStatus = "PASS" if kms_or_csi else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-kms-or-csi-secret-store", f"{asset.key} KMS/CSI Secret Store 集成检查", kms_status, "high" if kms_status == "FAIL" else "medium", asset, Evidence("有状态服务应具备 KMS 参数或 CSI Secret Store 集成证据", asset, "StorageClass.parameters/volumes[].csi", {"tier": tier, "csi_secret_store": csi_evidence, "encryption_evidence": encryption_evidence, "reason": "KMS or CSI Secret Store evidence present" if kms_status == "PASS" else "business data workload lacks KMS/CSI Secret Store evidence" if kms_status == "FAIL" else "KMS/CSI Secret Store evidence missing or incomplete"}, "KMS key or CSI Secret Store"), "为数据库凭据和存储加密接入 KMS、External Secrets 或 CSI Secret Store。"))
        backup_evidence = _workload_backup_snapshot_evidence(index, ns, claims, _pod_template_labels(sts))
        backup_status: FindingStatus = "PASS" if backup_evidence else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-backup-or-snapshot", f"{asset.key} 备份/快照证据检查", backup_status, "high" if backup_status == "FAIL" else "medium", asset, Evidence("有状态服务应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据", asset, "Backup/Schedule/VolumeSnapshot", {"tier": tier, "claims": claims, "backup_evidence": backup_evidence, "reason": "backup or snapshot evidence covers workload PVCs or selector" if backup_status == "PASS" else "business data workload lacks bound backup/snapshot evidence" if backup_status == "FAIL" else "backup/snapshot evidence missing or incomplete"}, "backup or snapshot evidence bound to PVC, selector, or explicit namespace scope"), "为有状态服务配置覆盖对应 PVC 或工作负载 selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。"))
        workload_inventory.append(
            {
                "asset": asset.key,
                "kind": asset.kind,
                "namespace": ns,
                "name": asset.name,
                "tier": tier,
                "classification": "statefulset",
                "claims": claims,
                "services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services],
                "controls": {
                    "network_policy": np_status,
                    "service_exposure": service_status,
                    "pod_network_exposure": "FAIL" if host_exposed else "PASS",
                    "secret_reference": secret_status,
                    "tls_or_mtls": tls_status,
                    "no_plaintext_env": "FAIL" if plaintext else "PASS",
                    "pvc_encryption": status,
                    "kms_or_csi_secret_store": kms_status,
                    "backup_or_snapshot": backup_status,
                },
            }
        )
    for workload in index.by_kind("Deployment") + index.by_kind("Job") + index.by_kind("CronJob"):
        if not _database_controller_workload(workload):
            continue
        asset = _asset(workload)
        ns = _ns_name(workload)
        tier = _namespace_tier_for_name(index, ns)
        np_covers_workload, np_evidence = _stateful_networkpolicy_evidence(network_policies, workload)
        np_status: FindingStatus = "PASS" if np_covers_workload else _data_control_missing_status(tier)
        np_evidence["tier"] = tier
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-stateful-networkpolicy", f"{asset.key} 网络隔离检查", np_status, "high" if np_status == "FAIL" else "medium" if np_status == "WARN" else "info", asset, Evidence("数据库/有状态工作负载应被 Ingress NetworkPolicy 覆盖", asset, "NetworkPolicy.spec.podSelector", np_evidence, "NetworkPolicy selects database workload pods and controls Ingress"), "为数据库/有状态工作负载配置默认拒绝和精确允许的 NetworkPolicy，确保 podSelector 覆盖对应 Pod 模板。"))
        services = _workload_services(index, workload)
        exposed_services = [
            {"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP"), "ports": service.get("spec", {}).get("ports", [])}
            for service in services
            if service.get("spec", {}).get("type") in {"NodePort", "LoadBalancer"}
        ]
        if exposed_services:
            service_status: FindingStatus = "FAIL"
            service_reason = "external Service exposure"
        elif services:
            service_status = "PASS"
            service_reason = "ClusterIP/headless Service only"
        else:
            service_status = "WARN"
            service_reason = "no matching Service evidence"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-database-service-exposure", f"{asset.key} 数据库 Service 暴露检查", service_status, "high" if service_status == "FAIL" else "medium" if service_status == "WARN" else "info", asset, Evidence("数据库/有状态工作负载不应通过 NodePort/LoadBalancer 直接暴露；未匹配到 Service 时作为证据缺口复核", asset, "Service.spec.type", {"services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services], "service_found": bool(services), "exposed": exposed_services, "reason": service_reason}, "ClusterIP/headless service with no NodePort/LoadBalancer exposure"), "将数据库 Service 限制为 ClusterIP/headless，并通过 NetworkPolicy 控制访问来源；未发现关联 Service 时补充服务发现或暴露面证明。"))
        network_exposure = _pod_network_exposure(workload)
        host_exposed = network_exposure["hostNetwork"] or bool(network_exposure["hostPorts"])
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pod-network-exposure", f"{asset.key} Pod 主机网络暴露检查", "FAIL" if host_exposed else "PASS", "high" if host_exposed else "info", asset, Evidence("数据库/有状态工作负载不应通过 hostNetwork/hostPort 绕过 Service 与 NetworkPolicy 暴露", asset, "spec.template.spec.hostNetwork/containers[].ports[].hostPort", network_exposure, {"hostNetwork": False, "hostPorts": []}), "移除数据库/有状态工作负载的 hostNetwork/hostPort；需要节点级端口时使用受控 Service、NetworkPolicy 和审计例外。"))
        has_secret = _has_secret_reference(workload)
        csi_secret_store, csi_evidence = _has_csi_secret_store(workload)
        secret_status: FindingStatus = "PASS" if (has_secret or csi_secret_store) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-secret-reference", f"{asset.key} Secret/CSI 引用检查", secret_status, "high" if secret_status == "FAIL" else "medium", asset, Evidence("数据库/有状态工作负载敏感配置应来自 Secret 或 CSI Secret Store", asset, "podSpec", {"tier": tier, "secret_refs": sorted(_secret_ref_names(workload)), "csi_secret_store": csi_evidence, "reason": "secret or CSI Secret Store present" if secret_status == "PASS" else "business data workload lacks Secret/CSI secret evidence" if secret_status == "FAIL" else "secret evidence missing or incomplete"}, "secretKeyRef/envFrom/secret volume/CSI secret"), "使用 Secret、External Secrets 或 CSI Secret Store 管理数据库口令和证书。"))
        tls_secret, tls_evidence = _tls_secret_refs(index, workload)
        mtls_strict = _mtls_strict_in_namespace(index, ns)
        tls_status: FindingStatus = "PASS" if (tls_secret or mtls_strict) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-tls-or-mtls", f"{asset.key} TLS/mTLS 证据检查", tls_status, "high" if tls_status == "FAIL" else "medium", asset, Evidence("数据库/有状态工作负载应具备 TLS Secret 或服务网格 mTLS STRICT 证据", asset, "Secret.type/PeerAuthentication", {"tier": tier, "tls_secret": tls_evidence, "mtls_strict": mtls_strict, "reason": "TLS Secret or mTLS STRICT present" if tls_status == "PASS" else "business data workload lacks TLS/mTLS evidence" if tls_status == "FAIL" else "TLS/mTLS evidence missing or incomplete"}, "TLS secret or mTLS STRICT"), "为数据库启用 TLS 证书 Secret，或通过服务网格启用 STRICT mTLS。"))
        plaintext = []
        for c in _containers(workload):
            for env in c.get("env", []) or []:
                name = env.get("name", "").lower()
                if any(token in name for token in ["password", "secret", "token", "key"]) and "value" in env:
                    plaintext.append(env.get("name"))
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-no-plaintext-env", f"{asset.key} 明文环境变量检查", "FAIL" if plaintext else "PASS", "high" if plaintext else "info", asset, Evidence("敏感配置不应以明文 env value 暴露", asset, "containers[].env", plaintext, "valueFrom Secret/CSI"), "使用 Secret 引用或 CSI Secret Store，避免明文 env。"))
        claims = sorted(_claim_names_for_obj(workload))
        encryption_evidence = []
        encrypted_claims = 0
        for claim in claims:
            pvc = pvcs_by_name_ns.get((ns, claim))
            if not pvc:
                continue
            encrypted, evidence = _storageclass_encryption_evidence(index, pvc)
            encrypted_claims += int(encrypted)
            encryption_evidence.append({"claim": claim, **evidence})
        if claims and encryption_evidence:
            encryption_ok = encrypted_claims == len(encryption_evidence)
            encryption_status: FindingStatus = "PASS" if encryption_ok else _data_control_missing_status(tier)
        else:
            encryption_status = "UNKNOWN"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pvc-encryption-evidence", f"{asset.key} PVC 加密证据检查", encryption_status, "high" if encryption_status == "FAIL" else "medium", asset, Evidence("数据库/有状态工作负载 PVC 应有关联 StorageClass 加密/KMS 证据", asset, "pvc.storageClass.parameters", {"tier": tier, "claims": claims, "encryption_evidence": encryption_evidence, "encrypted_claims": encrypted_claims, "reason": "all referenced PVCs have encryption evidence" if encryption_status == "PASS" else "referenced business PVC lacks encryption/KMS evidence" if encryption_status == "FAIL" else "PVC encryption evidence unavailable or incomplete"}, "all referenced PVC encrypted or documented"), "为数据库/有状态工作负载使用带加密/KMS 参数的 StorageClass，或补充底层存储默认加密证明。"))
        kms_or_csi = csi_secret_store or any(
            any(
                ("kms" in key.lower() or "key" in key.lower()) and str(value).strip().lower() not in {"", "false", "0", "none", "null"}
                for key, value in (item.get("parameters") or {}).items()
            )
            for item in encryption_evidence
        )
        kms_status: FindingStatus = "PASS" if kms_or_csi else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-kms-or-csi-secret-store", f"{asset.key} KMS/CSI Secret Store 集成检查", kms_status, "high" if kms_status == "FAIL" else "medium", asset, Evidence("数据库/有状态工作负载应具备 KMS 参数或 CSI Secret Store 集成证据", asset, "StorageClass.parameters/volumes[].csi", {"tier": tier, "csi_secret_store": csi_evidence, "encryption_evidence": encryption_evidence, "reason": "KMS or CSI Secret Store evidence present" if kms_status == "PASS" else "business data workload lacks KMS/CSI Secret Store evidence" if kms_status == "FAIL" else "KMS/CSI Secret Store evidence missing or incomplete"}, "KMS key or CSI Secret Store"), "为数据库凭据和存储加密接入 KMS、External Secrets 或 CSI Secret Store。"))
        backup_evidence = _workload_backup_snapshot_evidence(index, ns, claims, _pod_template_labels(workload))
        backup_status: FindingStatus = "PASS" if backup_evidence else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-backup-or-snapshot", f"{asset.key} 备份/快照证据检查", backup_status, "high" if backup_status == "FAIL" else "medium", asset, Evidence("数据库/有状态工作负载应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据", asset, "Backup/Schedule/VolumeSnapshot", {"tier": tier, "claims": claims, "backup_evidence": backup_evidence, "reason": "backup or snapshot evidence covers workload PVCs or selector" if backup_status == "PASS" else "business data workload lacks bound backup/snapshot evidence" if backup_status == "FAIL" else "backup/snapshot evidence missing or incomplete"}, "backup or snapshot evidence bound to PVC, selector, or explicit namespace scope"), "为数据库/有状态工作负载配置覆盖对应 PVC 或工作负载 selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。"))
        workload_inventory.append(
            {
                "asset": asset.key,
                "kind": asset.kind,
                "namespace": ns,
                "name": asset.name,
                "tier": tier,
                "classification": str(asset.kind).lower(),
                "claims": claims,
                "services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services],
                "controls": {
                    "network_policy": np_status,
                    "service_exposure": service_status,
                    "pod_network_exposure": "FAIL" if host_exposed else "PASS",
                    "secret_reference": secret_status,
                    "tls_or_mtls": tls_status,
                    "no_plaintext_env": "FAIL" if plaintext else "PASS",
                    "pvc_encryption": encryption_status,
                    "kms_or_csi_secret_store": kms_status,
                    "backup_or_snapshot": backup_status,
                },
            }
        )
    for pod in index.by_kind("Pod"):
        if any(_owner_reference_kind(pod, kind) for kind in {"StatefulSet", "ReplicaSet", "Job", "CronJob"}) or not _database_pod(pod):
            continue
        asset = _asset(pod)
        ns = _ns_name(pod)
        tier = _namespace_tier_for_name(index, ns)
        np_covers_pod, np_evidence = _stateful_networkpolicy_evidence(network_policies, pod)
        np_status: FindingStatus = "PASS" if np_covers_pod else _data_control_missing_status(tier)
        np_evidence["tier"] = tier
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-stateful-networkpolicy", f"{asset.key} 数据库 Pod 网络隔离检查", np_status, "high" if np_status == "FAIL" else "medium" if np_status == "WARN" else "info", asset, Evidence("独立数据库 Pod 应被受限 Ingress NetworkPolicy 覆盖", asset, "NetworkPolicy.spec.podSelector", np_evidence, "restricted ingress NetworkPolicy selects database Pod"), "为独立数据库 Pod 配置默认拒绝和精确允许的 NetworkPolicy，确保 podSelector 覆盖该 Pod。"))
        services = _pod_services(index, pod)
        exposed_services = [
            {"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP"), "ports": service.get("spec", {}).get("ports", [])}
            for service in services
            if service.get("spec", {}).get("type") in {"NodePort", "LoadBalancer"}
        ]
        if exposed_services:
            service_status: FindingStatus = "FAIL"
            service_reason = "external Service exposure"
        elif services:
            service_status = "PASS"
            service_reason = "ClusterIP/headless Service only"
        else:
            service_status = "WARN"
            service_reason = "no matching Service evidence"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-database-service-exposure", f"{asset.key} 数据库 Pod Service 暴露检查", service_status, "high" if service_status == "FAIL" else "medium" if service_status == "WARN" else "info", asset, Evidence("数据库 Pod 不应通过 NodePort/LoadBalancer 直接暴露；未匹配到 Service 时作为证据缺口复核", asset, "Service.spec.type", {"services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services], "service_found": bool(services), "exposed": exposed_services, "reason": service_reason}, "ClusterIP/headless service with no NodePort/LoadBalancer exposure"), "将数据库 Service 限制为 ClusterIP/headless，并通过 NetworkPolicy 控制访问来源；未发现关联 Service 时补充服务发现或暴露面证明。"))
        network_exposure = _pod_network_exposure(pod)
        host_exposed = network_exposure["hostNetwork"] or bool(network_exposure["hostPorts"])
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pod-network-exposure", f"{asset.key} 数据库 Pod 主机网络暴露检查", "FAIL" if host_exposed else "PASS", "high" if host_exposed else "info", asset, Evidence("数据库 Pod 不应通过 hostNetwork/hostPort 绕过 Service 与 NetworkPolicy 暴露", asset, "spec.hostNetwork/containers[].ports[].hostPort", network_exposure, {"hostNetwork": False, "hostPorts": []}), "移除数据库 Pod 的 hostNetwork/hostPort；需要节点级端口时使用受控 Service、NetworkPolicy 和审计例外。"))
        has_secret = _has_secret_reference(pod)
        csi_secret_store, csi_evidence = _has_csi_secret_store(pod)
        secret_status: FindingStatus = "PASS" if (has_secret or csi_secret_store) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-secret-reference", f"{asset.key} 数据库 Pod Secret/CSI 引用检查", secret_status, "high" if secret_status == "FAIL" else "medium", asset, Evidence("数据库 Pod 敏感配置应来自 Secret 或 CSI Secret Store", asset, "podSpec", {"tier": tier, "secret_refs": sorted(_secret_ref_names(pod)), "csi_secret_store": csi_evidence, "reason": "secret or CSI Secret Store present" if secret_status == "PASS" else "business data workload lacks Secret/CSI secret evidence" if secret_status == "FAIL" else "secret evidence missing or incomplete"}, "secretKeyRef/envFrom/secret volume/CSI secret"), "使用 Secret、External Secrets 或 CSI Secret Store 管理数据库口令和证书。"))
        tls_secret, tls_evidence = _tls_secret_refs(index, pod)
        mtls_strict = _mtls_strict_in_namespace(index, ns)
        tls_status: FindingStatus = "PASS" if (tls_secret or mtls_strict) else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-tls-or-mtls", f"{asset.key} 数据库 Pod TLS/mTLS 证据检查", tls_status, "high" if tls_status == "FAIL" else "medium", asset, Evidence("数据库 Pod 应具备 TLS Secret 或服务网格 mTLS STRICT 证据", asset, "Secret.type/PeerAuthentication", {"tier": tier, "tls_secret": tls_evidence, "mtls_strict": mtls_strict, "reason": "TLS Secret or mTLS STRICT present" if tls_status == "PASS" else "business data workload lacks TLS/mTLS evidence" if tls_status == "FAIL" else "TLS/mTLS evidence missing or incomplete"}, "TLS secret or mTLS STRICT"), "为数据库启用 TLS 证书 Secret，或通过服务网格启用 STRICT mTLS。"))
        plaintext = []
        for c in _containers(pod):
            for env in c.get("env", []) or []:
                name = env.get("name", "").lower()
                if any(token in name for token in ["password", "secret", "token", "key"]) and "value" in env:
                    plaintext.append(env.get("name"))
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-no-plaintext-env", f"{asset.key} 数据库 Pod 明文环境变量检查", "FAIL" if plaintext else "PASS", "high" if plaintext else "info", asset, Evidence("敏感配置不应以明文 env value 暴露", asset, "containers[].env", plaintext, "valueFrom Secret/CSI"), "使用 Secret 引用或 CSI Secret Store，避免明文 env。"))
        claims = sorted(_claim_names_for_obj(pod))
        encryption_evidence = []
        encrypted_claims = 0
        for claim in claims:
            pvc = pvcs_by_name_ns.get((ns, claim))
            if not pvc:
                continue
            encrypted, evidence = _storageclass_encryption_evidence(index, pvc)
            encrypted_claims += int(encrypted)
            encryption_evidence.append({"claim": claim, **evidence})
        if claims and encryption_evidence:
            encryption_ok = encrypted_claims == len(encryption_evidence)
            encryption_status: FindingStatus = "PASS" if encryption_ok else _data_control_missing_status(tier)
        else:
            encryption_status = "UNKNOWN"
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-pvc-encryption-evidence", f"{asset.key} 数据库 Pod PVC 加密证据检查", encryption_status, "high" if encryption_status == "FAIL" else "medium", asset, Evidence("数据库 Pod PVC 应有关联 StorageClass 加密/KMS 证据", asset, "pvc.storageClass.parameters", {"tier": tier, "claims": claims, "encryption_evidence": encryption_evidence, "encrypted_claims": encrypted_claims, "reason": "all referenced PVCs have encryption evidence" if encryption_status == "PASS" else "referenced business PVC lacks encryption/KMS evidence" if encryption_status == "FAIL" else "PVC encryption evidence unavailable or incomplete"}, "all referenced PVC encrypted or documented"), "为数据库 Pod 使用带加密/KMS 参数的 StorageClass，或补充底层存储默认加密证明。"))
        kms_or_csi = csi_secret_store or any(
            any(
                ("kms" in key.lower() or "key" in key.lower()) and str(value).strip().lower() not in {"", "false", "0", "none", "null"}
                for key, value in (item.get("parameters") or {}).items()
            )
            for item in encryption_evidence
        )
        kms_status: FindingStatus = "PASS" if kms_or_csi else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-kms-or-csi-secret-store", f"{asset.key} 数据库 Pod KMS/CSI Secret Store 集成检查", kms_status, "high" if kms_status == "FAIL" else "medium", asset, Evidence("数据库 Pod 应具备 KMS 参数或 CSI Secret Store 集成证据", asset, "StorageClass.parameters/volumes[].csi", {"tier": tier, "csi_secret_store": csi_evidence, "encryption_evidence": encryption_evidence, "reason": "KMS or CSI Secret Store evidence present" if kms_status == "PASS" else "business data workload lacks KMS/CSI Secret Store evidence" if kms_status == "FAIL" else "KMS/CSI Secret Store evidence missing or incomplete"}, "KMS key or CSI Secret Store"), "为数据库凭据和存储加密接入 KMS、External Secrets 或 CSI Secret Store。"))
        backup_evidence = _workload_backup_snapshot_evidence(index, ns, claims, _pod_template_labels(pod))
        backup_status: FindingStatus = "PASS" if backup_evidence else _data_control_missing_status(tier)
        findings.append(_finding(task_id, "CN-37", "CN-PER-003-backup-or-snapshot", f"{asset.key} 数据库 Pod 备份/快照证据检查", backup_status, "high" if backup_status == "FAIL" else "medium", asset, Evidence("数据库 Pod 应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据", asset, "Backup/Schedule/VolumeSnapshot", {"tier": tier, "claims": claims, "backup_evidence": backup_evidence, "reason": "backup or snapshot evidence covers workload PVCs or selector" if backup_status == "PASS" else "business data workload lacks bound backup/snapshot evidence" if backup_status == "FAIL" else "backup/snapshot evidence missing or incomplete"}, "backup or snapshot evidence bound to PVC, selector, or explicit namespace scope"), "为数据库 Pod 配置覆盖对应 PVC 或 Pod selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。"))
        workload_inventory.append(
            {
                "asset": asset.key,
                "kind": asset.kind,
                "namespace": ns,
                "name": asset.name,
                "tier": tier,
                "classification": "database-pod",
                "claims": claims,
                "services": [{"name": _meta(service).get("name"), "type": service.get("spec", {}).get("type", "ClusterIP")} for service in services],
                "controls": {
                    "network_policy": np_status,
                    "service_exposure": service_status,
                    "pod_network_exposure": "FAIL" if host_exposed else "PASS",
                    "secret_reference": secret_status,
                    "tls_or_mtls": tls_status,
                    "no_plaintext_env": "FAIL" if plaintext else "PASS",
                    "pvc_encryption": encryption_status,
                    "kms_or_csi_secret_store": kms_status,
                    "backup_or_snapshot": backup_status,
                },
            }
        )
    for pvc in index.by_kind("PersistentVolumeClaim"):
        asset = _asset(pvc)
        ns = _ns_name(pvc)
        encrypted, encryption_evidence = _storageclass_encryption_evidence(index, pvc)
        backup_evidence = _backup_snapshot_evidence(index, ns, _meta(pvc).get("name"))
        if encrypted and backup_evidence:
            protection_status: FindingStatus = "PASS"
        elif encrypted or backup_evidence:
            protection_status = "WARN"
        else:
            protection_status = "FAIL"
        findings.append(
            _finding(
                task_id,
                "CN-37",
                "CN-PER-003-pvc-data-protection",
                f"{asset.key} PVC 数据保护证据检查",
                protection_status,
                "high" if protection_status == "FAIL" else "medium",
                asset,
                Evidence(
                    "PVC 应同时具备存储加密和可恢复备份/快照证据",
                    asset,
                    "PersistentVolumeClaim.spec.storageClassName/VolumeSnapshot",
                    {"encryption": encryption_evidence, "backup_evidence": backup_evidence},
                    "encrypted StorageClass and backup/snapshot evidence",
                ),
                "为持久化 PVC 绑定加密/KMS StorageClass，并配置 CSI VolumeSnapshot、Velero Schedule 或等效备份证据。",
            )
        )
        isolated, isolation_evidence = _pvc_namespace_isolation_evidence(index, network_policies, pvc)
        access_modes = pvc.get("spec", {}).get("accessModes", []) or []
        shared = "ReadWriteMany" in access_modes
        isolation_status: FindingStatus = "FAIL" if not isolated else "WARN" if shared else "PASS"
        findings.append(
            _finding(
                task_id,
                "CN-37",
                "CN-PER-003-pvc-namespace-isolation",
                f"{asset.key} PVC 网络隔离与共享面检查",
                isolation_status,
                "high" if isolation_status == "FAIL" else "medium" if isolation_status == "WARN" else "info",
                asset,
                Evidence(
                    "PVC 所在 namespace 应具备 NetworkPolicy，且共享读写卷需要额外访问控制",
                    asset,
                    "NetworkPolicy/PersistentVolumeClaim.spec.accessModes",
                    {**isolation_evidence, "access_modes": access_modes},
                    "restricted NetworkPolicy covers PVC consumers and minimal shared access",
                ),
                "为承载持久化数据的 namespace 配置覆盖 PVC 消费工作负载的默认拒绝和精确允许 NetworkPolicy；RWX 卷需补充租户隔离和应用级权限控制。",
            )
        )
        pvc_inventory.append(
            {
                "asset": asset.key,
                "namespace": ns,
                "name": asset.name,
                "storageClassName": pvc.get("spec", {}).get("storageClassName"),
                "access_modes": access_modes,
                "encrypted": encrypted,
                "backup_evidence": backup_evidence,
                "namespace_network_policy": isolated,
                "isolation_evidence": isolation_evidence,
                "data_protection_status": protection_status,
                "namespace_isolation_status": isolation_status,
            }
        )
    if workload_inventory or pvc_inventory:
        control_status_count: dict[str, int] = defaultdict(int)
        for row in workload_inventory:
            for status in row["controls"].values():
                control_status_count[str(status)] += 1
        for row in pvc_inventory:
            control_status_count[str(row["data_protection_status"])] += 1
            control_status_count[str(row["namespace_isolation_status"])] += 1
        findings.append(
            _cluster_finding(
                task_id,
                "CN-37",
                "CN-PER-003-data-protection-inventory",
                "有状态应用数据保护清单",
                "PASS",
                "info",
                "已输出 StatefulSet/数据库 Pod/PVC 数据保护清单，并汇总网络、凭据、TLS、KMS、备份和 PVC 控制状态",
                {
                    "workload_count": len(workload_inventory),
                    "pvc_count": len(pvc_inventory),
                    "control_status_count": dict(sorted(control_status_count.items())),
                    "workloads": workload_inventory,
                    "pvcs": pvc_inventory,
                },
                "stateful/data workload and PVC inventory with per-control statuses",
                "持续维护有状态应用、PVC、备份、KMS、Secret/TLS 与 NetworkPolicy 的清单化证据。",
            )
        )
    if not findings:
        findings.append(_cluster_finding(task_id, "CN-37", "CN-PER-003-no-statefulset", "有状态应用采集检查", "UNKNOWN", "info", "未采集 StatefulSet/数据库 Pod/PVC", [], "StatefulSet, database Pod, or PVC objects", "采集有状态应用、数据库 Pod 或标记场景不适用。"))
    return findings


def check_registry_security(index: ResourceIndex, task_id: str) -> list[Finding]:
    image_rows = []
    registry_endpoints = index.by_kind("RegistryEndpoint")
    for obj in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        pull_secret_evidence = _image_pull_secret_evidence(index, obj)
        pull_secrets = pull_secret_evidence["effective"]
        for c in _containers(obj):
            if c.get("image"):
                image = c.get("image")
                registry = _image_registry(image)
                image_rows.append({"asset": _asset(obj).key, "namespace": _ns_name(obj), "container": c.get("name"), "image": image, "registry": registry, "pull_secrets": pull_secrets, "pull_secret_sources": pull_secret_evidence})
    insecure = [row for row in image_rows if _image_insecure(row["image"], row["registry"], registry_endpoints)]
    latest = [row for row in image_rows if _image_mutable_tag(row["image"])]
    pull_secret_risks = _registry_pull_secret_risks(index, image_rows)
    endpoint_rows, endpoint_risks = _registry_endpoint_rows(registry_endpoints)
    audit_rows, audit_risks = _registry_audit_rows(index)
    inferred_endpoint_rows = _registry_inferred_endpoint_rows(image_rows, registry_endpoints)
    k8s_pull_events = _registry_kubernetes_pull_events(index)
    k8s_pull_risks = [event for event in k8s_pull_events if event.get("risk_reasons")]
    combined_audit_risks = [*audit_risks, *k8s_pull_risks]
    vuln_rows, vuln_risks, vuln_platform_review, secret_scan_rows, secret_scan_risks, secret_platform_review, vuln_unknown = _trivy_vulnerability_rows(index)
    inventory_rows = _registry_inventory_rows(image_rows, registry_endpoints)
    endpoint_status: FindingStatus = "FAIL" if endpoint_risks else "PASS" if endpoint_rows else "WARN" if inferred_endpoint_rows else "UNKNOWN"
    audit_status: FindingStatus = "FAIL" if combined_audit_risks else "PASS" if audit_rows else "WARN" if k8s_pull_events else "UNKNOWN"
    secret_status: FindingStatus = "FAIL" if secret_scan_risks else "PASS" if secret_scan_rows else "UNKNOWN"
    posture = _registry_security_posture_summary(
        index,
        image_rows,
        inventory_rows,
        insecure,
        latest,
        pull_secret_risks,
        endpoint_rows,
        inferred_endpoint_rows,
        endpoint_risks,
        audit_rows,
        k8s_pull_events,
        combined_audit_risks,
        vuln_rows,
        vuln_risks,
        vuln_platform_review,
        secret_scan_rows,
        secret_scan_risks,
        secret_platform_review,
        vuln_unknown,
    )
    posture_status: FindingStatus = posture["status"]
    findings = [
        _cluster_finding(task_id, "CN-38", "CN-REG-001-security-posture", "镜像仓库安全状态汇总", posture_status, "info", "汇总镜像引用、RegistryEndpoint adapter、审计事件、pull secret、Trivy/SecretReport 证据的仓库安全态势", posture, "registry security posture is observable across inventory, endpoint, audit, credential, and scan signals", "持续接入 registry API、审计日志和镜像扫描报告；按 registry 维度跟踪 TLS、匿名拉取、robot 权限、异常事件和漏洞泄露。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-registry-inventory", "镜像仓库引用识别清单", "PASS" if inventory_rows else "UNKNOWN", "info", "从 Pod/Workload/Job/CronJob image 字段识别 registry、namespace、镜像样本和 pull secret 使用情况", inventory_rows, "registry inventory derived from image references", "保持镜像引用清单，接入 registry API 后补充 TLS、匿名访问、robot 和审计配置。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-insecure-registry", "HTTP/本地明文仓库引用检查", "FAIL" if insecure else "PASS", "high" if insecure else "info", "不安全镜像引用", insecure, [], "使用 HTTPS registry，禁用匿名/明文 HTTP registry。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-latest-tag", "latest/未固定标签检查", "WARN" if latest else "PASS", "medium" if latest else "info", "latest 或无 tag 镜像", latest, [], "固定 tag 并优先使用 digest。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-pull-secret", "私有仓库拉取凭据检查", "FAIL" if pull_secret_risks else "PASS", "high" if pull_secret_risks else "info", "私有仓库 imagePullSecret 风险", pull_secret_risks, [], "为私有仓库 workload 配置 kubernetes.io/dockerconfigjson pull secret，并避免使用默认匿名拉取。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-registry-endpoint", "Registry TLS/匿名/robot/audit 配置检查", endpoint_status, "high" if endpoint_status == "FAIL" else "medium" if endpoint_status == "WARN" else "info", "RegistryEndpoint mock/adapter 证据；无 adapter 时用镜像引用推导有限 registry inventory", {"registries": endpoint_rows, "inferred_registries": inferred_endpoint_rows, "risks": endpoint_risks, "evidence_mode": "explicit" if endpoint_rows else "inferred" if inferred_endpoint_rows else "missing", "evidence_level": "full_adapter" if endpoint_rows else "limited_inference" if inferred_endpoint_rows else "missing", "limitations": [] if endpoint_rows else ["image references identify registries but cannot prove TLS, anonymous pull, robot scope, or audit settings"] if inferred_endpoint_rows else ["registry endpoint adapter evidence is missing"]}, "tls enabled, anonymous disabled, robot account scoped, audit enabled", "接入 Harbor/Registry API 或 mock adapter，开启 TLS、关闭匿名拉取、使用最小权限 robot account 并启用审计。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-registry-audit", "Registry 审计异常检查", audit_status, "high" if audit_status == "FAIL" else "medium" if audit_status == "WARN" else "info", "RegistryAuditEvent 审计事件；无 registry audit adapter 时用 Kubernetes image pull event 作为有限证据", {"events": audit_rows, "kubernetes_pull_events": k8s_pull_events, "risks": combined_audit_risks, "registry_audit_risks": audit_risks, "kubernetes_pull_risks": k8s_pull_risks, "evidence_mode": "registry_audit" if audit_rows else "kubernetes_events_limited" if k8s_pull_events else "missing", "evidence_level": "full_registry_audit" if audit_rows else "limited_kubernetes_event_stream" if k8s_pull_events else "missing", "limitations": [] if audit_rows else ["Kubernetes pull events prove image pull activity and pull failures but cannot prove registry actor identity or delete events"] if k8s_pull_events else ["registry audit event source is missing"]}, "no anonymous pull/delete/failed auth anomaly", "接入 Harbor/Registry 审计日志，告警匿名拉取、删除镜像、认证失败、ImagePullBackOff 和异常批量拉取。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-trivy-reports", "Trivy 镜像漏洞报告检查", "FAIL" if vuln_risks else "UNKNOWN" if vuln_unknown else "PASS", "high" if vuln_risks else "info", "VulnerabilityReport 摘要", {"reports": vuln_rows, "risks": vuln_risks, "platform_review": vuln_platform_review[:50], "platform_review_count": len(vuln_platform_review)}, "no critical/high vulnerabilities", "安装 Trivy Operator 或导入镜像扫描报告；修复业务镜像 Critical/High 漏洞；平台组件漏洞按变更窗口单独复核。"),
        _cluster_finding(task_id, "CN-38", "CN-REG-001-secret-leak-reports", "镜像/仓库 Secret 泄露扫描检查", secret_status, "high" if secret_status == "FAIL" else "info", "SecretReport 或 Trivy secret 扫描摘要", {"reports": secret_scan_rows, "risks": secret_scan_risks, "platform_review": secret_platform_review[:50], "platform_review_count": len(secret_platform_review)}, "no leaked secrets in image/registry scan reports", "接入 Trivy SecretReport 或 registry secret scan，清理业务镜像中的密钥、令牌和凭据；平台组件泄露项单独复核。"),
    ]
    return findings


PUBLIC_REGISTRIES = {
    "docker.io",
    "registry-1.docker.io",
    "registry.k8s.io",
    "k8s.gcr.io",
    "gcr.io",
    "quay.io",
    "ghcr.io",
    "mcr.microsoft.com",
    "public.ecr.aws",
    "registry.gitlab.com",
    "docker.elastic.co",
    "registry.aliyuncs.com",
    "reg.kyverno.io",
    "mirror.gcr.io",
}


def _image_pull_secret_evidence(index: ResourceIndex, obj: dict[str, Any]) -> dict[str, Any]:
    spec = _pod_spec(obj)
    namespace = _ns_name(obj) or "default"
    service_account_name = spec.get("serviceAccountName") or "default"
    pod_secrets = [item.get("name") for item in spec.get("imagePullSecrets", []) or [] if item.get("name")]
    service_account_secrets: list[str] = []
    service_account_found = False
    for service_account in index.by_kind("ServiceAccount"):
        if _ns_name(service_account) == namespace and _meta(service_account).get("name") == service_account_name:
            service_account_found = True
            service_account_secrets = [
                item.get("name")
                for item in service_account.get("imagePullSecrets", []) or []
                if item.get("name")
            ]
            break
    effective = sorted(dict.fromkeys([*pod_secrets, *service_account_secrets]))
    return {
        "pod_spec": pod_secrets,
        "service_account": service_account_secrets,
        "serviceAccountName": service_account_name,
        "serviceAccountFound": service_account_found,
        "effective": effective,
    }


def _image_registry(image: str) -> str:
    normalized = image.removeprefix("http://").removeprefix("https://")
    parts = normalized.split("/", 1)
    if len(parts) == 1:
        return "docker.io"
    first = parts[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def _registry_endpoint_key(value: Any) -> str:
    normalized = str(value or "").removeprefix("http://").removeprefix("https://")
    return normalized.split("/", 1)[0]


def _image_mutable_tag(image: str) -> bool:
    if "@sha256:" in image:
        return False
    tail = image.rsplit("/", 1)[-1]
    return ":" not in tail or tail.endswith(":latest")


def _image_insecure(image: str, registry: str, endpoints: list[dict[str, Any]]) -> bool:
    if image.startswith("http://"):
        return True
    for endpoint in endpoints:
        url = str(endpoint.get("url") or endpoint.get("registry") or _meta(endpoint).get("name") or "")
        if registry in url:
            if endpoint.get("tls_enabled") is True or url.startswith("https://"):
                return False
            if endpoint.get("tls_enabled") is False or url.startswith("http://"):
                return True
    if registry.startswith("localhost") or registry.endswith(":5000"):
        return True
    return False


def _registry_pull_secret_risks(index: ResourceIndex, image_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    secret_index = {(_ns_name(secret), _meta(secret).get("name")): secret for secret in index.by_kind("Secret")}
    configured_registries = {
        _registry_endpoint_key(endpoint.get("url") or endpoint.get("registry") or _meta(endpoint).get("name") or "")
        for endpoint in index.by_kind("RegistryEndpoint")
    }
    for row in image_rows:
        registry = row["registry"]
        private_like = _registry_needs_pull_secret_evidence(registry, row["image"], configured_registries)
        if not private_like:
            continue
        secrets = [secret_index.get((row["namespace"], name)) for name in row["pull_secrets"]]
        valid = any(secret and secret.get("type") in {"kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg"} for secret in secrets)
        if not valid:
            risks.append({**row, "reason": "private registry image without valid dockerconfigjson pull secret"})
    return risks


def _registry_needs_pull_secret_evidence(registry: str, image: str, configured_registries: set[str]) -> bool:
    if registry in configured_registries or image.startswith("http://") or registry.endswith(":5000") or registry.startswith("localhost"):
        return True
    return registry != "docker.io" and registry not in PUBLIC_REGISTRIES


def _registry_endpoint_rows(endpoints: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    for endpoint in endpoints:
        row = {
            "asset": _asset(endpoint).key,
            "url": endpoint.get("url") or endpoint.get("registry") or _meta(endpoint).get("name"),
            "tls_enabled": endpoint.get("tls_enabled"),
            "anonymous_pull": endpoint.get("anonymous_pull"),
            "robot_account": endpoint.get("robot_account"),
            "robot_account_scope": endpoint.get("robot_account_scope"),
            "audit_enabled": endpoint.get("audit_enabled"),
        }
        row_risks = []
        if row["tls_enabled"] is not True:
            row_risks.append("tls disabled or unknown")
        if row["anonymous_pull"] is not False:
            row_risks.append("anonymous pull enabled or unknown")
        if not row["robot_account"]:
            row_risks.append("robot account missing")
        scope_risks = _robot_scope_risks(row.get("robot_account_scope"))
        if scope_risks:
            row_risks.extend(scope_risks)
        if row["audit_enabled"] is not True:
            row_risks.append("audit disabled or unknown")
        rows.append(row)
        if row_risks:
            risks.append({**row, "risks": row_risks})
    return rows, risks


def _registry_inferred_endpoint_rows(image_rows: list[dict[str, Any]], explicit_endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if explicit_endpoints:
        return []
    registries: dict[str, dict[str, Any]] = {}
    for row in image_rows:
        registry = row.get("registry") or "docker.io"
        entry = registries.setdefault(
            registry,
            {
                "registry": registry,
                "image_count": 0,
                "namespaces": set(),
                "images_sample": [],
                "tls_inferred": not (str(registry).startswith("localhost") or str(registry).endswith(":5000")),
                "evidence_mode": "inferred_from_image_refs",
                "limitations": ["anonymous/robot/audit settings require registry API evidence"],
            },
        )
        entry["image_count"] += 1
        entry["namespaces"].add(row.get("namespace"))
        if len(entry["images_sample"]) < 5:
            entry["images_sample"].append(row.get("image"))
    normalized = []
    for entry in registries.values():
        normalized.append({**entry, "namespaces": sorted(ns for ns in entry["namespaces"] if ns)})
    return sorted(normalized, key=lambda item: item["registry"])


def _registry_inventory_rows(image_rows: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoint_registries = {
        _registry_endpoint_key(endpoint.get("url") or endpoint.get("registry") or _meta(endpoint).get("name") or ""): _asset(endpoint).key
        for endpoint in endpoints
    }
    inventory: dict[str, dict[str, Any]] = {}
    for row in image_rows:
        registry = row.get("registry") or "docker.io"
        entry = inventory.setdefault(
            registry,
            {
                "registry": registry,
                "image_count": 0,
                "namespaces": set(),
                "assets": set(),
                "images_sample": [],
                "pull_secret_count": 0,
                "endpoint_asset": endpoint_registries.get(registry),
                "tls_inferred": not (str(registry).startswith("localhost") or str(registry).endswith(":5000") or str(registry).startswith("10.")),
            },
        )
        entry["image_count"] += 1
        if row.get("namespace"):
            entry["namespaces"].add(row.get("namespace"))
        if row.get("asset"):
            entry["assets"].add(row.get("asset"))
        if row.get("pull_secrets"):
            entry["pull_secret_count"] += len(row.get("pull_secrets") or [])
        if len(entry["images_sample"]) < 8:
            entry["images_sample"].append(row.get("image"))
    rows = []
    for entry in inventory.values():
        rows.append(
            {
                **entry,
                "namespaces": sorted(entry["namespaces"]),
                "assets": sorted(entry["assets"])[:20],
            }
        )
    return sorted(rows, key=lambda item: item["registry"])


def _registry_security_posture_summary(
    index: ResourceIndex,
    image_rows: list[dict[str, Any]],
    inventory_rows: list[dict[str, Any]],
    insecure_rows: list[dict[str, Any]],
    latest_rows: list[dict[str, Any]],
    pull_secret_risks: list[dict[str, Any]],
    endpoint_rows: list[dict[str, Any]],
    inferred_endpoint_rows: list[dict[str, Any]],
    endpoint_risks: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    k8s_pull_events: list[dict[str, Any]],
    combined_audit_risks: list[dict[str, Any]],
    vuln_rows: list[dict[str, Any]],
    vuln_risks: list[dict[str, Any]],
    vuln_platform_review: list[dict[str, Any]],
    secret_scan_rows: list[dict[str, Any]],
    secret_scan_risks: list[dict[str, Any]],
    secret_platform_review: list[dict[str, Any]],
    vuln_unknown: bool,
) -> dict[str, Any]:
    configured_registries = {
        _registry_endpoint_key(endpoint.get("url") or endpoint.get("registry") or _meta(endpoint).get("name") or "")
        for endpoint in index.by_kind("RegistryEndpoint")
    }
    private_rows = [
        row
        for row in image_rows
        if _registry_needs_pull_secret_evidence(str(row.get("registry") or "docker.io"), str(row.get("image") or ""), configured_registries)
    ]
    endpoint_by_registry = {
        _registry_endpoint_key(row.get("url") or row.get("registry") or ""): row
        for row in endpoint_rows
        if row.get("url") or row.get("registry")
    }
    endpoint_risks_by_registry: dict[str, list[str]] = defaultdict(list)
    for risk in endpoint_risks:
        registry = _registry_endpoint_key(risk.get("url") or risk.get("registry") or "")
        endpoint_risks_by_registry[registry].extend(risk.get("risks") or [])
    audit_risk_count_by_registry: dict[str, int] = defaultdict(int)
    for risk in combined_audit_risks:
        registry = risk.get("registry")
        if not registry and risk.get("image"):
            registry = _image_registry(str(risk.get("image")))
        if registry:
            audit_risk_count_by_registry[str(registry)] += 1
    latest_count_by_registry: dict[str, int] = defaultdict(int)
    insecure_count_by_registry: dict[str, int] = defaultdict(int)
    pull_secret_missing_by_registry: dict[str, int] = defaultdict(int)
    for row in latest_rows:
        latest_count_by_registry[str(row.get("registry") or "docker.io")] += 1
    for row in insecure_rows:
        insecure_count_by_registry[str(row.get("registry") or "docker.io")] += 1
    for row in pull_secret_risks:
        pull_secret_missing_by_registry[str(row.get("registry") or "docker.io")] += 1
    registry_state = []
    for entry in inventory_rows:
        registry = str(entry.get("registry") or "docker.io")
        endpoint = endpoint_by_registry.get(registry)
        registry_state.append(
            {
                "registry": registry,
                "image_count": entry.get("image_count", 0),
                "namespaces": entry.get("namespaces", []),
                "endpoint_evidence": "explicit" if endpoint else "inferred" if not endpoint_rows else "missing_for_registry",
                "endpoint_asset": entry.get("endpoint_asset"),
                "tls_enabled": endpoint.get("tls_enabled") if endpoint else entry.get("tls_inferred"),
                "anonymous_pull": endpoint.get("anonymous_pull") if endpoint else "unknown",
                "robot_account": bool(endpoint.get("robot_account")) if endpoint else "unknown",
                "audit_enabled": endpoint.get("audit_enabled") if endpoint else "unknown",
                "mutable_tag_count": latest_count_by_registry.get(registry, 0),
                "insecure_ref_count": insecure_count_by_registry.get(registry, 0),
                "missing_pull_secret_count": pull_secret_missing_by_registry.get(registry, 0),
                "endpoint_risks": sorted(set(endpoint_risks_by_registry.get(registry, []))),
                "audit_risk_count": audit_risk_count_by_registry.get(registry, 0),
            }
        )
    explicit_covered = sum(1 for row in inventory_rows if row.get("endpoint_asset"))
    hard_risk_count = len(insecure_rows) + len(pull_secret_risks) + len(endpoint_risks) + len(combined_audit_risks) + len(vuln_risks) + len(secret_scan_risks)
    warning_count = len(latest_rows)
    limited_evidence = bool(
        inferred_endpoint_rows
        or vuln_unknown
        or (k8s_pull_events and not (endpoint_rows or audit_rows))
    )
    if hard_risk_count:
        posture_status: FindingStatus = "FAIL"
        posture_reason = "registry posture contains concrete insecure endpoint, credential, audit, or scan risks"
    elif limited_evidence or warning_count:
        posture_status = "WARN"
        if limited_evidence and warning_count:
            posture_reason = "registry posture has limited evidence and mutable-tag drift signals"
        elif limited_evidence:
            posture_reason = "registry posture is observable but relies on limited inferred/event evidence"
        else:
            posture_reason = "registry posture has mutable-tag drift signals but no hard registry control failures"
    elif image_rows or endpoint_rows or audit_rows or secret_scan_rows or vuln_rows:
        posture_status = "PASS"
        posture_reason = "registry posture is observable and no hard risks were found"
    else:
        posture_status = "UNKNOWN"
        posture_reason = "registry posture evidence is missing"
    return {
        "source_present": bool(image_rows or endpoint_rows or audit_rows or k8s_pull_events or vuln_rows or secret_scan_rows),
        "status": posture_status,
        "status_reason": posture_reason,
        "hard_risk_count": hard_risk_count,
        "warning_count": warning_count,
        "limited_evidence": limited_evidence,
        "registry_state": registry_state,
        "image_inventory": {
            "image_count": len(image_rows),
            "registry_count": len(inventory_rows),
            "registries": [row.get("registry") for row in inventory_rows],
            "mutable_tag_count": len(latest_rows),
            "insecure_ref_count": len(insecure_rows),
        },
        "pull_secret_coverage": {
            "private_or_configured_image_count": len(private_rows),
            "covered_count": max(0, len(private_rows) - len(pull_secret_risks)),
            "missing_or_invalid_count": len(pull_secret_risks),
        },
        "endpoint_evidence": {
            "mode": "explicit" if endpoint_rows else "inferred" if inferred_endpoint_rows else "missing",
            "endpoint_count": len(endpoint_rows),
            "inferred_registry_count": len(inferred_endpoint_rows),
            "explicit_registry_coverage_count": explicit_covered,
            "missing_registry_coverage_count": max(0, len(inventory_rows) - explicit_covered) if endpoint_rows else 0,
            "risk_count": len(endpoint_risks),
        },
        "audit_evidence": {
            "registry_audit_event_count": len(audit_rows),
            "kubernetes_pull_event_count": len(k8s_pull_events),
            "risk_count": len(combined_audit_risks),
        },
        "scan_evidence": {
            "vulnerability_report_count": len(vuln_rows),
            "business_vulnerability_risk_count": len(vuln_risks),
            "platform_vulnerability_review_count": len(vuln_platform_review),
            "secret_report_count": len(secret_scan_rows),
            "business_secret_risk_count": len(secret_scan_risks),
            "platform_secret_review_count": len(secret_platform_review),
            "scan_reports_missing": vuln_unknown,
        },
    }


def _robot_scope_risks(scope: Any) -> list[str]:
    normalized = str(scope or "").strip().lower()
    if not normalized:
        return ["robot account scope too broad or unknown"]
    risks: list[str] = []
    if any(token in normalized for token in ["*", "admin", "system", "delete", "push", "write"]):
        risks.append("robot account scope includes write/admin/delete privileges")
    if "pull" not in normalized and "read" not in normalized:
        risks.append("robot account scope lacks explicit pull/read privilege")
    return risks


def _registry_audit_rows(index: ResourceIndex) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    for event in index.by_kind("RegistryAuditEvent"):
        row = {
            "asset": _asset(event).key,
            "registry": event.get("registry"),
            "repository": event.get("repository"),
            "action": event.get("action"),
            "actor": event.get("actor"),
            "result": event.get("result"),
            "time": event.get("time") or _meta(event).get("creationTimestamp"),
        }
        action = str(row["action"] or "").lower()
        actor = str(row["actor"] or "").lower()
        result = str(row["result"] or "").lower()
        row_risks = []
        if "delete" in action:
            row_risks.append("image delete event")
        if actor in {"anonymous", "unauthenticated", ""} and "pull" in action:
            row_risks.append("anonymous pull event")
        if result in {"denied", "failed", "unauthorized"}:
            row_risks.append("failed or denied registry operation")
        rows.append(row)
        if row_risks:
            risks.append({**row, "risks": row_risks})
    return rows, risks


def _registry_image_from_event_message(message: str) -> str | None:
    quoted = re.search(r'image\s+["\']([^"\']+)["\']', message, flags=re.IGNORECASE)
    if quoted:
        return quoted.group(1)
    unquoted = re.search(r"image\s+([^\s,;:]+(?:/[^\s,;:]+)*(?::[^\s,;]+|@sha256:[a-fA-F0-9]+)?)", message, flags=re.IGNORECASE)
    if unquoted:
        candidate = unquoted.group(1).strip("\"'")
        if candidate and candidate.lower() not in {"pull", "pulling"}:
            return candidate
    return None


def _registry_kubernetes_pull_events(index: ResourceIndex) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in index.by_kind("Event"):
        reason = str(event.get("reason") or "").lower()
        message = str(event.get("message") or event.get("note") or "")
        text = f"{reason} {message.lower()}"
        if not any(token in text for token in ["pull", "image", "back-off pulling", "errimagepull", "imagepullbackoff"]):
            continue
        involved = event.get("involvedObject") or event.get("regarding") or {}
        risk_reasons = []
        if any(token in text for token in ["imagepullbackoff", "errimagepull", "back-off pulling", "failed to pull", "pull access denied", "unauthorized", "denied", "not found"]):
            risk_reasons.append("image pull failure")
        if "latest" in text and reason in {"failed", "backoff"}:
            risk_reasons.append("failed mutable-tag pull")
        namespace = involved.get("namespace") or _ns_name(event)
        image = _registry_image_from_event_message(message)
        rows.append(
            {
                "asset": _asset(event).key,
                "reason": event.get("reason"),
                "namespace": namespace,
                "name": involved.get("name") or _meta(event).get("name"),
                "image": image,
                "registry": _image_registry(image) if image else None,
                "tier": _namespace_tier_for_name(index, namespace),
                "message": message[:300],
                "time": event.get("eventTime") or event.get("lastTimestamp") or event.get("firstTimestamp") or _meta(event).get("creationTimestamp"),
                "evidence_mode": "kubernetes_event",
                "risk_reasons": risk_reasons,
            }
        )
    return rows[:50]


def _registry_scan_report_tier(index: ResourceIndex, report: dict[str, Any]) -> str:
    if str(report.get("kind") or "").startswith("Cluster"):
        return "platform"
    return _namespace_tier_for_name(index, _ns_name(report))


def _trivy_vulnerability_rows(index: ResourceIndex) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], bool]:
    reports = (
        index.by_kind("VulnerabilityReport")
        + index.by_kind("ClusterVulnerabilityReport")
        + index.by_kind("SecretReport")
        + index.by_kind("ExposedSecretReport")
    )
    rows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    platform_review: list[dict[str, Any]] = []
    secret_rows: list[dict[str, Any]] = []
    secret_risks: list[dict[str, Any]] = []
    secret_platform_review: list[dict[str, Any]] = []
    for report in reports:
        summary = report.get("report", {}).get("summary", {}) or report.get("summary", {}) or {}
        critical = int(summary.get("criticalCount") or summary.get("critical") or 0)
        high = int(summary.get("highCount") or summary.get("high") or 0)
        secret_count = _trivy_secret_count(report, summary)
        namespace = _ns_name(report)
        tier = _registry_scan_report_tier(index, report)
        row = {"asset": _asset(report).key, "kind": report.get("kind"), "namespace": namespace, "tier": tier, "critical": critical, "high": high, "secrets": secret_count, "summary": summary}
        kind = report.get("kind")
        if kind in {"SecretReport", "ExposedSecretReport"} or secret_count:
            secret_rows.append(row)
            if secret_count:
                if tier == "platform":
                    secret_platform_review.append(row)
                else:
                    secret_risks.append(row)
        else:
            rows.append(row)
        if kind in {"VulnerabilityReport", "ClusterVulnerabilityReport"} and (critical or high):
            if tier == "platform":
                platform_review.append(row)
            else:
                risks.append(row)
    return rows, risks, platform_review, secret_rows, secret_risks, secret_platform_review, not reports


def _trivy_secret_count(report: dict[str, Any], summary: dict[str, Any]) -> int:
    summary_count = int(summary.get("secretCount") or summary.get("secrets") or summary.get("secret") or 0)
    secrets = report.get("report", {}).get("secrets") or report.get("secrets") or []
    checks = report.get("report", {}).get("checks") or report.get("checks") or []
    results = report.get("report", {}).get("results") or report.get("results") or []
    detail_count = 0
    if isinstance(secrets, list):
        detail_count += len(secrets)
    if isinstance(checks, list):
        detail_count += sum(1 for item in checks if "secret" in str(item.get("type") or item.get("category") or item.get("title") or "").lower())
    if isinstance(results, list):
        detail_count += sum(1 for item in results if "secret" in str(item.get("class") or item.get("type") or item.get("category") or "").lower())
    return max(summary_count, detail_count)


def check_persistence_runtime_monitoring(index: ResourceIndex, task_id: str) -> list[Finding]:
    falco_like = _falco_events(index)
    pod_pvc_index = _pod_pvc_reference_index(index)
    pod_volume_index = _pod_volume_reference_index(index)
    volume_mount_risks = []
    platform_volume_mount_review = []
    for obj in _workloads(index) + index.by_kind("Pod"):
        volumes_by_name = {
            volume.get("name"): volume
            for volume in _pod_spec(obj).get("volumes", []) or []
            if volume.get("name")
        }
        for c in _containers(obj):
            for mount in c.get("volumeMounts", []) or []:
                path = mount.get("mountPath", "")
                volume = volumes_by_name.get(mount.get("name"), {})
                host_path = volume.get("hostPath", {}).get("path")
                volume_type = _volume_source_type(volume)
                mount_risks = _volume_escape_risks(path, host_path, mount, volume_type)
                if mount_risks:
                    row = {"asset": _asset(obj).key, "mountPath": path, "hostPath": host_path, "volumeType": volume_type, "subPath": mount.get("subPath"), "mountPropagation": mount.get("mountPropagation"), "risks": mount_risks}
                    if _namespace_tier_for_name(index, _ns_name(obj)) == "platform":
                        platform_volume_mount_review.append(row)
                    else:
                        volume_mount_risks.append(row)
    audit_rows, audit_risks, audit_platform_review = _persistence_audit_event_rows(index)
    runtime_categories = _persistence_runtime_categories(falco_like, pod_pvc_index, audit_risks, pod_volume_index)
    pvc_rows, pvc_risks = _pvc_mount_anomaly_rows(index)
    source_summary = _runtime_monitor_source_summary(index, falco_like, audit_rows)
    incident_ledger = _persistence_incident_ledger(falco_like, audit_risks, pvc_risks, pod_pvc_index, pod_volume_index)
    runtime_category_observed = {**runtime_categories, "source": source_summary}
    runtime_category_status: FindingStatus = "FAIL" if runtime_categories["risks"] else "PASS" if source_summary["event_stream_present"] else "UNKNOWN"
    findings = [
        _cluster_finding(task_id, "CN-39", "CN-PER-004-falco-events", "Falco/Audit/Event 数据源检查", "PASS" if source_summary["source_present"] else "UNKNOWN", "info" if source_summary["source_present"] else "high", "Falco/Audit/Event 数据源覆盖", source_summary, "Falco events, audit/events, or Falco workload", "接入 Falco 事件流、Kubernetes Event 或 apiserver audit log；无异常事件时保留数据源健康证据。"),
        _cluster_finding(task_id, "CN-39", "CN-PER-004-incident-ledger", "持久化异常事件台账", "PASS" if source_summary["event_stream_present"] else "UNKNOWN", "info" if source_summary["event_stream_present"] else "high", "归一化 Falco/Audit/Event/PVC 异常事件，形成可追溯历史台账", incident_ledger, "normalized runtime persistence incident ledger", "将 Falco、Kubernetes Event 和 apiserver audit log 持续写入事件台账，并保留 Pod/PVC/Namespace 关联。"),
        _cluster_finding(task_id, "CN-39", "CN-PER-004-runtime-event-classification", "运行时持久化异常分类检查", runtime_category_status, "high" if runtime_category_status == "FAIL" else "info", "Falco/Audit/Event 流中的持久化异常分类；仅发现监控 workload 但没有事件流时不视为已完成分类", runtime_category_observed, "no abnormal write/shell/sensitive path/pvc event with runtime event stream present", "为 Falco/运行时日志建立异常写入、敏感路径访问、容器 shell 和 PVC 访问分类告警。"),
        _cluster_finding(task_id, "CN-39", "CN-PER-004-risky-volume-mount", "敏感路径挂载检查", "FAIL" if volume_mount_risks else "PASS", "high" if volume_mount_risks else "info", "业务/默认 namespace 敏感路径挂载", {"risks": volume_mount_risks, "platform_review": platform_volume_mount_review[:50], "platform_review_count": len(platform_volume_mount_review)}, [], "避免将宿主敏感路径或根目录挂载进业务容器；平台/安全组件 hostPath 需记录最小化和例外依据。"),
        _cluster_finding(task_id, "CN-39", "CN-PER-004-audit-persistence-event", "Audit/Event 持久化异常检查", "FAIL" if audit_risks else "PASS" if audit_rows else "UNKNOWN", "high" if audit_risks else "info", "AuditLogEvent/Event 持久化异常", {"events": audit_rows, "risks": audit_risks, "platform_review": audit_platform_review[:50], "platform_review_count": len(audit_platform_review)}, "no suspicious PV/PVC/Pod volume audit event", "接入 apiserver audit log 与 Kubernetes Event，告警 PVC/PV 删除、Pod hostPath/PVC 异常变更和挂载失败；平台组件事件单独复核。"),
        _cluster_finding(task_id, "CN-39", "CN-PER-004-pvc-mount-anomaly", "PVC 异常挂载检查", "FAIL" if pvc_risks else "PASS" if pvc_rows else "UNKNOWN", "high" if pvc_risks else "info", "PVC 挂载关系", {"mounts": pvc_rows, "risks": pvc_risks}, "no sensitive mount path or unexpected multi-workload RWO mount", "限制 PVC 挂载路径，避免多个 workload 共享 RWO PVC；必要时使用 RWX 并补充访问控制。"),
    ]
    for event in falco_like[:20]:
        severity = _falco_event_severity(event)
        status: FindingStatus = "FAIL" if severity in {"critical", "high"} else "WARN"
        observed = _falco_event_observed(event, pod_pvc_index, pod_volume_index)
        categories = _persistence_runtime_event_categories(event, observed)
        rule_id, title_suffix = _falco_runtime_rule_for_categories(categories)
        linked_asset = _falco_linked_asset(index, event, observed)
        event_observed = {**observed, "categories": categories, "linked_asset": linked_asset.key}
        findings.append(
            _finding(
                task_id,
                "CN-39",
                rule_id,
                f"Falco {title_suffix}: {event.get('rule', _meta(event).get('name', 'unknown'))}",
                status,
                severity,
                linked_asset,
                Evidence("Falco 事件关联运行时异常或敏感持久化访问，并关联 Pod/PVC/Namespace 上下文", linked_asset, "FalcoEvent", event_observed, "no runtime persistence anomaly"),
                "审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。",
            )
        )
    return findings


SENSITIVE_CONTAINER_PATHS = {"/", "/etc", "/host", "/proc", "/sys", "/root", "/dev", "/run", "/var/lib", "/var/run", "/var/run/docker.sock", "/run/containerd/containerd.sock"}


def _persistence_runtime_categories(events: list[dict[str, Any]], pod_pvc_index: dict[tuple[str, str], list[dict[str, Any]]], audit_risks: list[dict[str, Any]] | None = None, pod_volume_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    counts = {"abnormal_write": 0, "sensitive_path": 0, "shell": 0, "pvc_or_volume": 0}
    risks: list[dict[str, Any]] = []
    for event in events:
        file_path = str(_falco_field(event, "file", "path", "fd.name") or "")
        observed = _falco_event_observed(event, pod_pvc_index, pod_volume_index or {})
        categories = _persistence_runtime_event_categories(event, observed)
        for category in categories:
            counts[category] += 1
        if categories:
            risks.append({"asset": _asset(event).key, "categories": categories, "rule": event.get("rule"), "output": event.get("output"), "namespace": observed.get("namespace"), "pod": observed.get("pod"), "pvc_refs": observed.get("pvc_refs"), "file": file_path or None})
    for row in audit_risks or []:
        text = json.dumps(row, ensure_ascii=False, default=str).lower()
        categories = []
        resource = str(row.get("resource") or "").lower()
        verb = str(row.get("verb") or "").lower()
        risk_text = " ".join(str(risk).lower() for risk in row.get("risks", []) or [])
        if (
            resource in {"persistentvolumes", "persistentvolumeclaims", "pv", "pvc"} and verb in {"delete", "patch", "update"}
        ) or any(token in text for token in ["write", "modify", "chmod", "chown"]) or "delete operation" in risk_text or "patch operation" in risk_text or "update operation" in risk_text:
            categories.append("abnormal_write")
        if any(token in text for token in ["/etc", "/proc", "/sys", "/root", "/var/lib/kubelet", "hostpath", "sensitive"]):
            categories.append("sensitive_path")
        if any(token in text for token in ["pvc", "persistentvolume", "volume", "mount", "hostpath"]):
            categories.append("pvc_or_volume")
        for category in set(categories):
            counts[category] += 1
        if categories:
            risks.append(
                {
                    "asset": row.get("asset"),
                    "categories": sorted(set(categories)),
                    "source_kind": row.get("source_kind"),
                    "namespace": row.get("namespace"),
                    "name": row.get("name"),
                    "pvc": row.get("pvc"),
                    "time": row.get("time"),
                    "target_asset": row.get("target_asset"),
                    "pvc_refs": row.get("pvc_refs", []),
                    "volume_refs": row.get("volume_refs", []),
                    "risks": row.get("risks", []),
                    "message": row.get("message"),
                }
            )
    return {"counts": counts, "risks": risks}


def _persistence_incident_ledger(
    falco_events: list[dict[str, Any]],
    audit_risks: list[dict[str, Any]],
    pvc_risks: list[dict[str, Any]],
    pod_pvc_index: dict[tuple[str, str], list[dict[str, Any]]],
    pod_volume_index: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[str, Any]:
    incidents: list[dict[str, Any]] = []
    for event in falco_events:
        observed = _falco_event_observed(event, pod_pvc_index, pod_volume_index)
        categories = _persistence_runtime_event_categories(event, observed)
        if not categories:
            continue
        incidents.append(
            {
                "source": "falco",
                "asset": _asset(event).key,
                "time": observed.get("time"),
                "namespace": observed.get("namespace"),
                "pod": observed.get("pod"),
                "pvc_refs": observed.get("pvc_refs"),
                "volume_refs": observed.get("volume_refs"),
                "categories": categories,
                "summary": event.get("rule") or event.get("output"),
            }
        )
    for row in audit_risks:
        pvc_refs, volume_refs = _runtime_refs_for_audit_row(row, pod_pvc_index, pod_volume_index)
        incidents.append(
            {
                "source": str(row.get("source_kind") or "event").lower(),
                "asset": row.get("asset"),
                "time": row.get("time"),
                "namespace": row.get("namespace"),
                "pod": row.get("name") if row.get("target_kind") == "Pod" else None,
                "target_kind": row.get("target_kind"),
                "target_name": row.get("name"),
                "target_asset": row.get("target_asset"),
                "pvc_refs": pvc_refs,
                "volume_refs": volume_refs,
                "categories": _audit_runtime_categories(row),
                "summary": row.get("message") or " ".join(row.get("risks", []) or []),
            }
        )
    for row in pvc_risks:
        incidents.append(
            {
                "source": "pvc-mount",
                "asset": row.get("asset"),
                "time": "unknown",
                "namespace": row.get("namespace"),
                "pod": None,
                "pvc_refs": [{"pvc": row.get("pvc"), "asset": f"PersistentVolumeClaim/{row.get('namespace')}/{row.get('pvc')}"}] if row.get("pvc") else [],
                "volume_refs": [{"volume": row.get("volume"), "mount_paths": row.get("mount_paths", [])}],
                "categories": ["pvc_or_volume"] + (["sensitive_path"] if any(str(risk).startswith("sensitive mount path") for risk in row.get("risks", []) or []) else []),
                "summary": "; ".join(row.get("risks", []) or []),
            }
        )
    category_counts: dict[str, int] = defaultdict(int)
    source_counts: dict[str, int] = defaultdict(int)
    namespaces: set[str] = set()
    pvcs: set[str] = set()
    pods: set[str] = set()
    targets: set[str] = set()
    for incident in incidents:
        source_counts[str(incident.get("source"))] += 1
        if incident.get("namespace"):
            namespaces.add(str(incident["namespace"]))
        if incident.get("pod"):
            pods.add(f"{incident.get('namespace')}/{incident.get('pod')}")
        if incident.get("target_asset"):
            targets.add(str(incident["target_asset"]))
        for category in incident.get("categories", []) or []:
            category_counts[str(category)] += 1
        for ref in incident.get("pvc_refs", []) or []:
            if ref.get("pvc"):
                pvcs.add(f"{incident.get('namespace')}/{ref.get('pvc')}")
    return {
        "incident_count": len(incidents),
        "source_counts": dict(sorted(source_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "affected_namespaces": sorted(namespaces),
        "affected_pods": sorted(pods),
        "affected_pvcs": sorted(pvcs),
        "affected_targets": sorted(targets),
        "incidents": incidents[:100],
    }


def _runtime_refs_for_audit_row(
    row: dict[str, Any],
    pod_pvc_index: dict[tuple[str, str], list[dict[str, Any]]],
    pod_volume_index: dict[tuple[str, str], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    namespace = str(row.get("namespace") or "")
    candidate_names = [str(row.get("name") or "")]
    if row.get("target_kind") == "ReplicaSet":
        parent = _replicaset_parent_name(candidate_names[0])
        if parent:
            candidate_names.append(parent)
    pvc_refs: list[dict[str, Any]] = []
    volume_refs: list[dict[str, Any]] = []
    for name in candidate_names:
        if not name:
            continue
        pvc_refs.extend(pod_pvc_index.get((namespace, name), []))
        volume_refs.extend(pod_volume_index.get((namespace, name), []))
    if row.get("pvc"):
        pvc_name = str(row["pvc"])
        pvc_refs.append({"pvc": pvc_name, "asset": f"PersistentVolumeClaim/{namespace}/{pvc_name}"})
    return _dedupe_ref_rows(pvc_refs), _dedupe_ref_rows(volume_refs)


def _dedupe_ref_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def _replicaset_parent_name(name: str) -> str | None:
    if not name or "-" not in name:
        return None
    parent, suffix = name.rsplit("-", 1)
    if len(suffix) >= 5 and re.fullmatch(r"[a-z0-9]+", suffix):
        return parent
    return None


def _audit_runtime_categories(row: dict[str, Any]) -> list[str]:
    text = json.dumps(row, ensure_ascii=False, default=str).lower()
    categories: set[str] = set()
    if any(token in text for token in ["delete operation", "patch operation", "update operation", "write", "modify"]):
        categories.add("abnormal_write")
    if any(token in text for token in ["/etc", "/proc", "/sys", "/root", "/var/lib/kubelet", "hostpath", "sensitive"]):
        categories.add("sensitive_path")
    if any(token in text for token in ["pvc", "persistentvolume", "volume", "mount", "hostpath"]):
        categories.add("pvc_or_volume")
    return [category for category in ("abnormal_write", "sensitive_path", "shell", "pvc_or_volume") if category in categories]


def _persistence_runtime_event_categories(event: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    text = json.dumps(event, ensure_ascii=False, default=str).lower()
    categories: set[str] = set()
    file_path = str(observed.get("file") or "")
    process = str(observed.get("process") or observed.get("shell") or "").lower()
    if any(token in text for token in ["write", "opened for writing", "modify", "chmod", "chown"]):
        categories.add("abnormal_write")
    if file_path.startswith(("/etc", "/proc", "/sys", "/root", "/host", "/var/lib")) or any(token in text for token in ["sensitive", "/etc/shadow", "/etc/passwd", "/var/lib/kubelet"]):
        categories.add("sensitive_path")
    if process in {"sh", "bash", "zsh", "dash", "ash"} or any(token in text for token in ["shell", "terminal", "bash", "sh spawned", "exec"]):
        categories.add("shell")
    if observed.get("pvc_refs") or observed.get("volume_refs") or any(token in text for token in ["pvc", "persistentvolume", "persistent volume", "volume mount"]):
        categories.add("pvc_or_volume")
    return [category for category in ("abnormal_write", "sensitive_path", "shell", "pvc_or_volume") if category in categories]


def _falco_runtime_rule_for_categories(categories: list[str]) -> tuple[str, str]:
    if "abnormal_write" in categories:
        return "CN-PER-004-runtime-abnormal-write", "异常文件写入"
    if "pvc_or_volume" in categories:
        return "CN-PER-004-volume-mount-escape", "卷挂载逃逸/异常访问"
    if "sensitive_path" in categories:
        return "CN-PER-004-sensitive-path-access", "敏感路径访问"
    if "shell" in categories:
        return "CN-PER-004-container-shell", "容器内 shell"
    return "CN-PER-004-falco-runtime-event", "运行时异常"


def _falco_linked_asset(index: ResourceIndex, event: dict[str, Any], observed: dict[str, Any]) -> AssetRef:
    namespace = observed.get("namespace") or _ns_name(event)
    pod = observed.get("pod")
    if pod:
        for obj in index.by_kind("Pod"):
            if _ns_name(obj) == namespace and _meta(obj).get("name") == pod:
                return _asset(obj)
        return AssetRef(kind="Pod", name=str(pod), namespace=namespace, api_version="v1")
    pvc_refs = observed.get("pvc_refs") or []
    if pvc_refs:
        pvc_name = pvc_refs[0].get("pvc")
        if pvc_name:
            return AssetRef(kind="PersistentVolumeClaim", name=str(pvc_name), namespace=namespace, api_version="v1")
    return _asset(event)


def _runtime_monitor_source_summary(index: ResourceIndex, falco_events: list[dict[str, Any]], audit_rows: list[dict[str, Any]]) -> dict[str, Any]:
    falco_workloads = [
        _asset(obj).key
        for obj in _workloads(index) + index.by_kind("Pod")
        if "falco" in _asset(obj).key.lower() or "falco" in json.dumps(_meta(obj).get("labels", {}), ensure_ascii=False, default=str).lower()
    ]
    raw_event_stream_count = len(falco_events) + len(index.by_kind("AuditLogEvent")) + len(index.by_kind("Event"))
    return {
        "falco_event_count": len(falco_events),
        "audit_event_count": len(audit_rows),
        "raw_event_stream_count": raw_event_stream_count,
        "falco_workloads": falco_workloads,
        "event_stream_present": raw_event_stream_count > 0,
        "source_present": bool(raw_event_stream_count or falco_workloads),
    }


def _persistence_audit_event_rows(index: ResourceIndex) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    platform_review: list[dict[str, Any]] = []
    pod_pvc_index = _pod_pvc_reference_index(index)
    pod_volume_index = _pod_volume_reference_index(index)
    for event in index.by_kind("AuditLogEvent") + index.by_kind("Event"):
        row = _persistence_audit_event_row(index, event)
        if not row:
            continue
        pvc_refs, volume_refs = _runtime_refs_for_audit_row(row, pod_pvc_index, pod_volume_index)
        row = {**row, "pvc_refs": pvc_refs, "volume_refs": volume_refs}
        rows.append(row)
        if row["risks"]:
            if row.get("tier") == "platform":
                platform_review.append(row)
            else:
                risks.append(row)
    return rows, risks, platform_review


def _persistence_audit_event_row(index: ResourceIndex, event: dict[str, Any]) -> dict[str, Any] | None:
    kind = event.get("kind")
    text = json.dumps(event, ensure_ascii=False, default=str).lower()
    risks: list[str] = []
    if kind == "AuditLogEvent":
        ref = event.get("objectRef") or {}
        resource = str(ref.get("resource") or event.get("resource") or "").lower()
        verb = str(event.get("verb") or "").lower()
        namespace = ref.get("namespace") or _ns_name(event)
        name = ref.get("name") or _meta(event).get("name")
        target_kind = _audit_resource_target_kind(resource)
        if resource in {"persistentvolumes", "persistentvolumeclaims", "pv", "pvc"} and verb in {"delete", "patch", "update"}:
            risks.append(f"{resource} {verb} operation")
        if resource in {"pods", "deployments", "statefulsets", "daemonsets", "jobs"} and verb in {"create", "patch", "update"}:
            if "hostpath" in text:
                risks.append("workload volume change includes hostPath")
            if "persistentvolumeclaim" in text or "claimname" in text:
                risks.append("workload volume change includes PVC mount")
            if any(path in text for path in ["/etc", "/proc", "/sys", "/root", "/var/lib/kubelet"]):
                risks.append("workload volume change references sensitive path")
        if not risks and resource not in {"persistentvolumes", "persistentvolumeclaims", "pods", "deployments", "statefulsets", "daemonsets", "jobs"}:
            return None
        pvc = name if resource in {"persistentvolumeclaims", "pvc"} else _extract_pvc_name(text)
        tier = _namespace_tier_for_name(index, namespace)
        return {"asset": _asset(event).key, "source_kind": kind, "time": _event_time(event), "verb": verb, "resource": resource, "namespace": namespace, "event_namespace": _ns_name(event), "target_kind": target_kind, "target_asset": _target_asset_key(target_kind, namespace, name), "name": name, "pvc": pvc, "actor": (event.get("user") or {}).get("username") or event.get("actor"), "tier": tier, "risks": risks}
    reason = str(event.get("reason") or "").lower()
    message = str(event.get("message") or event.get("note") or "").lower()
    involved = event.get("involvedObject") or event.get("regarding") or {}
    if any(token in reason + " " + message for token in ["failedmount", "failedattachvolume", "mountvolume", "hostpath", "persistentvolume", "pvc", "volume"]):
        if any(token in reason + " " + message for token in ["failed", "denied", "forbidden", "hostpath", "sensitive", "/etc", "/proc", "/sys", "pvc"]):
            risks.append("volume mount event indicates failure or sensitive volume")
        target_ref = _event_target_ref(event)
        namespace = target_ref.get("namespace") or involved.get("namespace") or _ns_name(event)
        tier = _namespace_tier_for_name(index, namespace)
        target_kind = target_ref.get("kind") or involved.get("kind")
        name = target_ref.get("name") or involved.get("name") or _meta(event).get("name")
        return {"asset": _asset(event).key, "source_kind": kind, "time": _event_time(event), "reason": event.get("reason"), "namespace": namespace, "event_namespace": _ns_name(event), "target_kind": target_kind, "target_asset": _target_asset_key(target_kind, namespace, name), "name": name, "pvc": _extract_pvc_name(message), "message": event.get("message") or event.get("note"), "tier": tier, "risks": risks}
    return None


def _event_time(event: dict[str, Any]) -> Any:
    for key in ("time", "eventTime", "firstTimestamp", "lastTimestamp", "deprecatedFirstTimestamp", "deprecatedLastTimestamp", "requestReceivedTimestamp", "stageTimestamp", "timestamp"):
        if event.get(key):
            return event.get(key)
    return _meta(event).get("creationTimestamp") or "unknown"


def _audit_resource_target_kind(resource: str) -> str | None:
    return {
        "pods": "Pod",
        "pod": "Pod",
        "deployments": "Deployment",
        "deployment": "Deployment",
        "statefulsets": "StatefulSet",
        "statefulset": "StatefulSet",
        "daemonsets": "DaemonSet",
        "daemonset": "DaemonSet",
        "jobs": "Job",
        "job": "Job",
        "persistentvolumeclaims": "PersistentVolumeClaim",
        "pvc": "PersistentVolumeClaim",
        "persistentvolumes": "PersistentVolume",
        "pv": "PersistentVolume",
    }.get(resource)


def _target_asset_key(kind: Any, namespace: Any, name: Any) -> str | None:
    if not kind or not name:
        return None
    if kind == "PersistentVolume":
        return f"{kind}/{name}"
    return f"{kind}/{namespace or 'default'}/{name}"


def _event_target_ref(event: dict[str, Any]) -> dict[str, str | None]:
    involved = event.get("involvedObject") or event.get("regarding") or {}
    message = str(event.get("message") or event.get("note") or "")
    match = re.search(r"\b(Pod|Deployment|ReplicaSet|DaemonSet|StatefulSet|Job)\s+([a-z0-9]([-a-z0-9]*[a-z0-9])?)/([a-z0-9]([-a-z0-9.]*[a-z0-9])?)", message)
    if match:
        return {"kind": match.group(1), "namespace": match.group(2), "name": match.group(4)}
    return {"kind": involved.get("kind"), "namespace": involved.get("namespace"), "name": involved.get("name")}


def _extract_pvc_name(text: str) -> str | None:
    match = re.search(r"\bpvc[ /:]([a-z0-9]([-a-z0-9]*[a-z0-9])?)", text, re.IGNORECASE)
    return match.group(1) if match else None


def _pvc_mount_anomaly_rows(index: ResourceIndex) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pvc_modes = {(_ns_name(pvc), _meta(pvc).get("name")): set(pvc.get("spec", {}).get("accessModes") or []) for pvc in index.by_kind("PersistentVolumeClaim")}
    rows: list[dict[str, Any]] = []
    usage: dict[tuple[str, str], set[str]] = defaultdict(set)
    for obj in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        ns = _ns_name(obj)
        spec = _pod_spec(obj)
        pvc_by_volume = {
            volume.get("name"): volume.get("persistentVolumeClaim", {}).get("claimName")
            for volume in spec.get("volumes", []) or []
            if volume.get("persistentVolumeClaim", {}).get("claimName")
        }
        if not pvc_by_volume:
            continue
        mounts_by_volume: dict[str, list[str]] = defaultdict(list)
        for container in _containers(obj):
            for mount in container.get("volumeMounts", []) or []:
                if mount.get("name") in pvc_by_volume:
                    mounts_by_volume[mount.get("name")].append(mount.get("mountPath", ""))
        for volume_name, claim_name in pvc_by_volume.items():
            key = (ns, claim_name)
            usage[key].add(_logical_workload_key(obj))
            rows.append({"asset": _asset(obj).key, "namespace": ns, "pvc": claim_name, "volume": volume_name, "mount_paths": mounts_by_volume.get(volume_name, []), "access_modes": sorted(pvc_modes.get(key, set()))})
    risks: list[dict[str, Any]] = []
    for row in rows:
        row_risks = []
        for path in row["mount_paths"]:
            if _sensitive_mount_path(path):
                row_risks.append(f"sensitive mount path {path}")
        key = (row["namespace"], row["pvc"])
        access_modes = set(row["access_modes"])
        if len(usage[key]) > 1 and not ({"ReadWriteMany", "ReadOnlyMany"} & access_modes):
            row_risks.append("RWO PVC mounted by multiple workloads")
        if row_risks:
            risks.append({**row, "risks": row_risks, "workloads": sorted(usage[key])})
    return rows, risks


def _pod_pvc_reference_index(index: ResourceIndex) -> dict[tuple[str, str], list[dict[str, Any]]]:
    refs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for obj in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        ns = _ns_name(obj)
        spec = _pod_spec(obj)
        pvc_by_volume = {
            volume.get("name"): volume.get("persistentVolumeClaim", {}).get("claimName")
            for volume in spec.get("volumes", []) or []
            if volume.get("persistentVolumeClaim", {}).get("claimName")
        }
        if not pvc_by_volume:
            continue
        mount_paths: dict[str, list[str]] = defaultdict(list)
        for container in _containers(obj):
            for mount in container.get("volumeMounts", []) or []:
                if mount.get("name") in pvc_by_volume:
                    mount_paths[mount.get("name")].append(mount.get("mountPath", ""))
        ref_rows = [
            {"asset": _asset(obj).key, "pvc": claim_name, "volume": volume_name, "mount_paths": mount_paths.get(volume_name, [])}
            for volume_name, claim_name in pvc_by_volume.items()
        ]
        for name in _pod_reference_names(obj):
            refs[(ns, name)].extend(ref_rows)
    return refs


def _pod_volume_reference_index(index: ResourceIndex) -> dict[tuple[str, str], list[dict[str, Any]]]:
    refs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for obj in _workloads(index) + index.by_kind("Pod") + index.by_kind("Job") + index.by_kind("CronJob"):
        ns = _ns_name(obj)
        spec = _pod_spec(obj)
        volumes_by_name = {volume.get("name"): volume for volume in spec.get("volumes", []) or [] if volume.get("name")}
        if not volumes_by_name:
            continue
        mount_paths: dict[str, list[str]] = defaultdict(list)
        for container in _containers(obj):
            for mount in container.get("volumeMounts", []) or []:
                if mount.get("name") in volumes_by_name:
                    mount_paths[mount.get("name")].append(mount.get("mountPath", ""))
        ref_rows = []
        for volume_name, volume in volumes_by_name.items():
            volume_type = _volume_source_type(volume)
            if volume_type not in PERSISTENT_OR_HOST_VOLUME_TYPES:
                continue
            ref_rows.append(
                {
                    "asset": _asset(obj).key,
                    "volume": volume_name,
                    "volumeType": volume_type,
                    "hostPath": volume.get("hostPath", {}).get("path"),
                    "pvc": volume.get("persistentVolumeClaim", {}).get("claimName"),
                    "mount_paths": mount_paths.get(volume_name, []),
                }
            )
        if not ref_rows:
            continue
        for name in _pod_reference_names(obj):
            refs[(ns, name)].extend(ref_rows)
    return refs


def _pod_reference_names(obj: dict[str, Any]) -> set[str]:
    name = _meta(obj).get("name", "")
    kind = obj.get("kind")
    names = {name} if name else set()
    if kind == "StatefulSet" and name:
        names.add(f"{name}-0")
    return names


def _sensitive_mount_path(path: str) -> bool:
    if not path:
        return False
    normalized = path.rstrip("/") or "/"
    return normalized in SENSITIVE_CONTAINER_PATHS or normalized.startswith(("/etc/", "/proc/", "/sys/", "/root/", "/host/", "/dev/", "/run/", "/var/run/", "/var/lib/kubelet"))


def _logical_workload_key(obj: dict[str, Any]) -> str:
    meta = _meta(obj)
    if obj.get("kind") == "Pod":
        for owner in meta.get("ownerReferences") or []:
            if owner.get("controller") is True and owner.get("kind") and owner.get("name"):
                return f"{owner.get('kind')}/{_ns_name(obj)}/{owner.get('name')}"
    return _asset(obj).key


def _volume_source_type(volume: dict[str, Any]) -> str | None:
    for key in (
        "hostPath",
        "persistentVolumeClaim",
        "emptyDir",
        "configMap",
        "secret",
        "projected",
        "downwardAPI",
        "csi",
        "nfs",
    ):
        if volume.get(key) is not None:
            return key
    return None


PERSISTENT_OR_HOST_VOLUME_TYPES = {"hostPath", "persistentVolumeClaim", "nfs"}


def _volume_escape_risks(mount_path: str, host_path: str | None, mount: dict[str, Any], volume_type: str | None = None) -> list[str]:
    risks: list[str] = []
    if _sensitive_mount_path(mount_path) and volume_type in PERSISTENT_OR_HOST_VOLUME_TYPES:
        risks.append("sensitive container mount path")
    if host_path and _sensitive_mount_path(host_path):
        risks.append("sensitive hostPath source")
    if mount.get("mountPropagation") == "Bidirectional":
        risks.append("bidirectional mount propagation")
    sub_path = str(mount.get("subPath") or "")
    if _sensitive_mount_path(sub_path):
        risks.append("sensitive subPath")
    return risks


def _falco_events(index: ResourceIndex) -> list[dict[str, Any]]:
    events = []
    for obj in index.objects:
        if obj.get("kind") in {"FalcoEvent", "FalcoAlert"} or obj.get("source") == "falco":
            events.append(obj)
    return events


def _authlog_events(index: ResourceIndex) -> list[dict[str, Any]]:
    return [obj for obj in index.by_kind("AuthLogEvent") if not obj.get("source") or obj.get("source") == "authlog"]


def _falco_event_severity(event: dict[str, Any]) -> Severity:
    priority = str(event.get("priority", "")).lower()
    if priority in {"emergency", "alert", "critical"}:
        return "critical"
    if priority in {"error", "err"}:
        return "high"
    if priority in {"warning", "warn"}:
        return "medium"
    return "low"


def _falco_event_observed(event: dict[str, Any], pod_pvc_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None, pod_volume_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    namespace = _falco_field(event, "k8s_ns", "k8s.namespace.name", "k8s.ns", "k8s.namespace") or _ns_name(event)
    pod = _falco_field(event, "k8s_pod", "k8s.pod.name", "k8s.pod")
    return {
        "time": event.get("time") or _event_time(event),
        "priority": event.get("priority"),
        "rule": event.get("rule"),
        "output": event.get("output"),
        "namespace": namespace,
        "pod": pod,
        "container": _falco_field(event, "container.name", "container", "k8s.container.name", "k8s.container"),
        "file": _falco_field(event, "file", "path", "fd.name"),
        "process": _falco_field(event, "proc.name", "process", "shell"),
        "shell": _falco_field(event, "shell", "proc.name"),
        "pvc_refs": (pod_pvc_index or {}).get((namespace, pod), []),
        "volume_refs": (pod_volume_index or {}).get((namespace, pod), []),
    }


def _falco_field(event: dict[str, Any], *names: str) -> Any:
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    output_fields = event.get("output_fields") if isinstance(event.get("output_fields"), dict) else {}
    k8s = event.get("k8s") if isinstance(event.get("k8s"), dict) else {}
    container = event.get("container") if isinstance(event.get("container"), dict) else None
    for name in names:
        if name in event:
            value = event.get(name)
            if not isinstance(value, dict):
                return value
        if name in fields:
            return fields.get(name)
        if name in output_fields:
            return output_fields.get(name)
        if name.startswith("k8s."):
            value: Any = k8s
            for part in name.split(".")[1:]:
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, dict) and value.get("name") is not None:
                return value.get("name")
            if value is not None and not isinstance(value, dict):
                return value
        if name.startswith("container.") and container:
            value = container
            for part in name.split(".")[1:]:
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, dict) and value.get("name") is not None:
                return value.get("name")
            if value is not None and not isinstance(value, dict):
                return value
    return None


RULES: list[Rule] = [
    check_microservice_resilience,
    check_immutable_deployment_principle,
    check_container_immutability_controls,
    check_scaling_security,
    check_resource_policy_governance,
    check_scaling_behavior_defense,
    check_lifecycle_governance,
    check_authentication_mechanisms,
    check_dynamic_access_control,
    check_identity_hardening,
    check_etcd_security,
    check_pv_security,
    check_stateful_data_security,
    check_registry_security,
    check_persistence_runtime_monitoring,
]


def run_rules(index: ResourceIndex, task_id: str = "task-local") -> list[Finding]:
    findings_by_fp: dict[str, Finding] = {}
    for rule in RULES:
        for finding in rule(index, task_id):
            findings_by_fp[finding.fingerprint] = finding

    covered = {finding.checkpoint_id for finding in findings_by_fp.values()}
    for checkpoint in CLOUD_NATIVE_CHECKPOINTS:
        checkpoint_id = checkpoint.id
        if checkpoint_id not in covered:
            finding = _cluster_finding(task_id, checkpoint_id, f"{checkpoint.rule_group}-no-evidence", f"{checkpoint.name} 证据覆盖检查", "UNKNOWN", "info", "规则未生成证据", None, "at least one evidence", "补充采集源或规则实现。")
            findings_by_fp[finding.fingerprint] = finding
    return sorted(findings_by_fp.values(), key=lambda item: (item.checkpoint_id, item.rule_id, item.fingerprint))

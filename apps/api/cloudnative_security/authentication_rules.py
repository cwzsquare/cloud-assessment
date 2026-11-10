"""Focused CN-28 Kubernetes identity authentication assessment rules.

The rule and its helper functions are copied verbatim from main.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .collector import ResourceIndex
from .models import AssetRef, Evidence, Finding, FindingStatus, Severity

PLATFORM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "kyverno", "trivy-system", "falco", "calico-system", "tigera-operator"}


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


def _ns_name(obj: dict[str, Any]) -> str:
    return _meta(obj).get("namespace", "default")


def _workload_name(obj: dict[str, Any]) -> str:
    return _meta(obj).get("name", "unknown")


def _labels(obj: dict[str, Any]) -> dict[str, str]:
    return _meta(obj).get("labels", {}) or {}


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


def _intish(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


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

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .collector import ResourceIndex, collect_kubectl, collect_pve_kubectl, load_manifest_path
from .models import AssetRef, Evidence, Finding
from .rbac_matrix import build_rbac_matrix
from .rules import _finding, run_rules


@dataclass(frozen=True)
class AssessmentRequest:
    task_id: str
    profile: str = "cloud_native_full"
    target_id: str | None = None
    manifest: str | None = None
    kubeconfig: str | None = None
    pve_ssh: str | None = None
    control_plane_ip: str = "10.20.0.11"
    ssh_key: str = "/root/.ssh/agent_lab"
    ssh_user: str = "agent"
    extra_manifests: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterResult:
    tool_id: str
    findings: list[Finding]
    raw_summary: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


class ToolAdapter(Protocol):
    tool_id: str

    def healthcheck(self) -> dict[str, Any]:
        ...

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        ...


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resource_inventory(index: ResourceIndex) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in index.objects:
        meta = obj.get("metadata", {}) or {}
        rows.append(
            {
                "kind": obj.get("kind", "Unknown"),
                "apiVersion": obj.get("apiVersion"),
                "namespace": meta.get("namespace"),
                "name": meta.get("name", "unknown"),
                "labels": meta.get("labels", {}) or {},
                "spec_summary": _resource_spec_summary(obj),
            }
        )
    return sorted(rows, key=lambda row: (str(row["kind"]), str(row.get("namespace") or ""), str(row["name"])))


def _resource_claim_names(obj: dict[str, Any]) -> list[str]:
    claims = [
        vol.get("persistentVolumeClaim", {}).get("claimName")
        for vol in _resource_pod_spec(obj).get("volumes", []) or []
        if vol.get("persistentVolumeClaim", {}).get("claimName")
    ]
    if obj.get("kind") == "StatefulSet":
        claims.extend(
            template.get("metadata", {}).get("name") or template.get("name")
            for template in obj.get("spec", {}).get("volumeClaimTemplates", []) or []
            if template.get("metadata", {}).get("name") or template.get("name")
        )
    return sorted({str(claim) for claim in claims if claim})


def _resource_pod_spec(obj: dict[str, Any]) -> dict[str, Any]:
    if obj.get("kind") == "Pod":
        return obj.get("spec", {}) or {}
    return obj.get("spec", {}).get("template", {}).get("spec", {}) or {}


def _resource_template_labels(obj: dict[str, Any]) -> dict[str, Any]:
    if obj.get("kind") == "Pod":
        return obj.get("metadata", {}).get("labels", {}) or {}
    return obj.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {}) or {}


def _resource_spec_summary(obj: dict[str, Any]) -> dict[str, Any]:
    kind = obj.get("kind")
    spec = obj.get("spec", {}) or {}
    if kind == "Service":
        return {
            "type": spec.get("type", "ClusterIP"),
            "selector": spec.get("selector", {}) or {},
            "ports": [
                {
                    "name": port.get("name"),
                    "protocol": port.get("protocol", "TCP"),
                    "port": port.get("port"),
                    "targetPort": port.get("targetPort"),
                    "nodePort": port.get("nodePort"),
                }
                for port in spec.get("ports", []) or []
            ],
        }
    if kind == "PersistentVolumeClaim":
        return {
            "storageClassName": spec.get("storageClassName"),
            "accessModes": spec.get("accessModes", []) or [],
            "volumeName": spec.get("volumeName"),
        }
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        return {
            "replicas": spec.get("replicas"),
            "serviceName": spec.get("serviceName"),
            "selector": spec.get("selector", {}) or {},
            "templateLabels": _resource_template_labels(obj),
            "claims": _resource_claim_names(obj),
        }
    if kind == "Pod":
        return {"templateLabels": _resource_template_labels(obj), "claims": _resource_claim_names(obj)}
    return {}


class CloudNativeAdapter:
    tool_id = "cloud_native"

    def healthcheck(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "status": "ready", "modes": ["manifest", "kubeconfig", "pve_ssh"]}

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        if request.manifest:
            index = load_manifest_path(request.manifest)
            mode = "manifest"
        elif request.kubeconfig:
            index = collect_kubectl(request.kubeconfig)
            mode = "kubeconfig"
        elif request.pve_ssh:
            index = collect_pve_kubectl(request.pve_ssh, request.control_plane_ip, request.ssh_key, request.ssh_user)
            mode = "pve_ssh"
        else:
            raise ValueError("CloudNativeAdapter requires manifest, kubeconfig, or pve_ssh")
        for extra_manifest in request.extra_manifests:
            extra_index = load_manifest_path(extra_manifest)
            index.objects.extend(extra_index.objects)
            index.warnings.extend(extra_index.warnings)
        findings = run_rules(index, request.task_id)
        rbac_matrix = build_rbac_matrix(index)
        raw_summary = {
            "mode": mode,
            "object_count": len(index.objects),
            "kind_count": len(index.kinds()),
            "kinds": sorted(index.kinds()),
            "resource_inventory": _resource_inventory(index),
            "schema_version": "kubernetes-json/v1",
            "collected_at": _utc_now_iso(),
            "rbac_matrix": rbac_matrix,
        }
        return AdapterResult(self.tool_id, findings, raw_summary, index.warnings)


class CloudApiSecurityAdapterStub:
    tool_id = "cloud_api_stub"

    def healthcheck(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "status": "stub", "note": "mock cloud API security evidence"}

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        account = request.options.get("cloud_account", "demo-cloud-account")
        region = request.options.get("cloud_region", "mock-region-1")
        endpoint = request.options.get("api_endpoint", "https://api.example.invalid")
        auth_mode = request.options.get("api_auth_mode", "access_key")
        account_asset = AssetRef(kind="CloudAccount", name=account)
        endpoint_asset = AssetRef(kind="CloudApiEndpoint", name=endpoint, labels={"region": region, "auth_mode": auth_mode})
        findings = [
            _finding(request.task_id, "INT-8", "INT-API-001-stub-adapter", "云上 API 安全评估工具 stub 接入", "PASS", "info", account_asset, Evidence("Cloud API stub 已按统一 Finding 输出", account_asset, observed=self.tool_id, expected="normalized finding"), "替换为真实云厂商 API adapter 后保留统一输出。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-key-rotation", "云上 API 参数标准化与凭据姿态占位", "PASS", "info", account_asset, Evidence("stub 已接收并标准化云账号、区域和认证模式参数", account_asset, observed={"auth_mode": auth_mode, "rotation_days": "stub-placeholder", "mfa_check": "stub-placeholder"}, expected="standardized cloud API adapter parameters"), "真实云 API adapter 接入后用同一 Finding 合约替换轮换、MFA 和访问密钥证据。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-public-admin", "云上管理 API 暴露面 mock 风险样例", "WARN", "medium", endpoint_asset, Evidence("mock endpoint 用于验证 API 工具详情页和统一态势汇总，不代表真实云暴露结论", endpoint_asset, observed={"endpoint": endpoint, "source_restriction": "stub-placeholder", "mock_risk": "public-admin-sample"}, expected="mock finding visible in API detail view"), "真实 adapter 应校验管理 API 暴露范围、来源白名单、mTLS 或专线接入。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-audit-log", "云上 API 审计日志占位证据", "PASS", "info", account_asset, Evidence("stub 已声明 cloud audit log 能力和统一字段占位，后续真实 adapter 可直接替换", account_asset, observed={"audit_log_source": "stub-placeholder", "fields": ["actor", "source_ip", "action", "result", "time"]}, expected="cloud audit log adapter slot"), "接入真实云厂商审计日志后补充 API 调用来源、失败认证和高危操作证据。", self.tool_id),
        ]
        raw_summary = {
            "kind": "cloud_api_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "target_parameters": {
                "cloud_account": account,
                "cloud_region": region,
                "api_endpoint": endpoint,
                "api_auth_mode": auth_mode,
            },
            "capabilities": ["credential_posture", "api_exposure", "audit_log_presence", "mfa_and_rotation"],
            "integration_contract": {"input": "AssessmentRequest.options", "output": "Finding[]", "detail_view_tool_id": self.tool_id},
            "mock_assets": [account_asset.kind, endpoint_asset.kind],
            "mock_findings": len(findings),
        }
        return AdapterResult(self.tool_id, findings, raw_summary)


class SmartCloudSecurityAdapterStub:
    tool_id = "smart_cloud_stub"

    def healthcheck(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "status": "stub", "note": "mock AI/smart cloud security evidence"}

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        workspace = request.options.get("smart_workspace", "demo-gpu-workspace")
        gpu_pool = request.options.get("gpu_pool", "mock-a100-pool")
        model_endpoint = request.options.get("model_endpoint", "mock-llm-endpoint")
        workspace_asset = AssetRef(kind="SmartCloudWorkspace", name=workspace, labels={"gpu_pool": gpu_pool})
        model_asset = AssetRef(kind="ModelEndpoint", name=model_endpoint, labels={"workspace": workspace})
        findings = [
            _finding(request.task_id, "INT-10", "INT-SMART-001-stub-adapter", "智算云安全评估工具 stub 接入", "PASS", "info", workspace_asset, Evidence("SmartCloud stub 已按统一 Finding 输出", workspace_asset, observed=self.tool_id, expected="normalized finding"), "替换为真实智算云 adapter 后保留统一输出。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-image-provenance", "智算云镜像来源占位证据", "PASS", "info", workspace_asset, Evidence("stub 已声明 GPU workload 镜像来源检查能力和统一字段占位", workspace_asset, observed={"image_provenance": "stub-placeholder", "signature_check": "stub-placeholder"}, expected="trusted registry/signature adapter slot"), "接入真实智算云后检查镜像签名、模型数据路径和 GPU 节点隔离。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-model-auth", "模型服务鉴权 mock 风险样例", "WARN", "medium", model_asset, Evidence("mock 模型服务风险用于验证智算云详情页和统一态势汇总，不代表真实模型服务结论", model_asset, observed={"endpoint": model_endpoint, "authn": "stub-placeholder", "mock_risk": "model-auth-sample"}, expected="mock finding visible in SmartCloud detail view"), "真实 adapter 应检查模型服务入口鉴权、调用配额、来源限制和审计日志。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-dataset-audit", "训练数据集访问审计占位证据", "PASS", "info", workspace_asset, Evidence("stub 已声明数据集访问审计能力和统一字段占位", workspace_asset, observed={"dataset_audit_source": "stub-placeholder", "fields": ["dataset", "actor", "operation", "result", "time"]}, expected="dataset access audit adapter slot"), "接入真实智算云后补充数据集访问日志、跨租户共享和敏感数据路径证据。", self.tool_id),
        ]
        raw_summary = {
            "kind": "smart_cloud_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "target_parameters": {
                "smart_workspace": workspace,
                "gpu_pool": gpu_pool,
                "model_endpoint": model_endpoint,
            },
            "capabilities": ["gpu_workload_posture", "model_endpoint_exposure", "dataset_audit", "image_provenance"],
            "integration_contract": {"input": "AssessmentRequest.options", "output": "Finding[]", "detail_view_tool_id": self.tool_id},
            "mock_assets": [workspace_asset.kind, model_asset.kind],
            "mock_findings": len(findings),
        }
        return AdapterResult(self.tool_id, findings, raw_summary)


class RegistrySecurityAdapterStub:
    tool_id = "registry_stub"

    def healthcheck(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "status": "stub", "note": "mock Harbor/Registry security adapter contract"}

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        registry = request.options.get("registry_endpoint", "https://registry.example.invalid")
        registry_asset = AssetRef(kind="RegistryEndpoint", name=registry)
        findings = [
            _finding(
                request.task_id,
                "INT-7",
                "INT-FRAME-001-registry-adapter-stub",
                "Harbor/Registry 工具 adapter stub 接入",
                "PASS",
                "info",
                registry_asset,
                Evidence(
                    "Registry adapter stub 已按 ToolAdapter 合约接入；CN-38 规则可消费 RegistryEndpoint/RegistryAuditEvent/scan evidence",
                    registry_asset,
                    observed={
                        "tool_id": self.tool_id,
                        "capabilities": ["registry_endpoint_posture", "registry_audit_events", "vulnerability_scan", "secret_scan"],
                    },
                    expected="registered Harbor/Registry adapter slot",
                ),
                "替换为真实 Harbor/Registry API adapter 后保留统一 ToolAdapter 和 Finding 合约。",
                self.tool_id,
            )
        ]
        raw_summary = {
            "kind": "registry_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "target_parameters": {"registry_endpoint": registry},
            "capabilities": ["registry_endpoint_posture", "registry_audit_events", "vulnerability_scan", "secret_scan"],
            "integration_contract": {
                "input": "AssessmentRequest.options + RegistryEndpoint/RegistryAuditEvent evidence",
                "output": "Finding[] + raw registry evidence",
                "detail_view_tool_id": self.tool_id,
            },
            "mock_assets": [registry_asset.kind],
            "mock_findings": len(findings),
        }
        return AdapterResult(self.tool_id, findings, raw_summary)


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.tool_id] = adapter

    def get(self, tool_id: str) -> ToolAdapter:
        return self._adapters[tool_id]

    def healthcheck(self) -> dict[str, Any]:
        return {tool_id: adapter.healthcheck() for tool_id, adapter in sorted(self._adapters.items())}

    def for_profile(self, profile: str) -> list[ToolAdapter]:
        if profile == "all_tools_demo":
            return [self._adapters["cloud_native"], self._adapters["cloud_api_stub"], self._adapters["smart_cloud_stub"], self._adapters["registry_stub"]]
        return [self._adapters["cloud_native"]]


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(CloudNativeAdapter())
    registry.register(CloudApiSecurityAdapterStub())
    registry.register(SmartCloudSecurityAdapterStub())
    registry.register(RegistrySecurityAdapterStub())
    return registry

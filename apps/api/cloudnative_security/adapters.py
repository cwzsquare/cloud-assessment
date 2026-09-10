from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .collector import ResourceIndex, collect_kubectl, collect_pve_kubectl, load_manifest_path
from .collection_executor import CollectionExecutor
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
    capabilities = (
        "resource_inventory",
        "rbac",
        "control_plane_manifests",
        "auth_logs",
        "encryption_config",
        "certificate_metadata",
        "runtime_events",
    )

    def __init__(self, executor: CollectionExecutor | None = None) -> None:
        self.executor = executor or CollectionExecutor()

    def healthcheck(self) -> dict[str, Any]:
        return {"tool_id": self.tool_id, "status": "ready", "modes": ["manifest", "kubeconfig", "pve_ssh"], "capabilities": list(self.capabilities)}

    def evaluate(self, request: AssessmentRequest) -> AdapterResult:
        if request.manifest:
            mode = "manifest"
            collect = lambda: load_manifest_path(request.manifest)
        elif request.kubeconfig:
            mode = "kubeconfig"
            collect = lambda: collect_kubectl(request.kubeconfig)
        elif request.pve_ssh:
            mode = "pve_ssh"
            collect = lambda: collect_pve_kubectl(request.pve_ssh, request.control_plane_ip, request.ssh_key, request.ssh_user)
        else:
            mode = "unknown"
            collect = lambda: (_ for _ in ()).throw(ValueError("CloudNativeAdapter requires manifest, kubeconfig, or pve_ssh"))
        source = {"source_id": self.tool_id, "task_id": request.task_id, "name": self.tool_id, "metadata": {"mode": mode, "capabilities": list(self.capabilities)}}
        index = self.executor.execute(source, collect, request.options.get("collection_retry_policy", request.options.get("retry_policy")))
        for extra_manifest in request.extra_manifests:
            extra_index = load_manifest_path(extra_manifest)
            index.objects.extend(extra_index.objects)
            index.warnings.extend(extra_index.warnings)
        findings = run_rules(index, request.task_id)
        rbac_matrix = build_rbac_matrix(index)
        raw_summary = {
            "source_id": self.tool_id,
            "mode": mode,
            "stub_mode": False,
            "capabilities": list(self.capabilities),
            "object_count": len(index.objects),
            "kind_count": len(index.kinds()),
            "kinds": sorted(index.kinds()),
            # Sanitized objects retain node/config identity for structured
            # downstream analyzers without persisting Secret values.
            "objects": index.objects,
            "resource_inventory": _resource_inventory(index),
            "schema_version": "kubernetes-json/v1",
            "collected_at": _utc_now_iso(),
            "rbac_matrix": rbac_matrix,
            "collection_run": self.executor.last_run.to_dict() if self.executor.last_run else None,
            "collection_attempts": [attempt.to_dict() for attempt in self.executor.last_attempts],
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
        source_input = request.options.get("cloud_api_input") or {
            "schema_version": "cloud-api-tool/v1",
            "target": {"account_id": account, "region": region, "endpoint": endpoint},
            "authentication": {"mode": auth_mode, "mfa_enabled": True, "key_age_days": 41},
            "api_assets": [
                {"api_id": "api-cluster-admin", "method": "GET", "path": "/v1/projects/demo/clusters", "tls": True, "authorization": "iam-role"},
                {"api_id": "api-public-admin", "method": "POST", "path": "/v1/admin/scale", "tls": True, "authorization": "public"},
            ],
            "audit_events": [{"action": "scale", "actor": "demo-operator", "result": "success", "source_ip": "10.10.8.21"}],
        }
        findings = [
            _finding(request.task_id, "INT-8", "INT-API-001-stub-adapter", "云上 API 评估结果已接入", "PASS", "info", account_asset, Evidence("示例 API 工具输出已转换为统一评估结果", account_asset, observed={"input_schema": source_input["schema_version"], "finding_format": "Finding"}, expected="normalized API assessment result"), "后续替换为真实云上 API 工具输入，保持当前统一输出字段。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-key-rotation", "云账号凭据保护", "PASS", "info", account_asset, Evidence("示例数据包含认证方式、多因素认证和密钥年龄字段", account_asset, observed=source_input["authentication"], expected={"mfa_enabled": True, "key_age_days": "<=90"}), "真实数据接入后补充密钥轮换、MFA 和 IAM 角色证据。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-public-admin", "管理 API 不应对公网开放", "WARN", "medium", endpoint_asset, Evidence("示例 API 清单发现一个授权方式为 public 的管理接口", endpoint_asset, observed={"api_id": "api-public-admin", "authorization": "public", "tls": True}, expected={"authorization": "iam-role or mTLS", "public_access": False}), "限制管理 API 的访问来源，启用细粒度授权，并保留调用审计记录。", self.tool_id),
            _finding(request.task_id, "INT-8", "INT-API-001-audit-log", "高风险 API 操作应可追溯", "PASS", "info", account_asset, Evidence("示例输入包含 API 操作人、来源地址、动作和结果", account_asset, observed={"event_count": len(source_input["audit_events"]), "fields": ["actor", "source_ip", "action", "result"]}, expected="audit fields complete"), "真实数据接入后补充失败认证、越权调用和高风险管理操作日志。", self.tool_id),
        ]
        raw_summary = {
            "kind": "cloud_api_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "input_mode": "fixture",
            "input_schema": "cloud-api-tool/v1",
            "input": source_input,
            "target_parameters": {
                "cloud_account": account,
                "cloud_region": region,
                "api_endpoint": endpoint,
                "api_auth_mode": auth_mode,
            },
            "capabilities": [],
            "integration_contract": {"input": "AssessmentRequest.options.cloud_api_input", "output": "Finding[]", "detail_view_tool_id": self.tool_id},
            "replacement_note": "当前为按标书 API 工具适配要求构造的示例输入；真实部门数据接入后替换 input，不改变 Finding[] 输出契约。",
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
        source_input = request.options.get("smart_cloud_input") or {
            "schema_version": "smart-cloud-tool/v1",
            "target": {"workspace": workspace, "gpu_pool": gpu_pool},
            "compute_nodes": [{"node_id": "gpu-node-01", "accelerator": "NVIDIA-A100", "tenant": "demo-team", "isolation": True}],
            "workloads": [{"workload_id": "training-job-demo", "framework": "PyTorch", "image": "registry.example.invalid/ml/train@sha256:demo", "dataset": "customer-risk-demo"}],
            "model_endpoints": [{"name": model_endpoint, "tls": True, "authentication": "iam-role", "audit_enabled": True}],
            "dataset_audit": [{"dataset": "customer-risk-demo", "actor": "demo-trainer", "operation": "read", "result": "success"}],
        }
        findings = [
            _finding(request.task_id, "INT-10", "INT-SMART-001-stub-adapter", "智算云评估结果已接入", "PASS", "info", workspace_asset, Evidence("示例智算云工具输出已转换为统一评估结果", workspace_asset, observed={"input_schema": source_input["schema_version"], "finding_format": "Finding"}, expected="normalized smart-cloud assessment result"), "后续替换为真实智算云工具输入，保持当前统一输出字段。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-image-provenance", "AI 工作负载镜像来源应可追溯", "PASS", "info", workspace_asset, Evidence("示例工作负载包含镜像摘要、AI 框架和计算节点隔离字段", workspace_asset, observed=source_input["workloads"][0], expected={"image": "digest-pinned", "isolation": True}), "真实数据接入后补充镜像签名、模型数据路径和 GPU 节点隔离证据。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-model-auth", "模型服务访问应经过身份认证", "WARN", "medium", model_asset, Evidence("示例模型服务用于验证鉴权和传输保护结果的统一展示", model_asset, observed=source_input["model_endpoints"][0], expected={"authentication": "iam-role or mTLS", "tls": True, "audit_enabled": True}), "真实数据接入后检查模型服务入口鉴权、调用配额、来源限制和审计日志。", self.tool_id),
            _finding(request.task_id, "INT-10", "INT-SMART-001-dataset-audit", "训练数据访问应保留审计记录", "PASS", "info", workspace_asset, Evidence("示例输入包含训练数据集访问主体、操作和结果", workspace_asset, observed={"event_count": len(source_input["dataset_audit"]), "fields": ["dataset", "actor", "operation", "result"]}, expected="dataset access audit"), "真实数据接入后补充跨租户共享、敏感数据路径和完整访问日志证据。", self.tool_id),
        ]
        raw_summary = {
            "kind": "smart_cloud_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "input_mode": "fixture",
            "input_schema": "smart-cloud-tool/v1",
            "input": source_input,
            "target_parameters": {
                "smart_workspace": workspace,
                "gpu_pool": gpu_pool,
                "model_endpoint": model_endpoint,
            },
            "capabilities": [],
            "integration_contract": {"input": "AssessmentRequest.options.smart_cloud_input", "output": "Finding[]", "detail_view_tool_id": self.tool_id},
            "replacement_note": "当前为按标书智算云工具适配要求构造的示例输入；真实部门数据接入后替换 input，不改变 Finding[] 输出契约。",
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
        image_asset = AssetRef(kind="ContainerImage", name="team-a/payment-api:1.4.2", labels={"registry": registry})
        source_input = request.options.get("registry_input") or {
            "schema_version": "registry-tool/v1",
            "registry": {"endpoint": registry, "tls": True, "anonymous_pull": False, "robot_account": "scanner-bot"},
            "images": [{"repository": "team-a/payment-api", "tag": "1.4.2", "digest": "sha256:demo-payment-api", "pull_secret": True}],
            "scan_results": [{"repository": "team-a/payment-api", "critical": 0, "high": 1, "medium": 4, "scanner": "trivy"}],
            "secret_scans": [{"repository": "team-a/payment-api", "secrets_found": 0}],
            "audit_events": [{"action": "pull", "repository": "team-a/payment-api", "actor": "scanner-bot", "result": "success"}],
        }
        findings = [
            _finding(
                request.task_id,
                "INT-7",
                "INT-FRAME-001-registry-adapter-stub",
                "镜像仓库评估结果已接入",
                "PASS",
                "info",
                registry_asset,
                Evidence("示例镜像仓库输出已转换为统一评估结果", registry_asset, observed={"input_schema": source_input["schema_version"], "finding_format": "Finding"}, expected="normalized registry assessment result"),
                "后续替换为真实 Harbor/Registry 工具输入，保持当前统一输出字段。",
                self.tool_id,
            ),
            _finding(
                request.task_id,
                "CN-38",
                "CN-REG-001-registry-posture",
                "镜像仓库应启用安全访问控制",
                "PASS",
                "info",
                registry_asset,
                Evidence("示例仓库配置包含 TLS、关闭匿名拉取和机器人账号字段", registry_asset, observed=source_input["registry"], expected={"tls": True, "anonymous_pull": False, "robot_account": "configured"}),
                "真实数据接入后补充仓库端 TLS、匿名访问、机器人账号权限和审计配置证据。",
                self.tool_id,
            ),
            _finding(
                request.task_id,
                "CN-38",
                "CN-REG-001-vulnerability-scan",
                "业务镜像不应携带高风险漏洞",
                "WARN",
                "high",
                image_asset,
                Evidence("示例扫描结果发现业务镜像存在 1 个高危漏洞", image_asset, observed=source_input["scan_results"][0], expected={"critical": 0, "high": 0}),
                "修复或升级受影响组件，重新构建镜像并在发布前完成漏洞复核。",
                self.tool_id,
            ),
            _finding(
                request.task_id,
                "CN-38",
                "CN-REG-001-secret-scan",
                "镜像中不应包含敏感凭据",
                "PASS",
                "info",
                image_asset,
                Evidence("示例密钥扫描结果未发现泄露凭据", image_asset, observed=source_input["secret_scans"][0], expected={"secrets_found": 0}),
                "真实数据接入后持续执行镜像密钥扫描，并阻断包含凭据的镜像发布。",
                self.tool_id,
            ),
        ]
        raw_summary = {
            "kind": "registry_stub_summary",
            "schema_version": "stub/v1",
            "collected_at": _utc_now_iso(),
            "stub_mode": True,
            "input_mode": "fixture",
            "input_schema": "registry-tool/v1",
            "input": source_input,
            "target_parameters": {"registry_endpoint": registry},
            "capabilities": [],
            "integration_contract": {
                "input": "AssessmentRequest.options.registry_input",
                "output": "Finding[] + raw registry evidence",
                "detail_view_tool_id": self.tool_id,
            },
            "replacement_note": "当前为按标书镜像仓库数据安全要求构造的示例输入；真实部门数据接入后替换 input，不改变 Finding[] 输出契约。",
            "mock_assets": [registry_asset.kind, image_asset.kind],
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

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import AdapterRegistry, AdapterResult, AssessmentRequest, default_registry
from .checkpoints import ASSESSMENT_CHECKPOINTS, CLOUD_NATIVE_CHECKPOINTS
from .integration import build_integration_pipeline
from .models import AssetRef, AssessmentReport, Evidence, Finding
from .rules import _finding
from .scoring import build_report
from .structured_analysis import build_structured_payload


@dataclass(frozen=True)
class DataQualitySummary:
    completeness: float
    freshness: float
    duplicate_rate: float
    unknown_rate: float
    schema_error_count: int
    collection_warning_count: int
    raw_snapshot_count: int
    normalized_finding_count: int
    stale_snapshot_count: int = 0
    missing_timestamp_count: int = 0
    checkpoint_coverage_count: int = 0
    checkpoint_total: int = 0

@dataclass(frozen=True)
class OrchestratorResult:
    request: AssessmentRequest
    adapter_results: list[AdapterResult]
    findings: list[Finding]
    report: AssessmentReport
    data_quality: DataQualitySummary
    adapter_health: dict[str, Any]
    structured: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "request": asdict(self.request),
            "adapter_results": [asdict(result) for result in self.adapter_results],
            "findings": [asdict(finding) for finding in self.findings],
            "report": self.report.to_dict(),
            "data_quality": asdict(self.data_quality),
            "adapter_health": self.adapter_health,
            "structured": self.structured,
        }
        payload["summary"] = self.report.summary
        return payload


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    normalized: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint:
            fingerprint = finding.fingerprint
        else:
            fp_src = json.dumps(asdict(finding), sort_keys=True, ensure_ascii=False, default=str)
            fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()[:24]
        normalized[fingerprint] = finding
    return sorted(normalized.values(), key=lambda item: (item.tool_id, item.checkpoint_id, item.rule_id, item.fingerprint))


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _freshness_score(adapter_results: list[AdapterResult], now: datetime | None = None) -> tuple[float, int, int]:
    if not adapter_results:
        return 0.0, 0, 0
    now = now or datetime.now(timezone.utc)
    scores: list[int] = []
    stale_count = 0
    missing_count = 0
    for result in adapter_results:
        collected_at = _parse_time(result.raw_summary.get("collected_at"))
        if not collected_at:
            scores.append(0)
            missing_count += 1
            stale_count += 1
            continue
        age_seconds = max(0.0, (now - collected_at).total_seconds())
        if age_seconds <= 3600:
            scores.append(100)
        elif age_seconds <= 86400:
            scores.append(80)
        elif age_seconds <= 604800:
            scores.append(50)
            stale_count += 1
        else:
            scores.append(0)
            stale_count += 1
    return round(sum(scores) / len(scores), 2), stale_count, missing_count


def data_quality_summary(adapter_results: list[AdapterResult], findings: list[Finding]) -> DataQualitySummary:
    raw_snapshot_count = len(adapter_results)
    duplicate_rate = 0.0
    fingerprints = [finding.fingerprint for finding in findings]
    if fingerprints:
        duplicate_rate = round((len(fingerprints) - len(set(fingerprints))) / len(fingerprints) * 100, 2)
    unknown_rate = round(sum(1 for finding in findings if finding.status == "UNKNOWN") / len(findings) * 100, 2) if findings else 100.0
    covered = {finding.checkpoint_id for finding in findings}
    covered_count = len(covered & {checkpoint.id for checkpoint in ASSESSMENT_CHECKPOINTS})
    checkpoint_total = len(ASSESSMENT_CHECKPOINTS)
    completeness = round(covered_count / checkpoint_total * 100, 2)
    freshness, stale_count, missing_count = _freshness_score(adapter_results)
    warnings = [warning for result in adapter_results for warning in result.warnings]
    schema_error_count = sum(1 for warning in warnings if any(token in warning.lower() for token in ["failed to parse", "jsondecode", "schema"]))
    return DataQualitySummary(completeness, freshness, duplicate_rate, unknown_rate, schema_error_count, len(warnings), raw_snapshot_count, len(findings), stale_count, missing_count, covered_count, checkpoint_total)


def tool_summary(adapter_results: list[AdapterResult], findings: list[Finding], adapter_health: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for adapter_result in sorted(adapter_results, key=lambda item: item.tool_id):
        tool_findings = [finding for finding in findings if finding.tool_id == adapter_result.tool_id]
        health = (adapter_health or {}).get(adapter_result.tool_id, {})
        rows.append(
            {
                "tool_id": adapter_result.tool_id,
                "status": health.get("status", "ready"),
                "note": health.get("note"),
                "stub_mode": bool(adapter_result.raw_summary.get("stub_mode") or health.get("status") == "stub"),
                "schema_version": adapter_result.raw_summary.get("schema_version", "unknown"),
                "raw_kind": adapter_result.raw_summary.get("kind", "adapter_summary"),
                "object_count": adapter_result.raw_summary.get("object_count"),
                "finding_count": len(tool_findings),
                "fail_count": sum(1 for finding in tool_findings if finding.status == "FAIL"),
                "warn_count": sum(1 for finding in tool_findings if finding.status == "WARN"),
                "unknown_count": sum(1 for finding in tool_findings if finding.status == "UNKNOWN"),
                "warning_count": len(adapter_result.warnings),
                "summary_keys": sorted(adapter_result.raw_summary.keys()),
            }
        )
    platform_findings = [finding for finding in findings if finding.tool_id == "platform"]
    if platform_findings:
        rows.append(
            {
                "tool_id": "platform",
                "status": "ready",
                "note": "derived findings",
                "stub_mode": False,
                "schema_version": "internal/v1",
                "raw_kind": "derived_findings",
                "object_count": None,
                "finding_count": len(platform_findings),
                "fail_count": sum(1 for finding in platform_findings if finding.status == "FAIL"),
                "warn_count": sum(1 for finding in platform_findings if finding.status == "WARN"),
                "unknown_count": sum(1 for finding in platform_findings if finding.status == "UNKNOWN"),
                "warning_count": 0,
                "summary_keys": ["integration_findings", "visualization_findings"],
            }
        )
    return rows


def _quality_status(ok: bool, warn: bool = False) -> tuple[str, str]:
    if ok:
        return "PASS", "info"
    if warn:
        return "WARN", "medium"
    return "FAIL", "high"


def data_quality_findings(request: AssessmentRequest, quality: DataQualitySummary) -> list[Finding]:
    asset = AssetRef(kind="AssessmentPipeline", name=request.task_id)
    observed = asdict(quality)
    completeness_status, completeness_severity = _quality_status(quality.completeness >= 95, quality.completeness >= 90)
    freshness_status, freshness_severity = _quality_status(quality.freshness >= 90, quality.freshness >= 70)
    duplicate_status, duplicate_severity = _quality_status(quality.duplicate_rate == 0, quality.duplicate_rate <= 2)
    unknown_status, unknown_severity = _quality_status(quality.unknown_rate <= 5, quality.unknown_rate <= 15)
    schema_status, schema_severity = _quality_status(quality.schema_error_count == 0)
    warning_status, warning_severity = _quality_status(quality.collection_warning_count == 0, quality.schema_error_count == 0)
    return [
        _finding(request.task_id, "INT-5", "INT-DATA-005-completeness", "数据完整性覆盖率", completeness_status, completeness_severity, asset, Evidence("评估任务应覆盖标书全部检查点", asset, observed=observed, expected="completeness >= 95%"), "补齐缺失 adapter、规则或平台派生 finding，确保所有标书检查点都有证据。", "platform"),
        _finding(request.task_id, "INT-5", "INT-DATA-005-freshness", "数据新鲜度评估", freshness_status, freshness_severity, asset, Evidence("raw snapshot 应带采集时间，且采集时间应足够新", asset, observed=observed, expected="freshness >= 90% and collected_at present"), "为每个 adapter raw_summary 写入 collected_at；避免使用过期离线快照。", "platform"),
        _finding(request.task_id, "INT-5", "INT-DATA-005-duplicate-rate", "重复数据率评估", duplicate_status, duplicate_severity, asset, Evidence("Finding fingerprint 去重后重复率应接近 0", asset, observed=observed, expected="duplicate_rate == 0"), "修正 fingerprint 生成逻辑，避免同一风险重复展示。", "platform"),
        _finding(request.task_id, "INT-5", "INT-DATA-005-unknown-rate", "UNKNOWN 证据不足率评估", unknown_status, unknown_severity, asset, Evidence("UNKNOWN finding 过高说明证据链不足", asset, observed=observed, expected="unknown_rate <= 5%"), "补充采集权限、增强采集器或在报告限制说明中标注不可见证据。", "platform"),
        _finding(request.task_id, "INT-5", "INT-DATA-005-schema-errors", "Schema 错误评估", schema_status, schema_severity, asset, Evidence("解析失败和 schema 错误会降低评估可信度", asset, observed=observed, expected="schema_error_count == 0"), "修复输入 manifest/JSONL 格式或 adapter schema 映射。", "platform"),
        _finding(request.task_id, "INT-5", "INT-DATA-005-collection-warnings", "采集 warning 评估", warning_status, warning_severity, asset, Evidence("采集 warning 应在质量报告中显式呈现", asset, observed=observed, expected="collection_warning_count == 0 or non-fatal warnings documented"), "安装缺失 CRD、补齐权限，或在限制说明中记录非致命采集 warning。", "platform"),
    ]


def integration_findings(request: AssessmentRequest, adapter_results: list[AdapterResult], quality: DataQualitySummary) -> list[Finding]:
    asset = AssetRef(kind="AssessmentPipeline", name=request.task_id)
    tool_ids = [result.tool_id for result in adapter_results]
    findings = [
        _finding(request.task_id, "INT-1", "INT-DATA-001-raw-snapshot", "数据格式分析", "PASS" if adapter_results else "FAIL", "info", asset, Evidence("记录 adapter raw_summary 作为 raw snapshot 摘要", asset, observed=[result.raw_summary for result in adapter_results], expected="raw summaries"), "为每个 adapter 保存 raw_snapshots。", "platform"),
        _finding(request.task_id, "INT-2", "INT-DATA-002-schema", "统一数据格式定义", "PASS", "info", asset, Evidence("Finding/Asset/Evidence/Report dataclass schema 与 JSON Schema 已定义", asset, observed="dataclass + /api/schema", expected="unified schema"), "保持 schema 与 API 输出兼容。", "platform"),
        _finding(request.task_id, "INT-3", "INT-DATA-003-normalize", "数据格式转换实现", "PASS", "info", asset, Evidence("三个 adapter 输出统一转换为 Finding", asset, observed=tool_ids, expected="Finding[]"), "保持 adapter 输出和报告层解耦。", "platform"),
        _finding(request.task_id, "INT-4", "INT-DATA-004-cleaning", "数据标准化清洗", "PASS" if quality.duplicate_rate == 0 else "WARN", "info", asset, Evidence("按 fingerprint 去重并保留归一化状态/严重度", asset, observed={"duplicate_rate": quality.duplicate_rate}, expected="0 duplicate"), "持续执行 fingerprint 去重和敏感字段脱敏。", "platform"),
        _finding(request.task_id, "INT-6", "INT-DATA-006-index-summary", "数据格式优化", "PASS", "info", asset, Evidence("报告输出扁平 summary，SQLite 层提供索引", asset, observed="summary + sqlite indexes", expected="indexed query"), "大量 findings 时维护 task/status/severity/checkpoint 索引。", "platform"),
        _finding(request.task_id, "INT-7", "INT-FRAME-001-registry", "工具集成框架构建", "PASS" if len(tool_ids) >= 1 else "FAIL", "info", asset, Evidence("AdapterRegistry healthcheck 和 profile 选择可用", asset, observed=tool_ids, expected="registered adapters"), "新增真实工具时注册为 ToolAdapter。", "platform"),
        _finding(request.task_id, "INT-9", "INT-CN-001-cloudnative-adapter", "云原生安全评估工具接入适配", "PASS" if "cloud_native" in tool_ids else "FAIL", "high", asset, Evidence("CloudNativeAdapter 完成采集、规则、证据输出", asset, observed=tool_ids, expected="cloud_native"), "确保 Kubernetes API 和 manifest 模式都可运行。", "platform"),
        _finding(request.task_id, "INT-11", "INT-REQ-001-assessment-request", "调用参数标准化", "PASS", "info", asset, Evidence("AssessmentRequest 统一 target/profile/options", asset, observed=asdict(request), expected="normalized request"), "保持 API/CLI 使用相同请求模型。", "platform"),
        _finding(request.task_id, "INT-12", "INT-ORCH-001-flow", "调用流程协调", "PASS", "info", asset, Evidence("Orchestrator 按 profile 调用 adapters -> normalize -> score", asset, observed=request.profile, expected="orchestrated flow"), "后续加入任务锁和异步状态流。", "platform"),
        _finding(request.task_id, "INT-13", "INT-NORM-001-output", "输出格式归一化", "PASS", "info", asset, Evidence("报告层只依赖 Finding/Metric，不依赖工具内部结构", asset, observed="Finding[]", expected="normalized output"), "新增 adapter 不改报告聚合核心。", "platform"),
        _finding(request.task_id, "INT-14", "INT-AGG-001-aggregate", "结果汇总整合", "PASS", "info", asset, Evidence("生成 overall/domain/checkpoint/severity/status 汇总", asset, observed="AssessmentReport.summary", expected="aggregate summary"), "为总览页提供 tool/domain/checkpoint 维度聚合。", "platform"),
    ]
    return findings


def visualization_findings(request: AssessmentRequest, adapter_results: list[AdapterResult], quality: DataQualitySummary) -> list[Finding]:
    asset = AssetRef(kind="Dashboard", name="static-dashboard")
    static_dir = Path(__file__).resolve().parents[2] / "web" / "static"
    files = {name: (static_dir / name).is_file() for name in ("index.html", "app.js", "styles.css")}
    tool_ids = [result.tool_id for result in adapter_results]
    cloud_native_checkpoint_count = len(CLOUD_NATIVE_CHECKPOINTS)
    common = {
        "static_files": files,
        "task_id": request.task_id,
        "profile": request.profile,
        "tool_ids": tool_ids,
        "quality": asdict(quality),
    }
    return [
        _finding(request.task_id, "VIZ-MGMT", "VIZ-IND-001-crud-api", "指标录入管理页面与 API", "PASS" if files["index.html"] else "WARN", "info", asset, Evidence("Dashboard 指标管理页和 checkpoint CRUD/weight API 已接入", asset, observed=common | {"apis": ["POST /api/checkpoints", "PATCH /api/checkpoints/{id}", "PATCH /api/checkpoints/{id}/weight"]}, expected="checkpoint management workflow"), "补充规则启用状态、适用范围和新增指标表单的更细粒度 UI。", "platform"),
        _finding(request.task_id, "VIZ-WEIGHT", "VIZ-WGT-001-recalculate", "评估指标赋权与重算", "PASS", "info", asset, Evidence("权重保存后可通过 report recalculate API 重算已有报告", asset, observed={"api": "POST /api/reports/{task_id}/recalculate"}, expected="weight affects score"), "后续支持一级/二级/三级模块批量调权。", "platform"),
        _finding(request.task_id, "VIZ-ANALYSIS", "VIZ-ANA-001-conclusion", "综合结果分析与符合度判定", "PASS", "info", asset, Evidence("报告 summary 输出 overall_score、conclusion、severity/status、evidence coverage", asset, observed="AssessmentReport.summary", expected="compliance analysis"), "后续增加趋势对比和整改优先级视图。", "platform"),
        _finding(request.task_id, "VIZ-16", "VIZ-OVR-001-overview", "多工具安全态势总览", "PASS" if len(tool_ids) >= 3 else "WARN", "info", asset, Evidence("总览页展示总分、风险分布、工具列表、数据质量", asset, observed=common, expected="multi-tool overview"), "后续补充趋势图、雷达图和 Top namespace。", "platform"),
        _finding(request.task_id, "VIZ-17", "VIZ-API-001-detail", "API 工具结果详览", "PASS" if "cloud_api_stub" in tool_ids else "WARN", "info", asset, Evidence("API stub 页面和 tool_id 筛选可定位 mock findings", asset, observed=tool_ids, expected="cloud_api_stub details"), "后续展示真实 API 参数、接口资产和证据链。", "platform"),
        _finding(request.task_id, "VIZ-18", "VIZ-CN-001-detail", "云原生工具结果详览", "PASS", "info", asset, Evidence("云原生详情页展示 15 个检查点表，Finding 详情显示 evidence/remediation", asset, observed={"cloud_native_checkpoint_count": cloud_native_checkpoint_count}, expected="15 cloud native checkpoints visible"), "后续补充三大域树、规则列表和原始 YAML 片段。", "platform"),
        _finding(request.task_id, "VIZ-19", "VIZ-SMART-001-detail", "智算云工具结果详览", "PASS" if "smart_cloud_stub" in tool_ids else "WARN", "info", asset, Evidence("智算云 stub 页面和 tool_id 筛选可定位 mock findings", asset, observed=tool_ids, expected="smart_cloud_stub details"), "后续接入真实 GPU/模型服务风险证据。", "platform"),
        _finding(request.task_id, "VIZ-20", "VIZ-FLT-001-filters", "数据筛选交互", "PASS", "info", asset, Evidence("Findings 支持 tool/checkpoint/severity/status/namespace/kind/keyword 过滤", asset, observed=["tool_id", "checkpoint_id", "severity", "status", "namespace", "kind", "keyword"], expected="global filters"), "后续让筛选进一步联动图表和报告导出。", "platform"),
        _finding(request.task_id, "VIZ-21", "VIZ-DRILL-001-detail", "结果交互查询", "PASS", "info", asset, Evidence("点击 finding 可查看 evidence、资产定位、整改建议、同资产 findings，并可复制整改建议", asset, observed={"api": "GET /api/findings/{finding_id}", "ui": ["asset card", "related findings", "copy remediation"]}, expected="drill-down detail"), "继续增强图表点击联动和原始片段定位。", "platform"),
    ]


class AssessmentOrchestrator:
    def __init__(self, registry: AdapterRegistry | None = None) -> None:
        self.registry = registry or default_registry()

    def run(self, request: AssessmentRequest) -> OrchestratorResult:
        adapter_results: list[AdapterResult] = []
        findings: list[Finding] = []
        for adapter in self.registry.for_profile(request.profile):
            try:
                result = adapter.evaluate(request)
            except Exception as exc:  # pragma: no cover - defensive integration behavior
                asset = AssetRef(kind="Adapter", name=adapter.tool_id)
                error_finding = _finding(request.task_id, "INT-7", "INT-FRAME-001-adapter-error", f"{adapter.tool_id} adapter failed", "FAIL", "high", asset, Evidence("adapter 执行失败", asset, observed=str(exc), expected="successful adapter result"), "检查 adapter 参数、权限和网络。")
                adapter_results.append(AdapterResult(adapter.tool_id, [error_finding], {"error": str(exc)}, [str(exc)]))
                findings.append(error_finding)
                continue
            adapter_results.append(result)
            findings.extend(result.findings)

        normalized = normalize_findings(findings)
        quality = data_quality_summary(adapter_results, normalized)
        normalized = normalize_findings([*normalized, *integration_findings(request, adapter_results, quality)])
        quality = data_quality_summary(adapter_results, normalized)
        normalized = normalize_findings([*normalized, *visualization_findings(request, adapter_results, quality)])
        placeholder_quality = data_quality_summary(adapter_results, normalized)
        with_int5_placeholder = normalize_findings([*normalized, *data_quality_findings(request, placeholder_quality)])
        final_quality = data_quality_summary(adapter_results, with_int5_placeholder)
        normalized = normalize_findings([finding for finding in normalized if finding.checkpoint_id != "INT-5"] + data_quality_findings(request, final_quality))
        quality = data_quality_summary(adapter_results, normalized)
        report = build_report(request.task_id, normalized)
        adapter_health = self.registry.healthcheck()
        report.summary["data_quality"] = asdict(quality)
        report.summary["tool_count"] = len(adapter_results)
        report.summary["tool_summary"] = tool_summary(adapter_results, normalized, adapter_health)
        report.summary["tools"] = report.summary["tool_summary"]
        report.summary["integration_pipeline"] = build_integration_pipeline(
            request, adapter_results, normalized, quality, adapter_health
        )
        structured = build_structured_payload(request.task_id, adapter_results, normalized, report, quality)
        report.summary["structured"] = {
            "schema_version": structured.get("schema_version"),
            "module_counts": structured.get("module_counts", {}),
        }
        return OrchestratorResult(request, adapter_results, normalized, report, quality, adapter_health, structured)

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .adapters import AdapterResult, AssessmentRequest
from .checkpoints import INTEGRATION_CHECKPOINTS, VISUALIZATION_CHECKPOINTS
from .models import Finding


DATA_PROCESSING_POINTS: tuple[dict[str, Any], ...] = (
    {"id": "INT-1", "code": "3.1.1.1", "name": "数据格式分析", "stage": "数据加工", "mode": "implemented", "evidence": "采集各适配器 raw_summary，记录结构、schema 版本、采集时间与 warning。", "metric": "raw snapshot / source schema"},
    {"id": "INT-2", "code": "3.1.1.2", "name": "数据格式定义", "stage": "数据加工", "mode": "implemented", "evidence": "Finding、Asset、Evidence、Report 统一模型，并通过 /api/schema 对外提供 JSON Schema。", "metric": "unified JSON Schema"},
    {"id": "INT-3", "code": "3.1.1.3", "name": "数据格式转换实现", "stage": "数据加工", "mode": "implemented", "evidence": "CloudNative、API Stub、SmartCloud Stub、Registry Stub 均转换为统一 Finding[]。", "metric": "adapter output → Finding[]"},
    {"id": "INT-4", "code": "3.1.1.4", "name": "数据标准化清洗", "stage": "数据加工", "mode": "implemented", "evidence": "按 fingerprint 去重，统一 status/severity，保留原始 evidence 以支持追溯。", "metric": "dedupe / normalize"},
    {"id": "INT-5", "code": "3.1.1.5", "name": "数据质量评估", "stage": "数据加工", "mode": "implemented", "evidence": "计算完整性、新鲜度、重复率、UNKNOWN 率、schema 错误和采集 warning。", "metric": "quality score"},
    {"id": "INT-6", "code": "3.1.1.6", "name": "数据格式优化", "stage": "数据加工", "mode": "implemented", "evidence": "报告提供扁平 summary，SQLite 对任务、工具、检查点、严重性和状态建立查询索引。", "metric": "indexed summary"},
    {"id": "INT-7", "code": "3.1.2.1", "name": "工具集成框架构建", "stage": "工具适配", "mode": "implemented", "evidence": "AdapterRegistry 统一管理注册、健康检查、profile 选择和单适配器错误隔离。", "metric": "registry + healthcheck"},
    {"id": "INT-8", "code": "3.1.2.2", "name": "云上 API 安全评估工具接入适配", "stage": "工具适配", "mode": "placeholder", "evidence": "API 安全工具以 CloudApiSecurityAdapterStub 接入，输出统一 Finding 和参数/能力占位证据。", "metric": "stub adapter slot"},
    {"id": "INT-9", "code": "3.1.2.3", "name": "云原生安全评估工具接入适配", "stage": "工具适配", "mode": "real", "evidence": "CloudNativeAdapter 支持 manifest、kubeconfig、PVE SSH 三种采集模式，执行不可变部署、身份认证、etcd 持久化安全规则。", "metric": "real adapter / 3 modules"},
    {"id": "INT-10", "code": "3.1.2.4", "name": "智算云安全评估工具接入适配", "stage": "工具适配", "mode": "placeholder", "evidence": "SmartCloudSecurityAdapterStub 预留 GPU、模型服务、数据集审计等统一适配接口。", "metric": "stub adapter slot"},
    {"id": "INT-11", "code": "3.1.3.1", "name": "调用参数标准化", "stage": "统一调用", "mode": "implemented", "evidence": "AssessmentRequest 统一承载 target、profile、连接方式、评估范围和 options。", "metric": "AssessmentRequest"},
    {"id": "INT-12", "code": "3.1.3.2", "name": "调用流程协调", "stage": "统一调用", "mode": "implemented", "evidence": "Orchestrator 按 profile 调度适配器，记录任务事件，并执行归一化、质量评估和评分聚合。", "metric": "orchestrated flow"},
    {"id": "INT-13", "code": "3.1.4.1", "name": "输出格式归一化", "stage": "统一输出", "mode": "implemented", "evidence": "跨工具输出在报告层统一为 Finding、CheckpointScore、AssessmentReport，不耦合工具私有结构。", "metric": "normalized output"},
    {"id": "INT-14", "code": "3.1.4.2", "name": "结果汇总整合", "stage": "统一输出", "mode": "implemented", "evidence": "按工具、域、检查点、严重性和状态聚合，并生成综合评分、证据覆盖率和整改优先级。", "metric": "multi-tool aggregate"},
)

VISUALIZATION_POINTS: tuple[dict[str, Any], ...] = (
    {"id": "VIZ-MGMT", "code": "3.2.1.1", "name": "指标录入管理", "stage": "指标管理", "mode": "implemented", "evidence": "指标页面支持新增、启停、适用范围、规则启用和持久化管理。", "metric": "checkpoint CRUD"},
    {"id": "VIZ-WEIGHT", "code": "3.2.1.2", "name": "评估指标赋权", "stage": "指标管理", "mode": "implemented", "evidence": "支持编辑检查点权重，保存后调用重算接口更新综合报告。", "metric": "weight → recalculate"},
    {"id": "VIZ-ANALYSIS", "code": "3.2.2", "name": "综合结果分析判定", "stage": "结果分析", "mode": "implemented", "evidence": "报告聚合符合度、综合得分、风险分布、证据覆盖率、薄弱项和整改建议。", "metric": "compliance analysis"},
    {"id": "VIZ-16", "code": "3.2.3", "name": "综合态势展示", "stage": "结果分析", "mode": "implemented", "evidence": "总览页呈现总分、结论、Finding、严重度、工具态势、云原生域和数据质量。", "metric": "security posture"},
    {"id": "VIZ-17", "code": "3.2.4.1", "name": "API 工具结果详览", "stage": "工具详情", "mode": "placeholder", "evidence": "API Stub 页展示参数、能力标签和 mock 评估结果，保留真实工具替换插槽。", "metric": "API detail stub"},
    {"id": "VIZ-18", "code": "3.2.4.2", "name": "云原生工具结果详览", "stage": "工具详情", "mode": "real", "evidence": "云原生详情页展示 15 个检查点、RBAC 权限矩阵，并可下钻 Finding 的资产、证据和整改建议。", "metric": "15 checkpoints / drill-down"},
    {"id": "VIZ-19", "code": "3.2.4.3", "name": "智算云工具结果详览", "stage": "工具详情", "mode": "placeholder", "evidence": "智算云 Stub 页展示 GPU 工作区、模型服务和数据集审计等占位数据。", "metric": "SmartCloud detail stub"},
    {"id": "VIZ-20", "code": "3.2.5.1", "name": "数据筛选交互", "stage": "交互查询", "mode": "implemented", "evidence": "Findings 支持工具、检查点、域、严重性、状态、namespace、kind、名称和关键词组合筛选。", "metric": "9 filter dimensions"},
    {"id": "VIZ-21", "code": "3.2.5.2", "name": "结果交互查询", "stage": "交互查询", "mode": "implemented", "evidence": "点击 Finding 行打开详情，展示资产定位、原始 evidence、同资产关联项和整改建议。", "metric": "finding drill-down"},
)


def _point_status(findings: list[Finding], checkpoint_id: str) -> str:
    rows = [finding for finding in findings if finding.checkpoint_id == checkpoint_id]
    if any(row.status == "FAIL" for row in rows):
        return "FAIL"
    if any(row.status == "WARN" for row in rows):
        return "WARN"
    if rows:
        return "PASS"
    return "UNKNOWN"


def _checkpoint_map() -> dict[str, Any]:
    return {checkpoint.id: checkpoint for checkpoint in (*INTEGRATION_CHECKPOINTS, *VISUALIZATION_CHECKPOINTS)}


def build_integration_pipeline(
    request: AssessmentRequest,
    adapter_results: list[AdapterResult],
    findings: list[Finding],
    quality: Any,
    adapter_health: dict[str, Any],
) -> dict[str, Any]:
    checkpoints = _checkpoint_map()
    points: list[dict[str, Any]] = []
    for group, definitions in (("data_processing", DATA_PROCESSING_POINTS), ("visualization", VISUALIZATION_POINTS)):
        for definition in definitions:
            checkpoint = checkpoints[definition["id"]]
            row = dict(definition)
            row.update(
                {
                    "group": group,
                    "tender_no": checkpoint.tender_no,
                    "rule_group": checkpoint.rule_group,
                    "domain": checkpoint.domain,
                    "weight": checkpoint.weight,
                    "status": _point_status(findings, checkpoint.id),
                    "finding_count": sum(1 for finding in findings if finding.checkpoint_id == checkpoint.id),
                }
            )
            points.append(row)

    adapters = []
    for result in adapter_results:
        health = adapter_health.get(result.tool_id, {})
        adapters.append(
            {
                "tool_id": result.tool_id,
                "status": health.get("status", "ready"),
                "mode": "placeholder" if result.raw_summary.get("stub_mode") else "real",
                "schema_version": result.raw_summary.get("schema_version", "unknown"),
                "raw_kind": result.raw_summary.get("kind", "adapter_summary"),
                "finding_count": sum(1 for finding in findings if finding.tool_id == result.tool_id),
                "warning_count": len(result.warnings),
                "collected_at": result.raw_summary.get("collected_at"),
            }
        )

    return {
        "schema_version": "integration/v1",
        "task_id": request.task_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": request.profile,
        "stats": {
            "raw_snapshot_count": len(adapter_results),
            "normalized_finding_count": len(findings),
            "adapter_count": len(adapter_results),
            "quality_score": round((quality.completeness + quality.freshness + (100 - quality.unknown_rate)) / 3, 2),
            "completeness": quality.completeness,
            "freshness": quality.freshness,
            "duplicate_rate": quality.duplicate_rate,
            "unknown_rate": quality.unknown_rate,
        },
        "flow": [
            {"key": "collect", "label": "工具采集", "detail": f"{len(adapter_results)} adapters"},
            {"key": "normalize", "label": "统一归一", "detail": f"{len(findings)} findings"},
            {"key": "quality", "label": "质量评估", "detail": f"{quality.completeness}% completeness"},
            {"key": "aggregate", "label": "结果汇总", "detail": "report + dashboard"},
        ],
        "adapters": adapters,
        "points": points,
    }

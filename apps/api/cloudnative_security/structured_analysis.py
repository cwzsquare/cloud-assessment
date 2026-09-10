"""Build structured, queryable evidence products for one assessment run.

This module keeps the existing adapter/rule chain intact while exposing its
intermediate records for persistence, APIs, reports, and the dashboard.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

@dataclass
class PipelineContext:
    """Mutable artifacts shared by the real 14-step processing pipeline.

    The execution engine passes each step's output to the next step, while this
    context keeps the differently shaped artifacts available to independent
    later steps when an earlier callable fails.
    """

    task_id: str
    objects: list[dict[str, Any]]
    findings: list[Any]
    report: Any
    quality_summary: Any
    rbac_rows: list[dict[str, Any]] = field(default_factory=list)
    snapshots: list[dict[str, Any]] = field(default_factory=list)
    sources: list[Any] = field(default_factory=list)
    parsed_records: list[dict[str, Any]] | None = None
    mapped_records: list[dict[str, Any]] | None = None
    mapping_result: Any = None
    cleaned_records: list[dict[str, Any]] | None = None
    cleaning_result: Any = None
    normalized_assets: list[dict[str, Any]] | None = None
    resource_dedup: Any = None
    evidence_rows: list[dict[str, Any]] | None = None
    evidence_dedup: Any = None
    asset_graph: Any = None
    quality_results: list[Any] | None = None
    aggregated_findings: list[Any] | None = None
    checkpoint_scores: list[Any] | None = None
    lineage: Any = None
    persistence_outputs: list[str] | None = None

from .asset_graph import build_asset_graph
from .authn_analyzers import (
    analyze_authentication_profile,
    analyze_identity_profiles,
    analyze_service_account_tokens,
)
from .authn_profile import AuthenticationProfile
from .data_cleaning import CleaningConfig, clean_records
from .data_contracts import CollectionRun, SourceDescriptor
from .data_pipeline import DataPipeline
from .data_quality import DataQualityRule, evaluate_data_quality
from .data_lineage import build_lineage_graph
from .dedup import deduplicate_evidence, deduplicate_resources
from .encryption_config import parse_encryption_config
from .etcd_profile import assess_cluster_consistency, parse_apiserver_etcd_client, parse_etcd_flags
from .field_mapping import FieldMappingRule, apply_field_mappings
from .mtls_coverage import analyze_mtls_coverage
from .certificate_inspector import inspect_certificate

CURRENT_STRUCTURED_SCHEMA_VERSION = "structured-assessment/v1"


def normalize_structured_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize current and legacy structured payloads to one read contract."""
    if not isinstance(payload, Mapping):
        return {}
    normalized = dict(payload)
    source_version = str(normalized.get("schema_version") or normalized.get("version") or "structured-assessment/legacy")
    aliases = {
        "processing": "processing_run",
        "steps": "processing_steps",
        "quality": "data_quality_results",
        "mappings": "field_mapping_rules",
        "cleaning": "cleaning_actions",
        "conflicts": "data_conflicts",
        "authn": "authentication",
        "service_accounts": "service_account_tokens",
        "asset_relationships": "asset_graph",
    }
    for legacy_key, current_key in aliases.items():
        if current_key not in normalized and legacy_key in normalized:
            normalized[current_key] = normalized[legacy_key]
    defaults: dict[str, Any] = {
        "sources": [],
        "collection_runs": [],
        "processing_steps": [],
        "data_quality_results": [],
        "field_mapping_rules": [],
        "cleaning_actions": [],
        "data_conflicts": [],
        "lineage": {"nodes": [], "edges": []},
        "asset_graph": {"nodes": [], "edges": []},
        "service_account_tokens": [],
        "identities": [],
        "etcd": [],
        "apiserver_etcd": [],
        "encryption": [],
        "certificates": [],
        "mtls": [],
    }
    for key, default in defaults.items():
        if normalized.get(key) is None:
            normalized[key] = default.copy() if isinstance(default, dict) else list(default)
    normalized["schema_version"] = CURRENT_STRUCTURED_SCHEMA_VERSION
    normalized["compatibility"] = {
        "source_schema_version": source_version,
        "normalized_schema_version": CURRENT_STRUCTURED_SCHEMA_VERSION,
        "legacy_aliases_applied": [key for key, value in aliases.items() if value in normalized and key in payload and value not in payload],
    }
    return normalized
def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value



def _objects(adapter_results: list[Any]) -> list[dict[str, Any]]:
    cloud_native = next((item for item in adapter_results if item.tool_id == "cloud_native"), None)
    if not cloud_native:
        return []
    return [item for item in cloud_native.raw_summary.get("objects", []) if isinstance(item, dict)]


def _commands(objects: list[dict[str, Any]], component: str) -> list[dict[str, Any]]:
    return [item for item in objects if item.get("kind") == "ControlPlaneManifest" and str(item.get("component", "")) == component]


def _rbac_rows(adapter_results: list[Any]) -> list[dict[str, Any]]:
    cloud_native = next((item for item in adapter_results if item.tool_id == "cloud_native"), None)
    matrix = cloud_native.raw_summary.get("rbac_matrix", {}) if cloud_native else {}
    return [row for row in matrix.get("rows", []) if isinstance(row, dict)]


def _assets(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in objects:
        metadata = obj.get("metadata", {}) or {}
        if metadata.get("name") and obj.get("kind"):
            rows.append({
                "kind": obj.get("kind"),
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "api_version": obj.get("apiVersion"),
                "source": obj.get("source", "kubernetes-api"),
            })
    return rows
def _mapping_rules() -> list[FieldMappingRule]:
    return [
        FieldMappingRule("MAP-KIND", "kubernetes", "normalized", "kind", "normalized.kind", required=True),
        FieldMappingRule("MAP-NAME", "kubernetes", "normalized", "metadata.name", "normalized.name", required=True),
        FieldMappingRule("MAP-NAMESPACE", "kubernetes", "normalized", "metadata.namespace", "normalized.namespace"),
    ]


def _objects_from(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        return [data]
    if isinstance(data, (list, tuple, set)):
        return [item for item in data if isinstance(item, dict)]
    return []


def _normalization_from_context(context: PipelineContext, processing_run: Any) -> dict[str, Any]:
    """Export the artifacts produced by the pipeline, including failed fallbacks."""
    mapped_records = context.mapped_records if context.mapped_records is not None else (
        context.parsed_records if context.parsed_records is not None else context.objects
    )
    cleaned_records = context.cleaned_records if context.cleaned_records is not None else mapped_records
    normalized_assets = context.normalized_assets
    if normalized_assets is None:
        normalized_assets = _assets(cleaned_records)
    mapping_result = context.mapping_result
    if mapping_result is not None:
        mapping_summary = mapping_result.to_dict()
    else:
        step = next((item for item in processing_run.steps if item.step_name == "field_mapping"), None)
        mapping_summary = {
            "records": mapped_records,
            "required_failures": None,
            "required_failure_paths": {},
            "errors": list(getattr(step, "errors", []) or []),
            "mapped_count": len(mapped_records),
        }
    cleaning_result = context.cleaning_result
    if cleaning_result is not None:
        cleaning_summary = cleaning_result.to_dict()
        cleaning_actions = [item.to_dict() for item in cleaning_result.actions]
    else:
        step = next((item for item in processing_run.steps if item.step_name == "data_cleaning"), None)
        cleaning_actions = []
        cleaning_summary = {
            "records": cleaned_records,
            "actions": [],
            "invalid_count": None,
            "sensitive_skipped": None,
            "errors": list(getattr(step, "errors", []) or []),
        }
    resource_dedup = context.resource_dedup
    evidence_dedup = context.evidence_dedup
    resource_duplicates = int(getattr(resource_dedup, "duplicate_count", 0) or 0)
    evidence_duplicates = int(getattr(evidence_dedup, "duplicate_count", 0) or 0)
    evidence_records = (
        evidence_dedup.records if evidence_dedup is not None
        else (context.evidence_rows if context.evidence_rows is not None else [])
    )
    conflicts = []
    if resource_dedup is not None:
        conflicts.extend(item.to_dict() for item in resource_dedup.conflicts)
    if evidence_dedup is not None:
        conflicts.extend(item.to_dict() for item in evidence_dedup.conflicts)
    rules = _mapping_rules()
    return {
        "field_mapping_rules": [rule.to_dict() for rule in rules],
        "mapped_records": mapped_records,
        "mapping_summary": mapping_summary,
        "cleaning_actions": cleaning_actions,
        "cleaning_summary": cleaning_summary,
        "normalized_assets": normalized_assets,
        "data_conflicts": conflicts,
        "deduplication": {
            "resource_duplicate_count": resource_duplicates,
            "evidence_duplicate_count": evidence_duplicates,
            "finding_count": len(evidence_records),
        },
    }

def _quality(objects: list[dict[str, Any]], graph: Any) -> list[Any]:
    rules = [
        DataQualityRule("DQ-COMPLETE", "completeness", required_fields=("kind", "metadata.name"), threshold=100),
        DataQualityRule("DQ-UNIQUE", "uniqueness", key_fields=("kind", "metadata.namespace", "metadata.name"), threshold=100),
        DataQualityRule("DQ-NAME", "field_validity", fields=("kind", "metadata.name"), patterns={"metadata.name": r"[A-Za-z0-9][A-Za-z0-9._-]*"}, threshold=100),
        DataQualityRule("DQ-TYPES", "type_consistency", expected_types={"kind": "str", "metadata": "dict"}, threshold=100),
        DataQualityRule("DQ-REFERENCE", "reference_integrity", reference_fields={"metadata.ownerReferences[].name": "metadata.name"}, threshold=100),
        DataQualityRule("DQ-TIME", "temporal_continuity", time_field="metadata.creationTimestamp", threshold=100),
        DataQualityRule("DQ-LINEAGE", "lineage_integrity", lineage_fields=("kind", "metadata.name"), threshold=100),
    ]
    return evaluate_data_quality(objects, rules, references={"lineage": graph.to_dict() if hasattr(graph, "to_dict") else graph})


def _pipeline(context: PipelineContext) -> Any:
    catalog = [
        "input_loading", "structure_parsing", "resource_normalization", "field_mapping",
        "data_cleaning", "fingerprint", "deduplication", "relationship_building",
        "data_quality", "security_rules", "finding_aggregation", "checkpoint_scoring",
        "report_building", "persistence",
    ]

    def input_loading(data: Any, ctx: PipelineContext) -> list[dict[str, Any]]:
        records = _objects_from(data)
        ctx.objects = records
        return records

    def structure_parsing(data: Any, ctx: PipelineContext) -> dict[str, Any]:
        source = _objects_from(data)
        parsed = [dict(record) for record in source]
        ctx.parsed_records = parsed
        return {"output": parsed, "summary": {"parsed_records": len(parsed), "parse_errors": len(source) - len(parsed)}}

    def resource_normalization(data: Any, ctx: PipelineContext) -> list[dict[str, Any]]:
        records = _objects_from(data)
        # Preserve the source shape for field mapping; asset projections are
        # materialized here and replaced with deduplicated projections later.
        normalized = [dict(record) for record in records]
        ctx.normalized_assets = _assets(normalized)
        return {
            "output": normalized,
            "summary": {"normalized_records": len(normalized), "normalized_assets": len(ctx.normalized_assets)},
        }

    def field_mapping(data: Any, ctx: PipelineContext) -> dict[str, Any]:
        result = apply_field_mappings(_objects_from(data), _mapping_rules())
        ctx.mapping_result = result
        ctx.mapped_records = result.records
        return {
            "output": result.records,
            "summary": {
                "mapped_fields": [rule.mapping_id for rule in _mapping_rules()],
                "required_failures": result.required_failures,
                "mapping_errors": len(result.errors),
            },
            "status": "PARTIAL" if result.required_failures or result.errors else "SUCCESS",
        }

    def data_cleaning(data: Any, ctx: PipelineContext) -> dict[str, Any]:
        result = clean_records(
            _objects_from(data),
            CleaningConfig(name_fields=("name",), list_fields=("finalizers",), label_fields=("labels",)),
        )
        ctx.cleaning_result = result
        ctx.cleaned_records = result.records
        return {
            "output": result.records,
            "summary": {
                "cleaning_actions": len(result.actions),
                "invalid_count": result.invalid_count,
                "sensitive_skipped": result.sensitive_skipped,
            },
            "status": "PARTIAL" if result.invalid_count else "SUCCESS",
        }

    def fingerprint(data: Any, ctx: PipelineContext) -> list[dict[str, Any]]:
        rows = [
            {
                "evidence_key": getattr(item, "fingerprint", None) or getattr(item, "id", None) or str(index),
                "source": getattr(item, "tool_id", "assessment"),
                "status": getattr(item, "status", "UNKNOWN"),
                "severity": getattr(item, "severity", "UNKNOWN"),
                "source_reference": getattr(item, "checkpoint_id", None),
            }
            for index, item in enumerate(ctx.findings)
        ]
        ctx.evidence_rows = rows
        return rows

    def deduplication(data: Any, ctx: PipelineContext) -> list[dict[str, Any]]:
        source_records = ctx.cleaned_records if ctx.cleaned_records is not None else _objects_from(data)
        resource_result = deduplicate_resources(source_records)
        evidence_result = deduplicate_evidence(ctx.evidence_rows or [])
        ctx.resource_dedup = resource_result
        ctx.evidence_dedup = evidence_result
        ctx.normalized_assets = _assets(resource_result.records)
        return {
            "output": evidence_result.records,
            "summary": {
                "resource_duplicates": resource_result.duplicate_count,
                "evidence_duplicates": evidence_result.duplicate_count,
                "deduplicated_findings": len(evidence_result.records),
            },
        }

    def relationship_building(data: Any, ctx: PipelineContext) -> list[Any]:
        source_records = (
            ctx.resource_dedup.records
            if ctx.resource_dedup is not None
            else (ctx.cleaned_records if ctx.cleaned_records is not None else ctx.objects)
        )
        ctx.asset_graph = build_asset_graph(source_records, ctx.rbac_rows)
        return {
            "output": ctx.asset_graph.nodes,
            "summary": {"nodes": len(ctx.asset_graph.nodes), "edges": len(ctx.asset_graph.edges)},
        }

    def data_quality(data: Any, ctx: PipelineContext) -> list[Any]:
        source_records = (
            ctx.resource_dedup.records
            if ctx.resource_dedup is not None
            else (ctx.cleaned_records if ctx.cleaned_records is not None else ctx.objects)
        )
        ctx.quality_results = _quality(source_records, ctx.asset_graph)
        return {
            "output": ctx.quality_results,
            "summary": {"rule_count": len(ctx.quality_results), "unknown_count": sum(item.status == "UNKNOWN" for item in ctx.quality_results)},
        }

    def security_rules(data: Any, ctx: PipelineContext) -> list[Any]:
        # Rule evaluation is owned by the orchestrator; this step records the
        # real finding stream rather than inventing a second evaluation.
        return {"output": list(ctx.findings), "summary": {"finding_count": len(ctx.findings), "external": True}}

    def finding_aggregation(data: Any, ctx: PipelineContext) -> list[Any]:
        allowed = None
        if ctx.evidence_dedup is not None:
            allowed = {row.get("evidence_key") for row in ctx.evidence_dedup.records}
        aggregated: list[Any] = []
        seen: set[Any] = set()
        for index, finding in enumerate(ctx.findings):
            key = getattr(finding, "fingerprint", None) or getattr(finding, "id", None) or str(index)
            if allowed is not None and key not in allowed:
                continue
            if key in seen:
                continue
            seen.add(key)
            aggregated.append(finding)
        ctx.aggregated_findings = aggregated
        return {"output": aggregated, "summary": {"finding_count": len(aggregated), "deduplicated": len(ctx.findings) - len(aggregated)}}

    def checkpoint_scoring(data: Any, ctx: PipelineContext) -> list[Any]:
        ctx.checkpoint_scores = list(getattr(ctx.report, "checkpoint_scores", []) or [])
        return {"output": ctx.checkpoint_scores, "summary": {"external": True, "score_count": len(ctx.checkpoint_scores)}}

    def report_building(data: Any, ctx: PipelineContext) -> list[Any]:
        return {"output": [ctx.report], "summary": {"schema_version": getattr(ctx.report, "schema_version", "unknown"), "external": True}}

    def persistence(data: Any, ctx: PipelineContext) -> list[str]:
        ctx.persistence_outputs = ["raw_snapshots", "findings", "reports", "structured_payload"]
        return {"output": ctx.persistence_outputs, "summary": {"stored_outputs": ctx.persistence_outputs, "external": True}}

    steps = {
        "input_loading": input_loading,
        "structure_parsing": structure_parsing,
        "resource_normalization": resource_normalization,
        "field_mapping": field_mapping,
        "data_cleaning": data_cleaning,
        "fingerprint": fingerprint,
        "deduplication": deduplication,
        "relationship_building": relationship_building,
        "data_quality": data_quality,
        "security_rules": security_rules,
        "finding_aggregation": finding_aggregation,
        "checkpoint_scoring": checkpoint_scoring,
        "report_building": report_building,
        "persistence": persistence,
    }
    pipeline = DataPipeline(steps, catalog=catalog)
    return pipeline.run(context.objects, context=context)


def build_structured_payload(task_id: str, adapter_results: list[Any], findings: list[Any], report: Any, quality_summary: Any) -> dict[str, Any]:
    """Return all structured products generated from real adapter evidence."""
    objects = _objects(adapter_results)
    rbac_rows = _rbac_rows(adapter_results)
    sources: list[SourceDescriptor] = []
    collections: list[CollectionRun] = []
    snapshots: list[dict[str, Any]] = []
    for result in adapter_results:
        descriptor = SourceDescriptor(source_id=result.tool_id, source_type=result.raw_summary.get("kind", "adapter"), name=result.tool_id, version=result.raw_summary.get("schema_version"), metadata={"mode": result.raw_summary.get("mode"), "stub_mode": bool(result.raw_summary.get("stub_mode")), "capabilities": list(result.raw_summary.get("capabilities") or [])})
        sources.append(descriptor)
        run = CollectionRun(source=descriptor, status="PARTIAL" if result.warnings else "SUCCESS", input_count=int(result.raw_summary.get("object_count", 0) or 0), output_count=int(result.raw_summary.get("object_count", 0) or 0), warnings=list(result.warnings), summary={"kind_count": result.raw_summary.get("kind_count", 0)})
        run.completed_at = datetime.now(timezone.utc).isoformat()
        collections.append(run)
        snapshots.append({"id": f"{task_id}:{result.tool_id}", "task_id": task_id, "source": result.tool_id, "kind": result.raw_summary.get("kind", "adapter_summary"), "schema_version": result.raw_summary.get("schema_version", "unknown"), "content_hash": "", "warning_count": len(result.warnings)})

    context = PipelineContext(
        task_id=task_id,
        objects=objects,
        findings=list(findings),
        report=report,
        quality_summary=quality_summary,
        rbac_rows=rbac_rows,
        snapshots=snapshots,
        sources=sources,
    )
    processing_run = _pipeline(context)
    normalization = _normalization_from_context(context, processing_run)
    assets = normalization["normalized_assets"]
    asset_graph = context.asset_graph
    quality_results = context.quality_results if context.quality_results is not None else []
    final_findings = context.aggregated_findings if context.aggregated_findings is not None else list(findings)
    lineage = build_lineage_graph(snapshots, assets, final_findings, getattr(report, "checkpoint_scores", []), [report], sources)
    context.lineage = lineage

    apiserver = _commands(objects, "kube-apiserver")
    etcd_manifests = _commands(objects, "etcd")
    apiserver_flags = [item.get("command", []) for item in apiserver]
    etcd_profiles = [parse_etcd_flags(item.get("command", []), source=item.get("path")) for item in etcd_manifests]
    apiserver_etcd_profiles = [parse_apiserver_etcd_client(item.get("command", []), source=item.get("path")) for item in apiserver]
    consistency = assess_cluster_consistency(etcd_profiles)
    encryption_configs = [parse_encryption_config(item.get("config", {}), source_name=item.get("path")) for item in objects if item.get("kind") == "EncryptionProviderConfig"]
    certificate_profiles = []
    for index, obj in enumerate(objects):
        for certificate in obj.get("certificates", []) if isinstance(obj.get("certificates"), list) else []:
            if isinstance(certificate, dict) and isinstance(certificate.get("profile"), dict):
                certificate_profiles.append(certificate["profile"])
        for key, value in obj.items():
            if isinstance(value, str) and "-----BEGIN CERTIFICATE-----" in value:
                certificate_profiles.append(inspect_certificate(value, source_name=f"{obj.get('kind', 'object')}:{index}:{key}"))
    policies = [item for item in objects if item.get("kind") == "PeerAuthentication"]
    workloads = [item for item in objects if item.get("kind") in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}]
    mtls = analyze_mtls_coverage(policies, workloads)
    authn = analyze_authentication_profile(apiserver_flags[0] if apiserver_flags else None, None, rbac_rows)
    service_accounts = [item for item in objects if item.get("kind") == "ServiceAccount"]
    token_profiles = analyze_service_account_tokens(workloads, service_accounts, rbac_rows, None)
    identities = analyze_identity_profiles(rbac_rows)
    return normalize_structured_payload({
        "schema_version": "structured-assessment/v1",
        "task_id": task_id,
        "sources": [_jsonable(x) for x in sources],
        "collection_runs": [_jsonable(x) for x in collections],
        "snapshots": snapshots,
        "processing_run": _jsonable(processing_run),
        "processing_steps": [_jsonable(x) for x in processing_run.steps],
        "data_quality_results": [_jsonable(x) for x in quality_results],
        "quality_summary": _jsonable(quality_summary),
        "field_mapping_rules": normalization["field_mapping_rules"],
        "cleaning_actions": normalization["cleaning_actions"],
        "data_conflicts": normalization["data_conflicts"],
        "normalization": normalization,
        "asset_graph": _jsonable(asset_graph),
        "lineage": _jsonable(lineage),
        "authentication": _jsonable(authn),
        "service_account_tokens": _jsonable(token_profiles),
        "identities": _jsonable(identities),
        "etcd": _jsonable(etcd_profiles),
        "apiserver_etcd": _jsonable(apiserver_etcd_profiles),
        "config_consistency": _jsonable(consistency),
        "encryption": _jsonable(encryption_configs),
        "certificates": _jsonable(certificate_profiles),
        "mtls": _jsonable(mtls),
        "module_counts": {
            "objects": len(objects),
            "findings": len(final_findings),
            "assets": len(assets),
            "lineage_nodes": len(lineage.nodes),
            "asset_nodes": len(getattr(asset_graph, "nodes", []) or []),
            "quality_results": len(quality_results),
            "etcd_nodes": len(etcd_profiles),
            "certificates": len(certificate_profiles),
        },
    })


__all__ = ["CURRENT_STRUCTURED_SCHEMA_VERSION", "PipelineContext", "build_structured_payload", "normalize_structured_payload"]



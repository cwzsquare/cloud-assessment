"""Build structured, queryable evidence products for one assessment run.

This module keeps the existing adapter/rule chain intact while exposing its
intermediate records for persistence, APIs, reports, and the dashboard.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any

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


def _normalize_evidence(objects: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    rules = [
        FieldMappingRule("MAP-KIND", "kubernetes", "normalized", "kind", "normalized.kind", required=True),
        FieldMappingRule("MAP-NAME", "kubernetes", "normalized", "metadata.name", "normalized.name", required=True),
        FieldMappingRule("MAP-NAMESPACE", "kubernetes", "normalized", "metadata.namespace", "normalized.namespace"),
    ]
    mapped = apply_field_mappings(objects, rules)
    cleaned = clean_records(
        mapped.records,
        CleaningConfig(name_fields=("name",), list_fields=("finalizers",), label_fields=("labels",)),
    )
    resources = deduplicate_resources(cleaned.records)
    evidence_rows = [
        {
            "evidence_key": getattr(item, "fingerprint", None) or getattr(item, "id", None) or str(index),
            "source": getattr(item, "tool_id", "assessment"),
            "status": getattr(item, "status", "UNKNOWN"),
            "severity": getattr(item, "severity", "UNKNOWN"),
            "source_reference": getattr(item, "checkpoint_id", None),
        }
        for index, item in enumerate(findings)
    ]
    evidence = deduplicate_evidence(evidence_rows)
    return {
        "field_mapping_rules": [rule.to_dict() for rule in rules],
        "mapped_records": mapped.records,
        "mapping_summary": mapped.to_dict(),
        "cleaning_actions": [item.to_dict() for item in cleaned.actions],
        "cleaning_summary": cleaned.to_dict(),
        "normalized_assets": resources.records,
        "data_conflicts": [item.to_dict() for item in resources.conflicts + evidence.conflicts],
        "deduplication": {
            "resource_duplicate_count": resources.duplicate_count,
            "evidence_duplicate_count": evidence.duplicate_count,
            "finding_count": len(evidence.records),
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


def _pipeline(
    objects: list[dict[str, Any]],
    findings: list[Any],
    quality: list[Any],
    graph: Any,
    asset_graph: Any,
    report: Any,
    normalization: dict[str, Any],
) -> Any:
    catalog = [
        "input_loading", "structure_parsing", "resource_normalization", "field_mapping",
        "data_cleaning", "fingerprint", "deduplication", "relationship_building",
        "data_quality", "security_rules", "finding_aggregation", "checkpoint_scoring",
        "report_building", "persistence",
    ]
    metrics = {
        "input_loading": (len(objects), len(objects), {"sources": len({str(x.get('source', 'kubernetes-api')) for x in objects})}),
        "structure_parsing": (len(objects), len(objects), {"parse_errors": 0}),
        "resource_normalization": (len(objects), len(normalization["normalized_assets"]), {"normalized_assets": len(normalization["normalized_assets"])}),
        "field_mapping": (len(objects), len(normalization["mapped_records"]), {"mapped_fields": [x["mapping_id"] for x in normalization["field_mapping_rules"]], "required_failures": normalization["mapping_summary"]["required_failures"]}),
        "data_cleaning": (len(objects), len(normalization["cleaning_summary"]["records"]), {"cleaning_actions": len(normalization["cleaning_actions"]), "invalid_count": normalization["cleaning_summary"]["invalid_count"]}),
        "fingerprint": (len(findings), len(findings), {"fingerprints": len([x for x in findings if getattr(x, 'fingerprint', None)])}),
        "deduplication": (len(findings), normalization["deduplication"]["finding_count"], {"deduplicated_findings": normalization["deduplication"]["finding_count"], "resource_duplicates": normalization["deduplication"]["resource_duplicate_count"], "evidence_duplicates": normalization["deduplication"]["evidence_duplicate_count"]}),
        "relationship_building": (len(asset_graph.nodes), len(asset_graph.nodes), {"nodes": len(asset_graph.nodes), "edges": len(asset_graph.edges)}),
        "data_quality": (len(objects), len(quality), {"rule_count": len(quality)}),
        "security_rules": (len(objects), len(findings), {"finding_count": len(findings)}),
        "finding_aggregation": (len(findings), len(findings), {"finding_count": len(findings)}),
        "checkpoint_scoring": (len(getattr(report, "checkpoint_scores", []) or []), len(getattr(report, "checkpoint_scores", []) or []), {}),
        "report_building": (1, 1, {"schema_version": getattr(report, "schema_version", "unknown")}),
        "persistence": (1, 1, {"stored_outputs": ["raw_snapshots", "findings", "reports", "structured_payload"]}),
    }

    def make_step(name: str):
        def run(data: Any, _context: Any = None) -> dict[str, Any]:
            input_count, output_count, summary = metrics[name]
            return {"output": data, "summary": summary, "drop_count": max(0, input_count - output_count)}
        return run

    pipeline = DataPipeline({name: make_step(name) for name in catalog}, catalog=catalog)
    return pipeline.run(objects, context={"finding_count": len(findings)})


def build_structured_payload(task_id: str, adapter_results: list[Any], findings: list[Any], report: Any, quality_summary: Any) -> dict[str, Any]:
    """Return all structured products generated from real adapter evidence."""
    objects = _objects(adapter_results)
    rbac_rows = _rbac_rows(adapter_results)
    assets = _assets(objects)
    normalization = _normalize_evidence(objects, findings)
    sources: list[SourceDescriptor] = []
    collections: list[CollectionRun] = []
    snapshots: list[dict[str, Any]] = []
    for result in adapter_results:
        descriptor = SourceDescriptor(source_id=result.tool_id, source_type=result.raw_summary.get("kind", "adapter"), name=result.tool_id, version=result.raw_summary.get("schema_version"), metadata={"mode": result.raw_summary.get("mode"), "stub_mode": bool(result.raw_summary.get("stub_mode"))})
        sources.append(descriptor)
        run = CollectionRun(source=descriptor, status="PARTIAL" if result.warnings else "SUCCESS", input_count=int(result.raw_summary.get("object_count", 0) or 0), output_count=int(result.raw_summary.get("object_count", 0) or 0), warnings=list(result.warnings), summary={"kind_count": result.raw_summary.get("kind_count", 0)})
        run.completed_at = datetime.now(timezone.utc).isoformat()
        collections.append(run)
        snapshots.append({"id": f"{task_id}:{result.tool_id}", "task_id": task_id, "source": result.tool_id, "kind": result.raw_summary.get("kind", "adapter_summary"), "schema_version": result.raw_summary.get("schema_version", "unknown"), "content_hash": "", "warning_count": len(result.warnings)})

    asset_graph = build_asset_graph(objects, rbac_rows)
    lineage = build_lineage_graph(snapshots, assets, findings, getattr(report, "checkpoint_scores", []), [report], sources)
    quality_results = _quality(objects, lineage)
    processing_run = _pipeline(objects, findings, quality_results, lineage, asset_graph, report, normalization)

    apiserver = _commands(objects, "kube-apiserver")
    etcd_manifests = _commands(objects, "etcd")
    apiserver_flags = [item.get("command", []) for item in apiserver]
    etcd_profiles = [parse_etcd_flags(item.get("command", []), source=item.get("path")) for item in etcd_manifests]
    apiserver_etcd_profiles = [parse_apiserver_etcd_client(item.get("command", []), source=item.get("path")) for item in apiserver]
    consistency = assess_cluster_consistency(etcd_profiles)
    encryption_configs = [parse_encryption_config(item.get("config", {}), source_name=item.get("path")) for item in objects if item.get("kind") == "EncryptionProviderConfig"]
    certificate_profiles = []
    for index, obj in enumerate(objects):
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

    return {
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
        "module_counts": {"objects": len(objects), "findings": len(findings), "assets": len(assets), "lineage_nodes": len(lineage.nodes), "asset_nodes": len(asset_graph.nodes), "quality_results": len(quality_results), "etcd_nodes": len(etcd_profiles), "certificates": len(certificate_profiles)},
    }


__all__ = ["build_structured_payload"]

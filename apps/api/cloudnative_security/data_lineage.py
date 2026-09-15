"""Deterministic provenance graph for assessment data.

The graph deliberately stores references and small metadata only.  It does not
retain raw adapter payloads (which may contain credentials or other secrets).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
import json
from collections.abc import Mapping, Iterable
from typing import Any


_SENSITIVE = ("password", "passwd", "secret", "token", "private_key", "privatekey", "bearer", "encryption_key", "key_material")


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, Mapping) else {}
    return {}


def _safe(value: Any, key: str | None = None) -> Any:
    """Make JSON-safe metadata while dropping values that could be secrets."""
    if key and any(token in key.lower() for token in _SENSITIVE):
        return None
    if isinstance(value, Mapping):
        return {str(k): cleaned for k, v in value.items() if (cleaned := _safe(v, str(k))) is not None}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _clean_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    cleaned = _safe(dict(value or {}))
    return cleaned if isinstance(cleaned, dict) else {}

def _known(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "null"}
def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    observed = getattr(value, "objects", None)
    if observed is not None and not isinstance(value, Mapping):
        return list(observed)
    if isinstance(value, Mapping) and isinstance(value.get("items"), list):
        return list(value["items"])
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _asset_key(asset: Any) -> str | None:
    data = _mapping(asset)
    if not data:
        return None
    if _known(data.get("key")):
        return str(data["key"])
    kind, name = data.get("kind"), data.get("name")
    if not (_known(kind) and _known(name)):
        return None
    return f"{kind}/{data.get('namespace') or '_cluster'}/{name}"


@dataclass(frozen=True)
class LineageNode:
    id: str
    kind: str
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # These aliases match the persistence/API graph vocabulary while the
        # concise id/kind/source fields remain convenient for Python callers.
        payload.update({"node_id": self.id, "node_type": self.kind, "name": self.label})
        return payload

    def dict(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True)
class LineageEdge:
    source: str
    target: str
    relation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.update({"source_node": self.source, "target_node": self.target})
        return payload

    def dict(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass
class LineageGraph:
    nodes: list[LineageNode] = field(default_factory=list)
    edges: list[LineageEdge] = field(default_factory=list)
    _node_index: dict[str, LineageNode] = field(default_factory=dict, init=False, repr=False)
    _edge_index: dict[tuple[str, str, str], LineageEdge] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        initial_nodes, initial_edges = list(self.nodes), list(self.edges)
        self.nodes, self.edges = [], []
        for node in initial_nodes:
            self.add_node(node)
        for edge in initial_edges:
            self.add_edge(edge)

    def add_node(self, node: LineageNode) -> LineageNode:
        if not _known(node.id):
            return node
        metadata = _clean_metadata(node.metadata)
        candidate = LineageNode(str(node.id), str(node.kind), node.label or str(node.id), metadata)
        previous = self._node_index.get(candidate.id)
        if previous is None:
            self._node_index[candidate.id] = candidate
        else:
            # Merging metadata makes output independent of input ordering.
            merged = {**previous.metadata, **candidate.metadata}
            merged = {key: merged[key] for key in sorted(merged)}
            candidate = LineageNode(previous.id, min(previous.kind, candidate.kind), min(previous.label, candidate.label), merged)
            self._node_index[candidate.id] = candidate
        self.nodes = sorted(self._node_index.values(), key=lambda item: item.id)
        return self._node_index[candidate.id]

    def add_edge(self, edge: LineageEdge) -> LineageEdge:
        if edge.source not in self._node_index or edge.target not in self._node_index:
            return edge
        candidate = LineageEdge(str(edge.source), str(edge.target), str(edge.relation), _clean_metadata(edge.metadata))
        key = (candidate.source, candidate.target, candidate.relation)
        previous = self._edge_index.get(key)
        if previous is None or json.dumps(candidate.metadata, sort_keys=True) < json.dumps(previous.metadata, sort_keys=True):
            self._edge_index[key] = candidate
        self.edges = sorted(self._edge_index.values(), key=lambda item: (item.source, item.target, item.relation))
        return self._edge_index[key]

    def get_node(self, node_id: str) -> LineageNode | None:
        if node_id in self._node_index:
            return self._node_index[node_id]
        matches = [node for node in self.nodes if node.id.rsplit(":", 1)[-1] == node_id or node.id.rsplit("/", 1)[-1] == node_id]
        return min(matches, key=lambda item: item.id) if matches else None

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "lineage/v1", "nodes": [node.to_dict() for node in self.nodes], "edges": [edge.to_dict() for edge in self.edges]}

    def dict(self) -> dict[str, Any]:
        return self.to_dict()

    def reverse_trace(self, start_id: str) -> list[LineageNode]:
        start = self.get_node(start_id)
        if start is None:
            return []
        incoming: dict[str, list[str]] = {}
        for edge in self.edges:
            incoming.setdefault(edge.target, []).append(edge.source)
        result: list[LineageNode] = []
        seen: set[str] = set()
        queue = [start.id]
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            node = self._node_index.get(current)
            if node:
                result.append(node)
            queue.extend(sorted(incoming.get(current, [])))
        return result

    def trace_from_finding(self, finding_id: str) -> list[LineageNode]:
        return self.reverse_trace(finding_id)

    def trace_from_asset(self, asset_id: str) -> list[LineageNode]:
        return self.reverse_trace(asset_id)


def _node_id(kind: str, value: Any) -> str | None:
    return f"{kind}:{value}" if _known(value) else None


def _add_record_node(graph: LineageGraph, record: Any, kind: str, id_keys: tuple[str, ...], label_keys: tuple[str, ...] = ()) -> str | None:
    data = _mapping(record)
    value = next((data.get(key) for key in id_keys if _known(data.get(key))), None)
    node_id = _node_id(kind, value)
    if node_id is None:
        return None
    label = next((str(data[key]) for key in label_keys if _known(data.get(key))), str(value))
    metadata = {key: data[key] for key in ("task_id", "source", "content_hash", "schema_version", "warning_count") if key in data}
    graph.add_node(LineageNode(node_id, kind, label, metadata))
    return node_id


def build_lineage_graph(
    raw_snapshots: Any = None,
    normalized_assets: Any = None,
    findings: Any = None,
    checkpoints: Any = None,
    reports: Any = None,
    sources: Any = None,
    *,
    assets: Any = None,
    quality_results: Any = None,
    anomalies: Any = None,
    associations: Any = None,
    cleaning_actions: Any = None,
    mapping_rules: Any = None,
) -> LineageGraph:
    """Build provenance records and only connect references that exist.

    Inputs may be dictionaries or the repository's dataclasses.  ``assets`` is
    an alias for ``normalized_assets``.  Missing IDs/references are skipped;
    no synthetic ``unknown`` node is created.
    """
    graph = LineageGraph()
    snapshots = _items(raw_snapshots)
    assets_input = normalized_assets if normalized_assets is not None else assets
    asset_records = _items(assets_input)
    finding_records = _items(findings)
    checkpoint_records = _items(checkpoints)
    report_records = _items(reports)

    source_ids: dict[str, str] = {}
    for source in _items(sources):
        data = _mapping(source)
        name = data.get("id") or data.get("source") or (source if isinstance(source, str) else None)
        node_id = _node_id("source", name)
        if node_id:
            graph.add_node(LineageNode(node_id, "source", str(name), _clean_metadata({k: data[k] for k in ("kind", "schema_version") if k in data})))
            source_ids[str(name)] = node_id

    snapshot_ids: dict[str, str] = {}
    for snapshot in snapshots:
        data = _mapping(snapshot)
        value = data.get("id") or data.get("content_hash") or (f"{data.get('source')}:{data.get('task_id')}" if _known(data.get("source")) else None)
        node_id = _node_id("raw_snapshot", value)
        if not node_id:
            continue
        graph.add_node(LineageNode(node_id, "raw_snapshot", str(value), {key: data[key] for key in ("task_id", "source", "content_hash", "schema_version", "warning_count") if key in data}))
        for key in ("id", "content_hash"):
            if _known(data.get(key)):
                snapshot_ids[str(data[key])] = node_id
        source_name = data.get("source")
        if _known(source_name):
            source_id = source_ids.get(str(source_name))
            if source_id is None:
                source_id = _node_id("source", source_name)
                graph.add_node(LineageNode(source_id, "source", str(source_name)))
                source_ids[str(source_name)] = source_id
            graph.add_edge(LineageEdge(source_id, node_id, "produces"))

    asset_ids: dict[str, str] = {}
    for asset in asset_records:
        key = _asset_key(asset)
        if key:
            node_id = _node_id("asset", key)
            data = _mapping(asset)
            graph.add_node(LineageNode(node_id, "normalized_asset", key.rsplit("/", 1)[-1], {k: data[k] for k in ("kind", "namespace", "api_version") if k in data}))
            asset_ids[key] = node_id
            ref = data.get("raw_snapshot_id") or data.get("snapshot_id") or data.get("source_snapshot_id")
            if _known(ref) and str(ref) in snapshot_ids:
                graph.add_edge(LineageEdge(snapshot_ids[str(ref)], node_id, "normalizes"))

    finding_ids: dict[str, str] = {}
    for finding in finding_records:
        data = _mapping(finding)
        value = data.get("id") or data.get("fingerprint") or data.get("rule_id")
        node_id = _node_id("finding", value)
        if not node_id:
            continue
        graph.add_node(LineageNode(node_id, "finding", str(data.get("title") or value), {k: data[k] for k in ("task_id", "tool_id", "checkpoint_id", "rule_id", "status", "severity") if k in data}))
        finding_ids[str(value)] = node_id
        asset = data.get("asset")
        key = _asset_key(asset)
        if key:
            asset_id = asset_ids.get(key)
            if asset_id is None:
                asset_id = _node_id("asset", key)
                graph.add_node(LineageNode(asset_id, "normalized_asset", key.rsplit("/", 1)[-1]))
                asset_ids[key] = asset_id
            graph.add_edge(LineageEdge(asset_id, node_id, "has_finding"))
        checkpoint_id = data.get("checkpoint_id")
        if _known(checkpoint_id):
            checkpoint_node = _node_id("checkpoint", checkpoint_id)
            if checkpoint_node in graph._node_index:
                graph.add_edge(LineageEdge(node_id, checkpoint_node, "evaluates"))

    checkpoint_ids: dict[str, str] = {}
    for checkpoint in checkpoint_records:
        data = _mapping(checkpoint)
        value = data.get("id")
        node_id = _node_id("checkpoint", value)
        if not node_id:
            continue
        graph.add_node(LineageNode(node_id, "checkpoint", str(data.get("name") or value), {k: data[k] for k in ("tender_no", "domain", "rule_group", "weight") if k in data}))
        checkpoint_ids[str(value)] = node_id
    # Checkpoint nodes may have been added after findings.
    for finding in finding_records:
        data = _mapping(finding)
        finding_id = finding_ids.get(str(data.get("id") or data.get("fingerprint") or data.get("rule_id")))
        checkpoint_node = checkpoint_ids.get(str(data.get("checkpoint_id")))
        if finding_id and checkpoint_node:
            graph.add_edge(LineageEdge(finding_id, checkpoint_node, "evaluates"))

    for report in report_records:
        data = _mapping(report)
        value = data.get("id") or data.get("task_id")
        report_id = _node_id("report", value)
        if not report_id:
            continue
        graph.add_node(LineageNode(report_id, "report", str(value), {k: data[k] for k in ("task_id", "schema_version", "generated_at") if k in data}))
        for finding in _items(data.get("findings")):
            ref = _mapping(finding).get("id") or _mapping(finding).get("fingerprint")
            finding_node = finding_ids.get(str(ref))
            if finding_node:
                checkpoint_ref = _mapping(finding).get("checkpoint_id")
                checkpoint_node = checkpoint_ids.get(str(checkpoint_ref))
                if checkpoint_node:
                    graph.add_edge(LineageEdge(checkpoint_node, report_id, "included_in"))
                else:
                    graph.add_edge(LineageEdge(finding_node, report_id, "included_in"))
        for checkpoint in _items(data.get("checkpoint_scores")):
            checkpoint_node = checkpoint_ids.get(str(_mapping(checkpoint).get("checkpoint_id")))
            if checkpoint_node:
                graph.add_edge(LineageEdge(checkpoint_node, report_id, "included_in"))
    def _refs(value: Any) -> set[str]:
        data = _mapping(value)
        refs: set[str] = {str(ref) for ref in data.get("evidence_refs", []) if ref}
        details = _mapping(data.get("details"))
        refs.update(str(ref) for ref in details.get("evidence_refs", []) if ref)
        for example in _items(data.get("examples")):
            example_data = _mapping(example)
            refs.update(str(ref) for ref in example_data.get("evidence_refs", example_data.get("record_refs", [])) if ref)
        return refs


    quality_nodes: dict[str, tuple[str, set[str]]] = {}
    for item in _items(quality_results):
        data = _mapping(item)
        rule_id = data.get("rule_id")
        node_id = _node_id("quality", rule_id)
        if not node_id:
            continue
        graph.add_node(LineageNode(node_id, "quality_result", str(rule_id), _clean_metadata({k: data[k] for k in ("status", "score", "dimension", "message") if k in data})))
        quality_nodes[str(rule_id)] = (node_id, _refs(data))

    anomaly_nodes: list[tuple[str, set[str]]] = []
    for item in _items(anomalies):
        data = _mapping(item)
        anomaly_id = data.get("anomaly_id") or data.get("id")
        node_id = _node_id("anomaly", anomaly_id)
        if not node_id:
            continue
        refs = {str(ref) for ref in data.get("evidence_refs", []) if ref}
        graph.add_node(LineageNode(node_id, "anomaly", str(data.get("field_path") or anomaly_id), _clean_metadata({k: data[k] for k in ("anomaly_type", "status", "source_id", "object_key", "field_path", "rule_id", "reason") if k in data})))
        anomaly_nodes.append((node_id, refs))
        source_name = data.get("source_id")
        if _known(source_name):
            source_node = source_ids.get(str(source_name)) or _node_id("source", source_name)
            if source_node:
                graph.add_node(LineageNode(source_node, "source", str(source_name)))
                source_ids[str(source_name)] = source_node
                graph.add_edge(LineageEdge(source_node, node_id, "observes"))

    association_nodes: list[tuple[str, set[str]]] = []
    association_data = _mapping(associations)
    for group in _items(association_data.get("groups")):
        data = _mapping(group)
        association_id = data.get("association_id")
        node_id = _node_id("association", association_id)
        if not node_id:
            continue
        refs = {str(ref) for ref in data.get("record_refs", []) if ref}
        graph.add_node(LineageNode(node_id, "association", str(association_id), _clean_metadata({k: data[k] for k in ("status", "source_ids", "reason") if k in data})))
        association_nodes.append((node_id, refs))
        for source_name in data.get("source_ids", []) or []:
            if _known(source_name):
                source_node = source_ids.get(str(source_name)) or _node_id("source", source_name)
                if source_node:
                    graph.add_node(LineageNode(source_node, "source", str(source_name)))
                    source_ids[str(source_name)] = source_node
                    graph.add_edge(LineageEdge(source_node, node_id, "associates"))

    for action_index, action in enumerate(_items(cleaning_actions)):
        data = _mapping(action)
        node_id = _node_id("cleaning", data.get("action_id") or f"{data.get('source_id', '')}|{data.get('object_key', '')}|{data.get('field_path', '')}|{action_index}")
        if not node_id:
            continue
        graph.add_node(LineageNode(node_id, "cleaning", str(data.get("field_path") or node_id), _clean_metadata({k: data[k] for k in ("action_type", "source_id", "object_key", "reason") if k in data})))
        source_name = data.get("source_id")
        if _known(source_name):
            source_node = source_ids.get(str(source_name)) or _node_id("source", source_name)
            if source_node:
                graph.add_node(LineageNode(source_node, "source", str(source_name)))
                source_ids[str(source_name)] = source_node
                graph.add_edge(LineageEdge(source_node, node_id, "cleans"))

    for rule in _items(mapping_rules):
        data = _mapping(rule)
        mapping_id = data.get("mapping_id") or data.get("id")
        node_id = _node_id("mapping", mapping_id)
        if node_id:
            graph.add_node(LineageNode(node_id, "mapping", str(mapping_id), _clean_metadata({k: data[k] for k in ("source_schema", "source_path", "target_path", "transform", "required") if k in data})))

    for quality_id, (quality_node, quality_refs) in quality_nodes.items():
        for anomaly_node, anomaly_refs in anomaly_nodes:
            if quality_refs & anomaly_refs:
                graph.add_edge(LineageEdge(anomaly_node, quality_node, "explains"))
        for association_node, association_refs in association_nodes:
            if quality_refs & association_refs:
                graph.add_edge(LineageEdge(association_node, quality_node, "supports"))
    return graph
def trace_from_quality(graph: LineageGraph, quality_id: str) -> list[LineageNode]:
    return graph.reverse_trace(quality_id if str(quality_id).startswith("quality:") else f"quality:{quality_id}")


def trace_from_anomaly(graph: LineageGraph, anomaly_id: str) -> list[LineageNode]:
    return graph.reverse_trace(anomaly_id if str(anomaly_id).startswith("anomaly:") else f"anomaly:{anomaly_id}")


def reverse_trace(graph: LineageGraph, node_id: str) -> list[LineageNode]:
    return graph.reverse_trace(node_id)


def trace_from_finding(graph: LineageGraph, finding_id: str) -> list[LineageNode]:
    return graph.trace_from_finding(finding_id)


def trace_from_asset(graph: LineageGraph, asset_id: str) -> list[LineageNode]:
    return graph.trace_from_asset(asset_id)


def query_lineage(graph: LineageGraph, node_id: str, direction: str = "reverse") -> list[LineageNode]:
    if direction.lower() in {"reverse", "backward", "upstream", "in"}:
        return graph.reverse_trace(node_id)
    node = graph.get_node(node_id)
    if node is None:
        return []
    outgoing = {edge.source: [] for edge in graph.edges}
    for edge in graph.edges:
        outgoing.setdefault(edge.source, []).append(edge.target)
    result, seen, queue = [], set(), [node.id]
    while queue:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        found = graph.get_node(current)
        if found:
            result.append(found)
        queue.extend(sorted(outgoing.get(current, [])))
    return result


__all__ = ["LineageNode", "LineageEdge", "LineageGraph", "build_lineage_graph", "reverse_trace", "trace_from_finding", "trace_from_asset", "trace_from_quality", "trace_from_anomaly", "query_lineage"]

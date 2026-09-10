"""Security-relevant relationships between Kubernetes and RBAC assets.

Only observed objects and matrix-row references become nodes.  References in
an object are linked when the referenced object is present; this avoids
inventing placeholder resources for incomplete collection evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from collections.abc import Iterable, Mapping
import hashlib
import json
from typing import Any


_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
_CONTROL_CONFIG_KINDS = {"ControlPlaneConfig", "APIServerFlags", "EtcdFlags", "KubeletConfig", "ClusterConfiguration"}
_CONTROL_CONFIG_NAMES = {"kubeadm-config", "kubelet-config", "extension-apiserver-authentication"}
_SENSITIVE = ("password", "passwd", "secret", "token", "private_key", "privatekey", "bearer", "encryption_key", "key_material")


def _data(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    converter = getattr(value, "to_dict", None)
    if callable(converter):
        result = converter()
        return result if isinstance(result, Mapping) else {}
    return {}


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


def _known(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "null"}


def _safe(value: Any, key: str | None = None) -> Any:
    if key and any(token in key.lower() for token in _SENSITIVE):
        return None
    if isinstance(value, Mapping):
        result = {}
        for item_key, item_value in value.items():
            cleaned = _safe(item_value, str(item_key))
            if cleaned is not None:
                result[str(item_key)] = cleaned
        return result
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _namespace(data: Mapping[str, Any]) -> str | None:
    value = _data(data.get("metadata", {})).get("namespace")
    return str(value) if _known(value) else None


def _ref_id(kind: Any, name: Any, namespace: Any = None) -> str | None:
    if not (_known(kind) and _known(name)):
        return None
    # Cluster-scoped RBAC objects and nodes use _cluster even if a malformed
    # input happens to carry a namespace.
    cluster = str(kind) in {"ClusterRole", "ClusterRoleBinding", "Node", "PersistentVolume", "Namespace", "StorageClass", "IngressClass"}
    ns = "_cluster" if cluster else (str(namespace) if _known(namespace) else "_cluster")
    return f"{kind}/{ns}/{name}"


def _object_id(obj: Mapping[str, Any]) -> str | None:
    metadata = _data(obj.get("metadata", {}))
    return _ref_id(obj.get("kind"), metadata.get("name"), metadata.get("namespace"))


def _object_metadata(obj: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _data(obj.get("metadata", {}))
    result: dict[str, Any] = {}
    for key in ("uid", "labels", "annotations", "creationTimestamp", "resourceVersion"):
        if key in metadata:
            result[key] = _safe(metadata[key], key)
    kind = obj.get("kind")
    if kind in _WORKLOADS:
        result["category"] = "workload"
    if kind in _CONTROL_CONFIG_KINDS:
        result["category"] = "control-plane-config"
    if kind in {"Secret", "ConfigMap"}:
        for key in ("data_key_count", "data_keys"):
            if key in obj:
                result[key] = _safe(obj[key], key)
        # A raw object may not have been sanitized by collector.py.  Expose
        # only counts, never values or stringData.
        if "data" in obj and isinstance(obj["data"], Mapping):
            result.setdefault("data_key_count", len(obj["data"]))
            result.setdefault("data_keys", sorted(str(key) for key in obj["data"]))
        if "stringData" in obj and isinstance(obj["stringData"], Mapping):
            result["data_key_count"] = result.get("data_key_count", 0) + len(obj["stringData"])
            result["data_keys"] = sorted(set(result.get("data_keys", [])) | {str(key) for key in obj["stringData"]})
    return {key: value for key, value in result.items() if value is not None}


@dataclass(frozen=True)
class AssetNode:
    id: str
    kind: str
    name: str
    namespace: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # ``key`` is the normalized-asset persistence identifier.
        payload["key"] = self.id
        return payload

    def dict(self) -> dict[str, Any]:
        return self.to_dict()
@dataclass(frozen=True)
class AssetEdge:
    source: str
    target: str
    relation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def dict(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass
class AssetGraph:
    nodes: list[AssetNode] = field(default_factory=list)
    edges: list[AssetEdge] = field(default_factory=list)
    _node_index: dict[str, AssetNode] = field(default_factory=dict, init=False, repr=False)
    _edge_index: dict[tuple[str, str, str], AssetEdge] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        initial_nodes, initial_edges = list(self.nodes), list(self.edges)
        self.nodes, self.edges = [], []
        for node in initial_nodes:
            self.add_node(node)
        for edge in initial_edges:
            self.add_edge(edge)

    def add_node(self, node: AssetNode) -> AssetNode:
        if not _known(node.id):
            return node
        candidate = AssetNode(str(node.id), str(node.kind), str(node.name), node.namespace, _safe(node.metadata) or {})
        old = self._node_index.get(candidate.id)
        if old is not None:
            merged = {**old.metadata, **candidate.metadata}
            candidate = AssetNode(old.id, min(old.kind, candidate.kind), min(old.name, candidate.name), old.namespace or candidate.namespace, {key: merged[key] for key in sorted(merged)})
        self._node_index[candidate.id] = candidate
        self.nodes = sorted(self._node_index.values(), key=lambda item: item.id)
        return candidate

    def add_edge(self, edge: AssetEdge) -> AssetEdge:
        if edge.source not in self._node_index or edge.target not in self._node_index:
            return edge
        candidate = AssetEdge(str(edge.source), str(edge.target), str(edge.relation), _safe(edge.metadata) or {})
        key = (candidate.source, candidate.target, candidate.relation)
        old = self._edge_index.get(key)
        if old is None or json.dumps(candidate.metadata, sort_keys=True) < json.dumps(old.metadata, sort_keys=True):
            self._edge_index[key] = candidate
        self.edges = sorted(self._edge_index.values(), key=lambda item: (item.source, item.target, item.relation))
        return self._edge_index[key]

    def get_node(self, node_id: str) -> AssetNode | None:
        if node_id in self._node_index:
            return self._node_index[node_id]
        matches = [node for node in self.nodes if node.name == node_id or node.id.endswith("/" + node_id)]
        return min(matches, key=lambda item: item.id) if matches else None

    def neighbors(self, node_id: str, relation: str | None = None, direction: str = "both") -> list[AssetNode]:
        node = self.get_node(node_id)
        if node is None:
            return []
        selected: set[str] = set()
        for edge in self.edges:
            if relation and edge.relation != relation:
                continue
            if direction in {"both", "out", "outgoing"} and edge.source == node.id:
                selected.add(edge.target)
            if direction in {"both", "in", "incoming"} and edge.target == node.id:
                selected.add(edge.source)
        return [self._node_index[item] for item in sorted(selected)]

    def related_assets(self, node_id: str, relation: str | None = None, direction: str = "both") -> list[AssetNode]:
        return self.neighbors(node_id, relation, direction)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "asset-graph/v1", "nodes": [node.to_dict() for node in self.nodes], "edges": [edge.to_dict() for edge in self.edges]}

    def dict(self) -> dict[str, Any]:
        return self.to_dict()


def _add_object_nodes(graph: AssetGraph, objects: list[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    for obj in objects:
        node_id = _object_id(obj)
        metadata = _data(obj.get("metadata", {}))
        name = metadata.get("name")
        if not (node_id and _known(name) and _known(obj.get("kind"))):
            continue
        kind = str(obj["kind"])
        node = AssetNode(node_id, kind, str(name), _namespace(obj), _object_metadata(obj))
        graph.add_node(node)
        by_id[node_id] = obj
    return by_id


def _add_ref_edge(graph: AssetGraph, by_id: Mapping[str, Mapping[str, Any]], source: str, kind: Any, name: Any, namespace: Any, relation: str, metadata: Mapping[str, Any] | None = None) -> None:
    target = _ref_id(kind, name, namespace)
    if target and target in by_id:
        graph.add_edge(AssetEdge(source, target, relation, dict(metadata or {})))


def _pod_spec(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    spec = _data(obj.get("spec", {}))
    template = _data(spec.get("template", {}))
    if template:
        return _data(template.get("spec", {}))
    return spec


def _pod_labels(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    spec = _data(obj.get("spec", {}))
    template = _data(spec.get("template", {}))
    return _data(template.get("metadata", {})).get("labels", {}) or _data(obj.get("metadata", {})).get("labels", {}) or {}


def _add_object_edges(graph: AssetGraph, objects: list[Mapping[str, Any]], by_id: Mapping[str, Mapping[str, Any]]) -> None:
    for obj in objects:
        source = _object_id(obj)
        if source not in by_id:
            continue
        kind = str(obj.get("kind"))
        namespace = _namespace(obj)
        spec = _pod_spec(obj)
        if kind in _WORKLOADS or kind == "Pod":
            service_account = spec.get("serviceAccountName") or spec.get("serviceAccount")
            _add_ref_edge(graph, by_id, source, "ServiceAccount", service_account, namespace, "uses_service_account")
            for volume in spec.get("volumes", []) or []:
                volume = _data(volume)
                secret = _data(volume.get("secret", {}))
                config = _data(volume.get("configMap", {}))
                pvc = _data(volume.get("persistentVolumeClaim", {}))
                _add_ref_edge(graph, by_id, source, "Secret", secret.get("secretName"), namespace, "mounts_secret")
                _add_ref_edge(graph, by_id, source, "ConfigMap", config.get("name"), namespace, "mounts_configmap")
                _add_ref_edge(graph, by_id, source, "PersistentVolumeClaim", pvc.get("claimName"), namespace, "mounts_pvc")
            containers = [*(spec.get("containers", []) or []), *(spec.get("initContainers", []) or [])]
            for container in containers:
                for env in _data(container).get("env", []) or []:
                    value_from = _data(_data(env).get("valueFrom", {}))
                    secret_key = _data(value_from.get("secretKeyRef", {}))
                    config_key = _data(value_from.get("configMapKeyRef", {}))
                    _add_ref_edge(graph, by_id, source, "Secret", secret_key.get("name"), namespace, "reads_secret")
                    _add_ref_edge(graph, by_id, source, "ConfigMap", config_key.get("name"), namespace, "reads_configmap")
                for env_from in _data(container).get("envFrom", []) or []:
                    env_from = _data(env_from)
                    _add_ref_edge(graph, by_id, source, "Secret", _data(env_from.get("secretRef", {})).get("name"), namespace, "reads_secret")
                    _add_ref_edge(graph, by_id, source, "ConfigMap", _data(env_from.get("configMapRef", {})).get("name"), namespace, "reads_configmap")
        if kind == "Pod":
            _add_ref_edge(graph, by_id, source, "Node", _data(obj.get("spec", {})).get("nodeName"), None, "scheduled_on")
            for owner in _data(obj.get("metadata", {})).get("ownerReferences", []) or []:
                owner = _data(owner)
                _add_ref_edge(graph, by_id, source, owner.get("kind"), owner.get("name"), namespace, "owned_by")
        if kind == "Service":
            selector = _data(obj.get("spec", {})).get("selector", {}) or {}
            if selector:
                for candidate in objects:
                    candidate_id = _object_id(candidate)
                    if candidate_id not in by_id or str(candidate.get("kind")) not in _WORKLOADS | {"Pod"}:
                        continue
                    if _namespace(candidate) != namespace:
                        continue
                    labels = _pod_labels(candidate)
                    if all(labels.get(key) == value for key, value in selector.items()):
                        graph.add_edge(AssetEdge(source, candidate_id, "selects"))
        if kind == "Ingress":
            ingress_spec = _data(obj.get("spec", {}))
            backends = []
            if _data(ingress_spec.get("defaultBackend", {})):
                backends.append(_data(ingress_spec["defaultBackend"]))
            for rule in ingress_spec.get("rules", []) or []:
                http = _data(_data(rule).get("http", {}))
                backends.extend(_data(path).get("backend", {}) for path in http.get("paths", []) or [])
            for backend in backends:
                backend = _data(backend)
                service = _data(backend.get("service", {}))
                service_name = service.get("name") or backend.get("serviceName")
                _add_ref_edge(graph, by_id, source, "Service", service_name, namespace, "routes_to")
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = _data(obj.get("roleRef", {}))
            role_kind, role_name = role_ref.get("kind"), role_ref.get("name")
            role_namespace = namespace if role_kind == "Role" else None
            _add_ref_edge(graph, by_id, source, role_kind, role_name, role_namespace, "binds_to")
            for subject in obj.get("subjects", []) or []:
                subject = _data(subject)
                subject_kind = subject.get("kind")
                subject_name = subject.get("name")
                subject_namespace = subject.get("namespace") or namespace if subject_kind == "ServiceAccount" else None
                _add_ref_edge(graph, by_id, source, subject_kind, subject_name, subject_namespace, "grants_to")
        if kind in {"Role", "ClusterRole"}:
            for rule in obj.get("rules", []) or []:
                rule = _data(rule)
                signature = json.dumps({key: rule.get(key) or [] for key in ("apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs")}, sort_keys=True, separators=(",", ":"))
                permission_id = "Permission/_cluster/" + hashlib.sha256(signature.encode()).hexdigest()[:16]
                graph.add_node(AssetNode(permission_id, "Permission", signature, None, {"rule": _safe(dict(rule)) or {}}))
                graph.add_edge(AssetEdge(source, permission_id, "grants_permission"))
        if kind in _CONTROL_CONFIG_KINDS:
            for candidate in objects:
                candidate_id = _object_id(candidate)
                if candidate_id in by_id and str(candidate.get("kind")) == "Pod" and _namespace(candidate) == "kube-system" and str(_data(candidate.get("metadata", {})).get("name", "")).startswith(("kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler")):
                    graph.add_edge(AssetEdge(source, candidate_id, "configures"))
    # Well-known control-plane ConfigMaps configure the static control-plane pods.
    for obj in objects:
        source = _object_id(obj)
        if source not in by_id or str(obj.get("kind")) != "ConfigMap":
            continue
        name = str(_data(obj.get("metadata", {})).get("name", ""))
        if name not in _CONTROL_CONFIG_NAMES:
            continue
        for candidate in objects:
            candidate_id = _object_id(candidate)
            candidate_name = str(_data(candidate.get("metadata", {})).get("name", ""))
            if candidate_id in by_id and str(candidate.get("kind")) == "Pod" and _namespace(candidate) == "kube-system" and candidate_name.startswith(("kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler")):
                graph.add_edge(AssetEdge(source, candidate_id, "configures"))

def _matrix_rows(rows: Any) -> list[Mapping[str, Any]]:
    if isinstance(rows, Mapping) and isinstance(rows.get("rows"), list):
        rows = rows["rows"]
    return [item for item in _items(rows) if isinstance(item, Mapping)]
def _subject_parts(row: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    kind = row.get("subject_kind")
    name = row.get("subject_name")
    namespace = row.get("subject_namespace")
    subject = row.get("subject")
    if isinstance(subject, Mapping):
        kind = kind or subject.get("kind")
        name = name or subject.get("name")
        namespace = namespace or subject.get("namespace")
    elif not (_known(kind) and _known(name)) and _known(subject):
        text = str(subject)
        if ":" in text:
            kind, text = text.split(":", 1)
        if "/" in text:
            namespace, name = text.split("/", 1)
        else:
            name = text
    return (str(kind) if _known(kind) else None, str(name) if _known(name) else None, str(namespace) if _known(namespace) else None)


def build_asset_graph_from_rbac(rows: Any, graph: AssetGraph | None = None) -> AssetGraph:
    result = graph or AssetGraph()
    for row in _matrix_rows(rows):
        binding_kind, binding_name = row.get("binding_kind"), row.get("binding_name")
        binding_namespace = row.get("binding_namespace")
        binding_id = _ref_id(binding_kind, binding_name, binding_namespace)
        role_kind, role_name = row.get("role_kind"), row.get("role_name")
        role_namespace = row.get("role_namespace") if role_kind == "Role" else None
        role_id = _ref_id(role_kind, role_name, role_namespace)
        subject_kind, subject_name, subject_namespace = _subject_parts(row)
        subject_id = _ref_id(subject_kind, subject_name, subject_namespace)
        if binding_id:
            result.add_node(AssetNode(binding_id, str(binding_kind), str(binding_name), str(binding_namespace) if _known(binding_namespace) else None, {"source": "rbac_matrix"}))
        if role_id:
            result.add_node(AssetNode(role_id, str(role_kind), str(role_name), str(role_namespace) if _known(role_namespace) else None, {"source": "rbac_matrix"}))
        if subject_id:
            result.add_node(AssetNode(subject_id, str(subject_kind), str(subject_name), str(subject_namespace) if _known(subject_namespace) else None, {"source": "rbac_matrix"}))
        if binding_id and role_id:
            result.add_edge(AssetEdge(binding_id, role_id, "binds_to"))
        if binding_id and subject_id:
            result.add_edge(AssetEdge(binding_id, subject_id, "grants_to"))
        permission_values = {key: row.get(key) or [] for key in ("api_groups", "resources", "verbs", "resource_names")}
        if any(permission_values.values()) and role_id:
            signature = json.dumps(permission_values, sort_keys=True, separators=(",", ":"))
            permission_id = "Permission/_cluster/" + hashlib.sha256(signature.encode()).hexdigest()[:16]
            result.add_node(AssetNode(permission_id, "Permission", signature, None, {"source": "rbac_matrix", **_safe(permission_values)}))
            result.add_edge(AssetEdge(role_id, permission_id, "grants_permission"))
    return result


def build_asset_graph_from_objects(objects: Any, rbac_rows: Any = None) -> AssetGraph:
    result = AssetGraph()
    normalized = [item for item in _items(objects) if isinstance(item, Mapping) and _known(item.get("kind"))]
    by_id = _add_object_nodes(result, normalized)
    _add_object_edges(result, normalized, by_id)
    if rbac_rows is not None:
        build_asset_graph_from_rbac(rbac_rows, result)
    return result


def build_asset_graph(objects: Any = None, rbac_rows: Any = None, *, rows: Any = None) -> AssetGraph:
    """Build a graph from Kubernetes objects and optional RBAC matrix rows."""
    return build_asset_graph_from_objects(objects, rbac_rows if rbac_rows is not None else rows)


build_kubernetes_asset_graph = build_asset_graph_from_objects
build_asset_graph_from_kubernetes = build_asset_graph_from_objects


__all__ = ["AssetNode", "AssetEdge", "AssetGraph", "build_asset_graph", "build_asset_graph_from_objects", "build_asset_graph_from_rbac", "build_kubernetes_asset_graph", "build_asset_graph_from_kubernetes"]

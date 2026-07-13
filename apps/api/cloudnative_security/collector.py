from __future__ import annotations

import json
import hashlib
import re
import shlex
import subprocess
import copy
from pathlib import Path
from typing import Any, Iterable

import yaml


KUBECTL_RESOURCES = [
    "namespaces",
    "nodes",
    "pods",
    "deployments.apps",
    "statefulsets.apps",
    "replicasets.apps",
    "daemonsets.apps",
    "jobs.batch",
    "cronjobs.batch",
    "services",
    "configmaps",
    "secrets",
    "ingresses.networking.k8s.io",
    "serviceaccounts",
    "roles.rbac.authorization.k8s.io",
    "clusterroles.rbac.authorization.k8s.io",
    "rolebindings.rbac.authorization.k8s.io",
    "clusterrolebindings.rbac.authorization.k8s.io",
    "horizontalpodautoscalers.autoscaling",
    "poddisruptionbudgets.policy",
    "resourcequotas",
    "limitranges",
    "priorityclasses.scheduling.k8s.io",
    "apiservices.apiregistration.k8s.io",
    "networkpolicies.networking.k8s.io",
    "storageclasses.storage.k8s.io",
    "persistentvolumes",
    "persistentvolumeclaims",
    "volumesnapshots.snapshot.storage.k8s.io",
    "volumesnapshotclasses.snapshot.storage.k8s.io",
    "volumesnapshotcontents.snapshot.storage.k8s.io",
    "backups.velero.io",
    "schedules.velero.io",
    "events",
    "clusterpolicies.kyverno.io",
    "policies.kyverno.io",
    "validatingadmissionpolicies.admissionregistration.k8s.io",
    "validatingadmissionpolicybindings.admissionregistration.k8s.io",
    "vulnerabilityreports.aquasecurity.github.io",
    "clustervulnerabilityreports.aquasecurity.github.io",
    "configauditreports.aquasecurity.github.io",
    "clusterconfigauditreports.aquasecurity.github.io",
    "rbacassessmentreports.aquasecurity.github.io",
    "clusterrbacassessmentreports.aquasecurity.github.io",
    "infraassessmentreports.aquasecurity.github.io",
    "clusterinfraassessmentreports.aquasecurity.github.io",
    "exposedsecretreports.aquasecurity.github.io",
    "sbomreports.aquasecurity.github.io",
    "clustersbomreports.aquasecurity.github.io",
]


def _nested_ssh_remote(ssh_key: str, user: str, host: str, inner: str) -> str:
    # PVE demo VMs are often restored or rebuilt, so their SSH host keys rotate.
    # Keep collection resilient instead of failing the whole evidence chain on
    # stale known_hosts entries.
    return " ".join(
        [
            "ssh",
            "-i",
            shlex.quote(ssh_key),
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            f"{shlex.quote(user)}@{shlex.quote(host)}",
            shlex.quote(inner),
        ]
    )


class ResourceIndex:
    def __init__(self, objects: Iterable[dict[str, Any]], warnings: list[str] | None = None) -> None:
        self.objects = [sanitize_resource(obj) for obj in objects if obj and obj.get("kind") and obj.get("metadata")]
        self.warnings = warnings or []

    def by_kind(self, kind: str) -> list[dict[str, Any]]:
        return [obj for obj in self.objects if obj.get("kind") == kind]

    def kinds(self) -> set[str]:
        return {obj.get("kind", "") for obj in self.objects}

    def namespaced(self, namespace: str | None = None) -> list[dict[str, Any]]:
        return [obj for obj in self.objects if obj.get("metadata", {}).get("namespace") == namespace]


def sanitize_resource(obj: dict[str, Any]) -> dict[str, Any]:
    item = copy.deepcopy(obj)
    kind = item.get("kind")
    if kind == "Secret":
        data = item.pop("data", None) or {}
        string_data = item.pop("stringData", None) or {}
        item["data_key_count"] = len(data) + len(string_data)
        item["data_keys"] = sorted([*data.keys(), *string_data.keys()])
    elif kind == "ConfigMap":
        data = item.pop("data", None) or {}
        binary_data = item.pop("binaryData", None) or {}
        item["data_key_count"] = len(data) + len(binary_data)
        item["data_keys"] = sorted([*data.keys(), *binary_data.keys()])
    return item


def load_manifest_path(path: str | Path) -> ResourceIndex:
    root = Path(path)
    files: list[Path]
    if root.is_dir():
        files = sorted([p for p in root.rglob("*") if p.suffix in {".yaml", ".yml", ".json", ".jsonl", ".log"}])
    else:
        files = [root]

    objects: list[dict[str, Any]] = []
    warnings: list[str] = []
    for file_path in files:
        try:
            if file_path.suffix == ".log":
                docs = parse_auth_log(file_path)
            elif file_path.suffix == ".jsonl":
                docs = [json.loads(line) for line in file_path.read_text().splitlines() if line.strip()]
            elif file_path.suffix == ".json":
                data = json.loads(file_path.read_text())
                docs = data.get("items", data if isinstance(data, list) else [data])
            else:
                docs = list(yaml.safe_load_all(file_path.read_text()))
        except Exception as exc:  # pragma: no cover - defensive path
            warnings.append(f"failed to parse {file_path}: {exc}")
            continue
        for doc in docs:
            if isinstance(doc, dict) and doc.get("kind") == "List":
                objects.extend([item for item in doc.get("items", []) if isinstance(item, dict)])
            elif isinstance(doc, dict):
                objects.append(normalize_event_document(doc, file_path.stem))
    return ResourceIndex(objects, warnings)


def normalize_event_document(doc: dict[str, Any], source_name: str) -> dict[str, Any]:
    if doc.get("kind") and doc.get("metadata"):
        return doc
    if doc.get("source") == "falco" or doc.get("rule") or doc.get("priority"):
        name = str(doc.get("event_id") or doc.get("id") or doc.get("rule") or source_name or "falco-event")
        normalized_name = re.sub(r"[^a-z0-9.-]+", "-", name.lower()).strip("-")[:63] or "falco-event"
        namespace = None
        k8s = doc.get("k8s") if isinstance(doc.get("k8s"), dict) else {}
        namespace = k8s.get("namespace") or k8s.get("ns") or doc.get("namespace")
        return {
            **doc,
            "apiVersion": "fixtures.cnsec/v1",
            "kind": "FalcoEvent",
            "source": doc.get("source") or "falco",
            "metadata": {"name": normalized_name, "namespace": namespace} if namespace else {"name": normalized_name},
        }
    return doc


def parse_auth_log(path: str | Path) -> list[dict[str, Any]]:
    return parse_auth_log_text(Path(path).read_text(), Path(path).stem)


def parse_auth_log_text(text: str, source_name: str = "authlog") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    failed_pattern = re.compile(
        r"^(?P<time>\S+)\s+(?P<node>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<remote_ip>\S+)"
    )
    success_pattern = re.compile(
        r"^(?P<time>\S+)\s+(?P<node>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Accepted (?P<auth_method>\S+) for (?P<user>\S+) from (?P<remote_ip>\S+)"
    )
    for line_no, line in enumerate(text.splitlines(), start=1):
        failed = failed_pattern.search(line)
        if failed:
            payload = failed.groupdict()
            events.append(
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuthLogEvent",
                    "metadata": {
                        "name": f"{source_name}-{line_no}",
                        "labels": {"source": "authlog", "event_type": "ssh_failed_password"},
                    },
                    "source": "authlog",
                    "event_type": "ssh_failed_password",
                    "outcome": "failure",
                    "raw": line,
                    **payload,
                }
            )
            continue
        success = success_pattern.search(line)
        if success:
            payload = success.groupdict()
            events.append(
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuthLogEvent",
                    "metadata": {
                        "name": f"{source_name}-{line_no}",
                        "labels": {"source": "authlog", "event_type": "ssh_login_success"},
                    },
                    "source": "authlog",
                    "event_type": "ssh_login_success",
                    "outcome": "success",
                    "raw": line,
                    **payload,
                }
            )
    return events


def collect_kubectl(kubeconfig: str | None = None, kubectl: str = "kubectl") -> ResourceIndex:
    objects: list[dict[str, Any]] = []
    warnings: list[str] = []
    base = [kubectl]
    if kubeconfig:
        base.extend(["--kubeconfig", kubeconfig])
    for resource in KUBECTL_RESOURCES:
        cmd = [*base, "get", resource, "-A", "-o", "json"]
        if resource in {"nodes", "persistentvolumes", "storageclasses.storage.k8s.io", "volumesnapshotclasses.snapshot.storage.k8s.io", "volumesnapshotcontents.snapshot.storage.k8s.io", "clusterroles.rbac.authorization.k8s.io", "clusterrolebindings.rbac.authorization.k8s.io", "priorityclasses.scheduling.k8s.io", "apiservices.apiregistration.k8s.io", "clusterpolicies.kyverno.io", "validatingadmissionpolicies.admissionregistration.k8s.io", "validatingadmissionpolicybindings.admissionregistration.k8s.io", "clusterinfraassessmentreports.aquasecurity.github.io", "clustersbomreports.aquasecurity.github.io"}:
            cmd = [*base, "get", resource, "-o", "json"]
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            warnings.append(f"{resource}: {proc.stderr.strip()}")
            continue
        payload = json.loads(proc.stdout)
        objects.extend(payload.get("items", []))
    return ResourceIndex(objects, warnings)


def collect_pve_auth_logs(
    objects: list[dict[str, Any]],
    pve_ssh: str,
    ssh_key: str,
    user: str,
    line_limit: int = 500,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for node_name, node_ip in node_internal_ips(objects).items():
        inner = f"tail -n {int(line_limit)} /var/log/auth.log 2>/dev/null || true"
        remote = _nested_ssh_remote(ssh_key, user, node_ip, inner)
        proc = subprocess.run(["ssh", pve_ssh, remote], text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            continue
        parsed_events = parse_auth_log_text(proc.stdout, f"{node_name}-authlog")
        events.append(
            {
                "apiVersion": "fixtures.cnsec/v1",
                "kind": "AuthLogSource",
                "metadata": {
                    "name": f"{node_name}-authlog",
                    "labels": {"source": "authlog", "node": node_name},
                },
                "source": "authlog",
                "node": node_name,
                "node_ip": node_ip,
                "line_count": len([line for line in proc.stdout.splitlines() if line.strip()]),
                "failed_password_count": len(parsed_events),
            }
        )
        for event in parsed_events:
            event.setdefault("metadata", {}).setdefault("labels", {})["node"] = node_name
            event["node_ip"] = node_ip
            events.append(event)
    return events


def parse_static_pod_manifest(
    text: str,
    path: str,
    node_name: str,
    node_ip: str,
) -> dict[str, Any] | None:
    try:
        manifest = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(manifest, dict) or manifest.get("kind") != "Pod":
        return None
    metadata = manifest.get("metadata", {}) or {}
    component = (metadata.get("labels", {}) or {}).get("component") or metadata.get("name") or Path(path).stem
    containers = manifest.get("spec", {}).get("containers", []) or []
    command: list[str] = []
    for container in containers:
        command.extend(container.get("command") or [])
        command.extend(container.get("args") or [])
    return {
        "apiVersion": "fixtures.cnsec/v1",
        "kind": "ControlPlaneManifest",
        "metadata": {
            "name": f"{node_name}-{Path(path).stem}",
            "labels": {
                "source": "static-pod-manifest",
                "node": node_name,
                "component": str(component),
            },
        },
        "source": "static-pod-manifest",
        "node": node_name,
        "node_ip": node_ip,
        "path": path,
        "component": component,
        "manifest_hash": hashlib.sha256(text.encode()).hexdigest(),
        "command": command,
        "manifest": manifest,
    }


def _command_flag_value(command: list[str], key: str) -> str | None:
    prefix = f"--{key}="
    for index, token in enumerate(command):
        text = str(token)
        if text.startswith(prefix):
            return text.split("=", 1)[1]
        if text == f"--{key}" and index + 1 < len(command):
            return str(command[index + 1])
    return None


def parse_encryption_provider_config(
    text: str,
    path: str,
    node_name: str,
    node_ip: str,
) -> dict[str, Any] | None:
    try:
        config = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(config, dict):
        return None
    resources = []
    for item in config.get("resources", []) or []:
        if not isinstance(item, dict):
            continue
        providers = []
        for provider in item.get("providers", []) or []:
            if isinstance(provider, dict):
                providers.extend(str(name) for name in provider.keys())
        resources.append(
            {
                "resources": [str(resource) for resource in item.get("resources", []) or []],
                "provider_names": providers,
            }
        )
    return {
        "apiVersion": "fixtures.cnsec/v1",
        "kind": "EncryptionProviderConfig",
        "metadata": {
            "name": f"{node_name}-{Path(path).name}",
            "labels": {
                "source": "encryption-provider-config",
                "node": node_name,
                "component": "kube-apiserver",
            },
        },
        "source": "encryption-provider-config",
        "node": node_name,
        "node_ip": node_ip,
        "path": path,
        "config_hash": hashlib.sha256(text.encode()).hexdigest(),
        "config": config,
        "resources": resources,
    }


def collect_pve_control_plane_manifests(
    objects: list[dict[str, Any]],
    pve_ssh: str,
    control_plane_ip: str,
    ssh_key: str,
    user: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    manifests: list[dict[str, Any]] = []
    warnings: list[str] = []
    node_ips = node_internal_ips(objects)
    control_plane_nodes = [
        obj for obj in objects
        if obj.get("kind") == "Node" and (
            "node-role.kubernetes.io/control-plane" in (obj.get("metadata", {}).get("labels", {}) or {})
            or obj.get("metadata", {}).get("name", "").startswith("k8s-cp")
        )
    ]
    targets: dict[str, str] = {}
    for node in control_plane_nodes:
        name = node.get("metadata", {}).get("name")
        if name and node_ips.get(name):
            targets[name] = node_ips[name]
    if not targets:
        targets["control-plane"] = control_plane_ip

    paths = [
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "/etc/kubernetes/manifests/etcd.yaml",
        "/etc/kubernetes/manifests/kube-controller-manager.yaml",
        "/etc/kubernetes/manifests/kube-scheduler.yaml",
    ]
    for node_name, node_ip in sorted(targets.items()):
        for path in paths:
            inner = f"sudo cat {shlex.quote(path)} 2>/dev/null"
            remote = _nested_ssh_remote(ssh_key, user, node_ip, inner)
            proc = subprocess.run(["ssh", pve_ssh, remote], text=True, capture_output=True, check=False)
            if proc.returncode != 0 or not proc.stdout.strip():
                warnings.append(f"control-plane manifest {node_name}:{path}: not collected")
                continue
            manifest = parse_static_pod_manifest(proc.stdout, path, node_name, node_ip)
            if manifest:
                manifests.append(manifest)
                encryption_config_path = _command_flag_value(manifest.get("command") or [], "encryption-provider-config")
                if encryption_config_path:
                    inner_cfg = f"sudo cat {shlex.quote(encryption_config_path)} 2>/dev/null"
                    remote_cfg = _nested_ssh_remote(ssh_key, user, node_ip, inner_cfg)
                    proc_cfg = subprocess.run(["ssh", pve_ssh, remote_cfg], text=True, capture_output=True, check=False)
                    if proc_cfg.returncode != 0 or not proc_cfg.stdout.strip():
                        warnings.append(f"encryption provider config {node_name}:{encryption_config_path}: not collected")
                    else:
                        encryption_obj = parse_encryption_provider_config(proc_cfg.stdout, encryption_config_path, node_name, node_ip)
                        if encryption_obj:
                            manifests.append(encryption_obj)
                        else:
                            warnings.append(f"encryption provider config {node_name}:{encryption_config_path}: parse failed")
            else:
                warnings.append(f"control-plane manifest {node_name}:{path}: parse failed")
    return manifests, warnings


def node_internal_ips(objects: list[dict[str, Any]]) -> dict[str, str]:
    nodes: dict[str, str] = {}
    for obj in objects:
        if obj.get("kind") != "Node":
            continue
        name = obj.get("metadata", {}).get("name")
        for address in obj.get("status", {}).get("addresses", []) or []:
            if address.get("type") == "InternalIP" and name and address.get("address"):
                nodes[name] = address["address"]
                break
    return nodes


def collect_pve_kubectl(
    pve_ssh: str = "cloudnative-env",
    control_plane_ip: str = "10.20.0.11",
    ssh_key: str = "/root/.ssh/agent_lab",
    user: str = "agent",
) -> ResourceIndex:
    objects: list[dict[str, Any]] = []
    warnings: list[str] = []
    for resource in KUBECTL_RESOURCES:
        kubectl_args = ["kubectl", "get", resource, "-A", "-o", "json"]
        if resource in {"nodes", "persistentvolumes", "storageclasses.storage.k8s.io", "volumesnapshotclasses.snapshot.storage.k8s.io", "volumesnapshotcontents.snapshot.storage.k8s.io", "clusterroles.rbac.authorization.k8s.io", "clusterrolebindings.rbac.authorization.k8s.io", "priorityclasses.scheduling.k8s.io", "clusterpolicies.kyverno.io", "validatingadmissionpolicies.admissionregistration.k8s.io", "validatingadmissionpolicybindings.admissionregistration.k8s.io", "clustervulnerabilityreports.aquasecurity.github.io", "clusterconfigauditreports.aquasecurity.github.io", "clusterrbacassessmentreports.aquasecurity.github.io", "clusterinfraassessmentreports.aquasecurity.github.io", "clustersbomreports.aquasecurity.github.io"}:
            kubectl_args = ["kubectl", "get", resource, "-o", "json"]
        inner = " ".join(shlex.quote(part) for part in kubectl_args)
        remote = _nested_ssh_remote(ssh_key, user, control_plane_ip, inner)
        proc = subprocess.run(["ssh", pve_ssh, remote], text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            warnings.append(f"{resource}: {proc.stderr.strip()}")
            continue
        payload = json.loads(proc.stdout)
        objects.extend(payload.get("items", []))
    control_plane_manifests, control_plane_warnings = collect_pve_control_plane_manifests(objects, pve_ssh, control_plane_ip, ssh_key, user)
    objects.extend(control_plane_manifests)
    warnings.extend(control_plane_warnings)
    objects.extend(collect_pve_auth_logs(objects, pve_ssh, ssh_key, user))
    return ResourceIndex(objects, warnings)

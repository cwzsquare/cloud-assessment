from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .collector import ResourceIndex


DANGEROUS_VERBS = {"*", "bind", "escalate", "impersonate"}
DANGEROUS_RESOURCES = {"*", "secrets", "pods/exec", "pods/attach", "pods/portforward", "roles", "clusterroles", "rolebindings", "clusterrolebindings"}
SYSTEM_NAMESPACES = {"kube-system", "kyverno", "trivy-system", "calico-system", "tigera-operator"}
BROAD_SUBJECTS = {"Group:system:authenticated", "Group:system:unauthenticated", "User:system:anonymous"}
EXPIRY_ANNOTATION_TOKENS = ("expires", "expiry", "expire-at", "ttl")
REQUIRED_MATRIX_RESOURCES = ("pods", "services", "configmaps", "secrets", "ingresses", "namespaces")


def _name(obj: dict[str, Any]) -> str:
    return obj.get("metadata", {}).get("name", "unknown")


def _namespace(obj: dict[str, Any]) -> str | None:
    return obj.get("metadata", {}).get("namespace")


def _role_key(kind: str, name: str, namespace: str | None) -> tuple[str, str | None, str]:
    return (kind, namespace if kind == "Role" else None, name)


def _subject_key(subject: dict[str, Any]) -> str:
    namespace = subject.get("namespace")
    prefix = f"{subject.get('kind', 'Subject')}:"
    if namespace:
        return f"{prefix}{namespace}/{subject.get('name', 'unknown')}"
    return f"{prefix}{subject.get('name', 'unknown')}"


def _danger_reasons(rule: dict[str, Any]) -> list[str]:
    verbs = set(rule.get("verbs") or [])
    resources = set(rule.get("resources") or [])
    reasons: list[str] = []
    if verbs & DANGEROUS_VERBS:
        reasons.append("dangerous verb")
    if resources & DANGEROUS_RESOURCES:
        reasons.append("dangerous resource")
    if {"get", "list", "watch"} & verbs and resources & {"secrets", "*"}:
        reasons.append("secret read/list/watch")
    interactive_resources = resources & {"pods/exec", "pods/attach", "pods/portforward", "*"}
    if {"create", "update", "patch", "*"} & verbs and interactive_resources:
        if "pods/exec" in interactive_resources or "*" in interactive_resources:
            reasons.append("pods exec")
        if "pods/attach" in interactive_resources or "*" in interactive_resources:
            reasons.append("pods attach")
        if "pods/portforward" in interactive_resources or "*" in interactive_resources:
            reasons.append("pods portforward")
    return reasons


def _annotations(obj: dict[str, Any] | None) -> dict[str, Any]:
    if not obj:
        return {}
    return obj.get("metadata", {}).get("annotations", {}) or {}


def _labels(obj: dict[str, Any] | None) -> dict[str, Any]:
    if not obj:
        return {}
    return obj.get("metadata", {}).get("labels", {}) or {}


def _selector_matches_labels(selector: dict[str, Any], labels: dict[str, Any]) -> bool:
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions", []) or []:
        key = expr.get("key")
        operator = expr.get("operator")
        values = expr.get("values") or []
        present = key in labels
        if operator == "In" and labels.get(key) not in values:
            return False
        if operator == "NotIn" and present and labels.get(key) in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
    return True


def _rule_signature(rule: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(sorted(str(item) for item in rule.get("apiGroups") or [])),
        tuple(sorted(str(item) for item in rule.get("resources") or [])),
        tuple(sorted(str(item) for item in rule.get("verbs") or [])),
        tuple(sorted(str(item) for item in rule.get("resourceNames") or [])),
        tuple(sorted(str(item) for item in rule.get("nonResourceURLs") or [])),
    )


def _parse_expiry_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.removesuffix("Z") + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _expiry_marker_status(*objects: dict[str, Any] | None) -> dict[str, Any]:
    for obj in objects:
        for key, value in _annotations(obj).items():
            haystack = f"{key}={value}".lower()
            if any(token in haystack for token in EXPIRY_ANNOTATION_TOKENS):
                parsed = _parse_expiry_datetime(value)
                if parsed:
                    expired = parsed <= datetime.now(timezone.utc)
                    return {
                        "status": "expired" if expired else "valid",
                        "key": key,
                        "value": value,
                        "expires_at": parsed.isoformat(),
                    }
                if "ttl" in key.lower() and re.fullmatch(r"\d+[smhdw]", str(value).strip().lower()):
                    return {"status": "unvalidated_ttl", "key": key, "value": value, "expires_at": None}
                return {"status": "invalid", "key": key, "value": value, "expires_at": None}
    return {"status": "missing", "key": None, "value": None, "expires_at": None}


def _effective_expiry_marker(binding_marker: dict[str, Any], role_marker: dict[str, Any]) -> dict[str, Any]:
    if binding_marker.get("status") == "valid":
        return {**binding_marker, "source": "binding"}
    if binding_marker.get("status") == "missing" and role_marker.get("status") == "valid":
        return {**role_marker, "source": "role"}
    return {**binding_marker, "source": "binding"}


def _is_system_managed_row(subject: str, subject_namespace: str | None, binding: dict[str, Any], role: dict[str, Any]) -> bool:
    if subject in BROAD_SUBJECTS:
        return False
    role_name = _name(role)
    binding_name = _name(binding)
    binding_namespace = _namespace(binding)
    if subject.startswith("User:system:") or subject.startswith("Group:system:masters") or subject.startswith("Group:system:bootstrappers"):
        return True
    if subject.startswith("ServiceAccount:"):
        namespace = subject_namespace or subject.split(":", 1)[1].split("/", 1)[0]
        if namespace in SYSTEM_NAMESPACES:
            return True
    if role_name.startswith(("system:", "kubeadm:")) or binding_name.startswith(("system:", "kubeadm:")):
        return True
    if binding_namespace in SYSTEM_NAMESPACES and role_name.startswith(("kyverno:", "trivy-", "calico-")):
        return True
    return False


def _risk_level(subject: str, role: dict[str, Any], reasons: list[str], system_managed: bool) -> str:
    if not reasons:
        return "none"
    if system_managed:
        return "system-required"
    if subject in BROAD_SUBJECTS:
        return "critical"
    role_name = _name(role)
    if role_name in {"cluster-admin", "admin", "edit"}:
        return "critical"
    if "dangerous verb" in reasons or "pods exec" in reasons or "secret read/list/watch" in reasons:
        return "high"
    return "medium"


def _requires_expiry(risk_level: str) -> bool:
    return risk_level in {"critical", "high"}


def _expanded_role_rules(role: dict[str, Any], cluster_roles: list[dict[str, Any]]) -> tuple[list[tuple[dict[str, Any], str | None]], list[str]]:
    rules: list[tuple[dict[str, Any], str | None]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = set()
    for rule in role.get("rules", []) or []:
        signature = _rule_signature(rule)
        if signature not in seen:
            rules.append((rule, None))
            seen.add(signature)
    if role.get("kind") != "ClusterRole":
        return rules, []

    selectors = role.get("aggregationRule", {}).get("clusterRoleSelectors", []) or []
    if not selectors:
        return rules, []

    sources: list[str] = []
    role_name = _name(role)
    for source in cluster_roles:
        source_name = _name(source)
        if source_name == role_name:
            continue
        source_labels = _labels(source)
        if not any(_selector_matches_labels(selector, source_labels) for selector in selectors):
            continue
        sources.append(source_name)
        for rule in source.get("rules", []) or []:
            signature = _rule_signature(rule)
            if signature in seen:
                continue
            rules.append((rule, source_name))
            seen.add(signature)
    return rules, sorted(sources)


def _covered_required_resources(resources: list[str]) -> set[str]:
    covered: set[str] = set()
    for resource in resources:
        normalized = str(resource).lower()
        if normalized == "*":
            covered.update(REQUIRED_MATRIX_RESOURCES)
            continue
        base = normalized.split("/", 1)[0]
        if base in REQUIRED_MATRIX_RESOURCES:
            covered.add(base)
        if base == "ingress":
            covered.add("ingresses")
    return covered


def _required_resource_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_resource: dict[str, dict[str, Any]] = {
        resource: {"row_count": 0, "subjects": set(), "verbs": set(), "scopes": set()}
        for resource in REQUIRED_MATRIX_RESOURCES
    }
    for row in rows:
        for resource in _covered_required_resources(row.get("resources") or []):
            entry = by_resource[resource]
            entry["row_count"] += 1
            entry["subjects"].add(row.get("subject"))
            entry["verbs"].update(row.get("verbs") or [])
            entry["scopes"].add(row.get("scope"))
    resources: dict[str, dict[str, Any]] = {}
    for resource, entry in by_resource.items():
        resources[resource] = {
            "covered": entry["row_count"] > 0,
            "row_count": entry["row_count"],
            "subject_count": len({item for item in entry["subjects"] if item}),
            "subjects_sample": sorted(item for item in entry["subjects"] if item)[:10],
            "verbs": sorted(item for item in entry["verbs"] if item)[:20],
            "scopes": sorted(item for item in entry["scopes"] if item)[:20],
        }
    missing = [resource for resource, entry in resources.items() if not entry["covered"]]
    return {
        "required_resources": list(REQUIRED_MATRIX_RESOURCES),
        "covered_resources": [resource for resource in REQUIRED_MATRIX_RESOURCES if resource not in missing],
        "missing_resources": missing,
        "coverage_percent": round((len(REQUIRED_MATRIX_RESOURCES) - len(missing)) / len(REQUIRED_MATRIX_RESOURCES) * 100, 2),
        "resources": resources,
    }


def build_rbac_matrix(index: ResourceIndex) -> dict[str, Any]:
    roles: dict[tuple[str, str | None, str], dict[str, Any]] = {}
    cluster_roles = index.by_kind("ClusterRole")
    for role in index.by_kind("Role") + index.by_kind("ClusterRole"):
        roles[_role_key(role.get("kind", "Role"), _name(role), _namespace(role))] = role
    expanded_roles = {
        role_key: _expanded_role_rules(role, cluster_roles)
        for role_key, role in roles.items()
    }

    rows: list[dict[str, Any]] = []
    unresolved_bindings: list[dict[str, Any]] = []
    for binding in index.by_kind("RoleBinding") + index.by_kind("ClusterRoleBinding"):
        binding_kind = binding.get("kind", "Binding")
        binding_namespace = _namespace(binding)
        role_ref = binding.get("roleRef", {}) or {}
        role_kind = role_ref.get("kind", "Role")
        role_name = role_ref.get("name", "unknown")
        role = roles.get(_role_key(role_kind, role_name, binding_namespace))
        if not role:
            unresolved_bindings.append(
                {
                    "binding_kind": binding_kind,
                    "binding_namespace": binding_namespace,
                    "binding_name": _name(binding),
                    "role_kind": role_kind,
                    "role_name": role_name,
                }
            )
            continue
        for subject in binding.get("subjects", []) or []:
            subject_key = _subject_key(subject)
            expanded_rules, aggregation_sources = expanded_roles.get(_role_key(role_kind, role_name, binding_namespace), ([], []))
            for rule, aggregation_source_role in expanded_rules:
                reasons = _danger_reasons(rule)
                system_managed = _is_system_managed_row(subject_key, subject.get("namespace"), binding, role)
                risk_level = _risk_level(subject_key, role, reasons, system_managed)
                expiry_marker = _expiry_marker_status(binding)
                role_expiry_marker = _expiry_marker_status(role)
                effective_expiry_marker = _effective_expiry_marker(expiry_marker, role_expiry_marker)
                rows.append(
                    {
                        "subject": subject_key,
                        "subject_kind": subject.get("kind", "Subject"),
                        "subject_name": subject.get("name", "unknown"),
                        "subject_namespace": subject.get("namespace"),
                        "binding_kind": binding_kind,
                        "binding_namespace": binding_namespace,
                        "binding_name": _name(binding),
                        "role_kind": role_kind,
                        "role_name": role_name,
                        "role_namespace": _namespace(role),
                        "scope": "cluster" if binding_kind == "ClusterRoleBinding" or role_kind == "ClusterRole" else (binding_namespace or "default"),
                        "api_groups": rule.get("apiGroups") or [""],
                        "resources": rule.get("resources") or [],
                        "verbs": rule.get("verbs") or [],
                        "resource_names": rule.get("resourceNames") or [],
                        "aggregation_source_role": aggregation_source_role,
                        "role_aggregation_sources": aggregation_sources,
                        "dangerous": bool(reasons),
                        "danger_reasons": reasons,
                        "system_managed": system_managed,
                        "risk_level": risk_level,
                        "requires_expiry": _requires_expiry(risk_level),
                        "has_expiry_marker": effective_expiry_marker["status"] == "valid",
                        "expiry_marker": expiry_marker,
                        "role_expiry_marker": role_expiry_marker,
                        "effective_expiry_marker": effective_expiry_marker,
                    }
                )

    subjects = sorted({row["subject"] for row in rows})
    role_refs = sorted({f"{row['role_kind']}/{row['role_name']}" for row in rows})
    dangerous_rows = [row for row in rows if row["dangerous"]]
    business_dangerous_rows = [row for row in dangerous_rows if not row["system_managed"]]
    system_dangerous_rows = [row for row in dangerous_rows if row["system_managed"]]
    expiry_missing_rows = [row for row in business_dangerous_rows if row["requires_expiry"] and row.get("effective_expiry_marker", {}).get("status") != "valid"]
    resource_coverage = _required_resource_coverage(rows)
    aggregated_roles = {
        _name(role): {"source_roles": sources, "expanded_rule_count": len(rules)}
        for role_key, role in roles.items()
        for rules, sources in [expanded_roles.get(role_key, ([], []))]
        if role.get("kind") == "ClusterRole" and sources
    }
    return {
        "schema_version": "rbac-matrix/v1",
        "summary": {
            "role_count": len(roles),
            "binding_count": len(index.by_kind("RoleBinding")) + len(index.by_kind("ClusterRoleBinding")),
            "subject_count": len(subjects),
            "matrix_row_count": len(rows),
            "dangerous_row_count": len(dangerous_rows),
            "business_dangerous_row_count": len(business_dangerous_rows),
            "system_dangerous_row_count": len(system_dangerous_rows),
            "expiry_missing_row_count": len(expiry_missing_rows),
            "unresolved_binding_count": len(unresolved_bindings),
            "aggregated_cluster_role_count": len(aggregated_roles),
            "aggregated_rule_row_count": sum(1 for row in rows if row.get("aggregation_source_role")),
            "required_resource_coverage_percent": resource_coverage["coverage_percent"],
            "required_resource_missing_count": len(resource_coverage["missing_resources"]),
        },
        "aggregated_cluster_roles": aggregated_roles,
        "required_resource_coverage": resource_coverage,
        "subjects": subjects,
        "roles": role_refs,
        "rows": rows,
        "dangerous_rows": dangerous_rows[:200],
        "business_dangerous_rows": business_dangerous_rows[:200],
        "system_dangerous_rows": system_dangerous_rows[:200],
        "expiry_missing_rows": expiry_missing_rows[:200],
        "unresolved_bindings": unresolved_bindings,
    }

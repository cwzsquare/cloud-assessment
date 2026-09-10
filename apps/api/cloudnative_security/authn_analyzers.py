"""Pure analyzers for Kubernetes authentication and identity evidence.

Inputs are ordinary argument/config dictionaries (or argv-like lists) and RBAC-like
rows.  Functions do not perform I/O, and output profiles never retain credential
material.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import urlparse

from .authn_profile import (
    UNKNOWN,
    AuthenticationProfile,
    FrontProxyAuthenticationProfile,
    IdentityProfile,
    ServiceAccountTokenProfile,
    StructuredAuthenticationConfig,
)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "on", "enabled"}:
        return True
    if text in {"false", "0", "no", "off", "disabled"}:
        return False
    return None


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _https(value: Any) -> bool | None:
    if value is None or str(value).strip() == "":
        return None
    return urlparse(str(value).strip()).scheme.lower() == "https"


def _flag_name(value: Any) -> str:
    return str(value).strip().lstrip("-").replace("_", "-")


def _flags(arguments: Any) -> dict[str, Any]:
    """Normalize argv, a flags mapping, or a pod/container command mapping."""
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        for nested in ("args", "command", "flags", "arguments"):
            if nested in arguments and isinstance(arguments[nested], (dict, list, tuple)):
                result = _flags(arguments[nested])
                # Keep direct keys as the more specific value.
                result.update({_flag_name(k): v for k, v in arguments.items() if k not in {"args", "command", "flags", "arguments"}})
                return result
        result: dict[str, Any] = {}
        for key, value in arguments.items():
            normalized = _flag_name(key)
            if normalized in {"name", "image", "kind", "metadata", "spec"} and not str(key).startswith("-"):
                continue
            result[normalized] = value
        return result
    if isinstance(arguments, (list, tuple)):
        result = {}
        index = 0
        while index < len(arguments):
            item = str(arguments[index])
            if not item.startswith("-"):
                index += 1
                continue
            raw = item.lstrip("-")
            if "=" in raw:
                key, value = raw.split("=", 1)
                result[_flag_name(key)] = value
            else:
                key = _flag_name(raw)
                if index + 1 < len(arguments) and not str(arguments[index + 1]).startswith("-"):
                    result[key] = arguments[index + 1]
                    index += 1
                else:
                    result[key] = True
            index += 1
        return result
    return {}


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        normalized = _flag_name(key)
        if normalized in mapping:
            return mapping[normalized]
    return None


def _deep_first(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if _flag_name(key) in keys and item not in (None, "", [], {}):
                return item
        for item in value.values():
            found = _deep_first(item, keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _deep_first(item, keys)
            if found is not None:
                return found
    return None


def _subject_text(subject: Any) -> str | None:
    if isinstance(subject, str):
        return subject
    if not isinstance(subject, dict):
        return None
    kind = str(subject.get("kind") or "").strip()
    name = str(subject.get("name") or "").strip()
    namespace = str(subject.get("namespace") or "").strip()
    if not name:
        return None
    if kind.lower() in {"serviceaccount", "service-account", "sa"}:
        return f"system:serviceaccount:{namespace or 'default'}:{name}"
    return f"{kind}:{name}" if kind else name


def _row_subjects(row: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    if "subject" in row:
        values.append(row["subject"])
    values.extend(row.get("subjects") or [])
    # Matrix rows commonly use subject/name/kind as separate columns.
    if not values and row.get("subject_name") is not None:
        values.append({"kind": row.get("subject_kind"), "name": row.get("subject_name"), "namespace": row.get("namespace")})
    output = [_subject_text(value) for value in values]
    return sorted({value for value in output if value})


def _row_permissions(row: dict[str, Any]) -> list[dict[str, Any]]:
    rules = row.get("rules")
    if isinstance(rules, dict):
        rules = [rules]
    if isinstance(rules, list):
        return [dict(rule, binding=row.get("binding") or row.get("binding_name"), role=row.get("role") or row.get("role_name")) for rule in rules if isinstance(rule, dict)]
    if any(key in row for key in ("verb", "verbs", "resource", "resources", "apiGroups", "api_groups")):
        return [{key: row[key] for key in ("verb", "verbs", "resource", "resources", "apiGroups", "api_groups", "namespace", "scope") if key in row}]
    permission = row.get("permission")
    return [permission] if isinstance(permission, dict) else []


def _permission_broad(permission: dict[str, Any]) -> bool:
    def values(*keys: str) -> set[str]:
        result: set[str] = set()
        for key in keys:
            value = permission.get(key)
            if isinstance(value, (list, tuple, set)):
                result.update(str(item).lower() for item in value)
            elif value is not None:
                result.add(str(value).lower())
        return result
    verbs = values("verb", "verbs")
    resources = values("resource", "resources")
    return "*" in verbs or "*" in resources or ("secrets" in resources and bool(verbs & {"list", "watch", "get", "update", "patch", "*"}))


def _permission_key(permission: dict[str, Any]) -> tuple[str, ...]:
    def norm(key: str) -> list[str]:
        value = permission.get(key)
        if isinstance(value, (list, tuple, set)):
            return sorted(str(item).lower() for item in value)
        return [str(value).lower()] if value is not None else []
    return tuple(norm("verb") + norm("verbs") + norm("resource") + norm("resources"))


def classify_anonymous_authorization(anonymous_auth: bool | None, rbac_rows: Iterable[dict[str, Any]] | None) -> str:
    """Classify anonymous access using both apiserver auth and authorization evidence."""
    if anonymous_auth is False:
        return "disabled"
    if anonymous_auth is None:
        return UNKNOWN
    if rbac_rows is None:
        return UNKNOWN
    matched = False
    broad = False
    for row in rbac_rows:
        subjects = {subject.lower() for subject in _row_subjects(row)}
        if not subjects.intersection({"user:system:anonymous", "user:system:unauthenticated", "system:anonymous", "system:unauthenticated", "group:system:unauthenticated", "group:system:authenticated"}):
            continue
        matched = True
        permissions = _row_permissions(row)
        broad = broad or not permissions or any(_permission_broad(permission) for permission in permissions)
    if not matched:
        return "enabled_restricted"
    return "enabled_broadly_authorized" if broad else "enabled_authorized"


def analyze_anonymous_auth(arguments: Any, rbac_rows: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    flags = _flags(arguments)
    raw = _first(flags, "anonymous-auth", "anonymous_auth")
    enabled = _bool(raw)
    classification = classify_anonymous_authorization(enabled, rbac_rows)
    return {
        "anonymous_auth": enabled,
        "anonymous_auth_source": "argument" if raw is not None else None,
        "anonymous_authorization": classification,
        "anonymous_authorization_status": "UNKNOWN" if classification == UNKNOWN else ("PASS" if classification in {"disabled", "enabled_restricted"} else "FAIL"),
    }


def _oidc_config(arguments: Any, config: Any = None) -> StructuredAuthenticationConfig:
    flags = _flags(arguments)
    issuer = _first(flags, "oidc-issuer-url", "oidc-issuer", "issuer-url")
    client_id = _first(flags, "oidc-client-id", "client-id")
    username = _first(flags, "oidc-username-claim", "username-claim")
    groups = _first(flags, "oidc-groups-claim", "groups-claim")
    ca_file = _first(flags, "oidc-ca-file", "oidc-ca")
    if config is not None:
        issuer = issuer or _deep_first(config, {"issuer", "issuer-url", "issuer-url"})
        client_id = client_id or _deep_first(config, {"client-id", "client_id"})
        username = username or _deep_first(config, {"username-claim", "username_claim"})
        groups = groups or _deep_first(config, {"groups-claim", "groups_claim"})
        ca_file = ca_file or _deep_first(config, {"certificate-authority", "ca-file", "ca"})
    present = any(value not in (None, "") for value in (issuer, client_id, username, groups, ca_file)) or config is not None
    issuer_https = _https(issuer)
    claims_ok = bool(str(username or "").strip()) and bool(str(groups or "").strip())
    checks = []
    if present and issuer is None:
        checks.append("issuer missing")
    if issuer is not None and issuer_https is False:
        checks.append("issuer must use HTTPS")
    if not client_id:
        checks.append("client id missing")
    if not claims_ok:
        checks.append("username and groups claims should be configured")
    status = UNKNOWN if not present else ("PASS" if not checks else "FAIL")
    return StructuredAuthenticationConfig(
        present=present,
        source="arguments" if any(value is not None for value in flags.values()) else ("config" if config is not None else None),
        api_version=config.get("apiVersion") if isinstance(config, dict) else None,
        issuer_url=str(issuer) if issuer is not None else None,
        client_id_present=client_id not in (None, ""),
        username_claim=str(username) if username else None,
        groups_claim=str(groups) if groups else None,
        issuer_https=issuer_https,
        claims_configured=claims_ok if present else None,
        ca_file_present=ca_file not in (None, "") if present else None,
        status=status,
        reasons=checks,
    )


def analyze_oidc_authentication(arguments: Any = None, config: Any = None) -> StructuredAuthenticationConfig:
    return _oidc_config(arguments, config)


analyze_oidc = analyze_oidc_authentication


def analyze_webhook_authentication(arguments: Any = None, config: Any = None) -> StructuredAuthenticationConfig:
    flags = _flags(arguments)
    endpoint = _first(flags, "authentication-token-webhook-endpoint", "webhook-endpoint", "endpoint", "url")
    ca_file = _first(flags, "authentication-token-webhook-ca-file", "webhook-ca-file", "ca-file", "ca")
    if config is not None:
        endpoint = endpoint or _deep_first(config, {"endpoint", "url", "server"})
        ca_file = ca_file or _deep_first(config, {"certificate-authority", "ca-file", "ca"})
    path = _first(flags, "authentication-token-webhook-config-file", "webhook-config-file")
    present = path not in (None, "") or endpoint not in (None, "") or config is not None
    endpoint_https = _https(endpoint)
    reasons: list[str] = []
    if present and endpoint is None and path in (None, ""):
        reasons.append("webhook endpoint/config missing")
    if endpoint is not None and endpoint_https is False:
        reasons.append("webhook endpoint must use HTTPS")
    if present and ca_file in (None, ""):
        reasons.append("webhook CA evidence missing")
    status = UNKNOWN if not present else ("PASS" if not reasons else "FAIL")
    return StructuredAuthenticationConfig(
        present=present,
        source="arguments" if flags else ("config" if config is not None else None),
        api_version=config.get("apiVersion") if isinstance(config, dict) else None,
        endpoint=str(endpoint) if endpoint is not None else None,
        endpoint_https=endpoint_https,
        ca_file_present=ca_file not in (None, "") if present else None,
        transport_secure=(endpoint_https is True and ca_file not in (None, "")) if present else None,
        status=status,
        reasons=reasons,
    )


analyze_webhook = analyze_webhook_authentication


def analyze_front_proxy_authentication(arguments: Any = None, config: Any = None) -> FrontProxyAuthenticationProfile:
    flags = _flags(arguments)
    ca = _first(flags, "requestheader-client-ca-file", "client-ca-file", "requestheader-client-ca")
    username = _first(flags, "requestheader-username-headers", "username-headers")
    groups = _first(flags, "requestheader-group-headers", "group-headers")
    allowed = _first(flags, "requestheader-allowed-names", "allowed-names")
    endpoint = _first(flags, "front-proxy-endpoint", "requestheader-endpoint", "endpoint", "url")
    if config is not None:
        ca = ca or _deep_first(config, {"client-ca-file", "client-ca", "certificate-authority", "ca-file"})
        username = username or _deep_first(config, {"username-headers", "username_headers"})
        groups = groups or _deep_first(config, {"group-headers", "group_headers"})
        allowed = allowed or _deep_first(config, {"allowed-names", "allowed_names"})
        endpoint = endpoint or _deep_first(config, {"endpoint", "url"})
    split = lambda value: [part.strip() for part in (str(value).split(",") if value is not None else []) if part.strip()]
    usernames = split(username) if not isinstance(username, list) else [str(item) for item in username]
    group_names = split(groups) if not isinstance(groups, list) else [str(item) for item in groups]
    allowed_names = split(allowed) if not isinstance(allowed, list) else [str(item) for item in allowed]
    present = any(value not in (None, "", []) for value in (ca, username, groups, allowed, endpoint)) or config is not None
    endpoint_https = _https(endpoint)
    enabled = True if present else None
    reasons: list[str] = []
    if present and ca in (None, ""):
        reasons.append("front-proxy client CA evidence missing")
    if present and not usernames:
        reasons.append("front-proxy username header missing")
    if endpoint is not None and endpoint_https is False:
        reasons.append("front-proxy endpoint must use HTTPS")
    secure = (ca not in (None, "") and bool(usernames) and (endpoint is None or endpoint_https is True)) if present else None
    status = UNKNOWN if not present else ("PASS" if secure else "FAIL")
    return FrontProxyAuthenticationProfile(
        enabled=enabled,
        client_ca_file_present=ca not in (None, "") if present else None,
        client_ca_file=str(ca) if ca not in (None, "") else None,
        username_headers=usernames,
        group_headers=group_names,
        allowed_names=allowed_names,
        endpoint=str(endpoint) if endpoint is not None else None,
        endpoint_https=endpoint_https,
        transport_secure=secure,
        status=status,
        reasons=reasons,
    )


analyze_front_proxy = analyze_front_proxy_authentication


def _contains_key(value: Any, wanted: set[str]) -> bool:
    if isinstance(value, dict):
        if any(_flag_name(key) in wanted for key in value):
            return True
        return any(_contains_key(item, wanted) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, wanted) for item in value)
    return False


def _has_oidc_config(value: Any) -> bool:
    return _contains_key(value, {"oidc", "oidc-issuer-url", "issuer", "issuer-url", "jwt", "client-id"})


def _has_webhook_config(value: Any) -> bool:
    return _contains_key(value, {"webhook", "webhook-config", "authentication-token-webhook", "authentication-token-webhook-config-file", "token-review"})


def _has_front_proxy_config(value: Any) -> bool:
    return _contains_key(value, {"front-proxy", "requestheader", "requestheader-client-ca-file", "client-ca-file", "allowed-names"})


def analyze_authentication_profile(arguments: Any = None, authentication_config: Any = None, rbac_rows: Iterable[dict[str, Any]] | None = None) -> AuthenticationProfile:
    anonymous = analyze_anonymous_auth(arguments, rbac_rows)
    oidc_config = authentication_config if _has_oidc_config(authentication_config) else None
    oidc = analyze_oidc_authentication(arguments, oidc_config)
    webhook_config = authentication_config if _has_webhook_config(authentication_config) else None
    front_proxy_config = authentication_config if _has_front_proxy_config(authentication_config) else None
    webhook = analyze_webhook_authentication(arguments, webhook_config)
    front_proxy = analyze_front_proxy_authentication(arguments, front_proxy_config)
    present = arguments is not None or authentication_config is not None or rbac_rows is not None
    reasons: list[str] = []
    if anonymous["anonymous_auth"] is None:
        reasons.append("anonymous-auth evidence missing")
    statuses = [oidc.status, webhook.status, front_proxy.status]
    status = UNKNOWN if not present else ("FAIL" if "FAIL" in statuses or anonymous["anonymous_authorization_status"] == "FAIL" else "PASS" if any(item == "PASS" for item in statuses) or anonymous["anonymous_authorization_status"] == "PASS" else UNKNOWN)
    return AuthenticationProfile(
        anonymous_auth=anonymous["anonymous_auth"],
        anonymous_auth_source=anonymous["anonymous_auth_source"],
        anonymous_authorization=anonymous["anonymous_authorization"],
        anonymous_authorization_status=anonymous["anonymous_authorization_status"],
        oidc=oidc,
        webhook=webhook,
        front_proxy=front_proxy,
        evidence_present=present,
        status=status,
        reasons=reasons,
    )


analyze_authn_profile = analyze_authentication_profile



def _pod_spec(workload: dict[str, Any]) -> dict[str, Any]:
    kind = str(workload.get("kind") or "")
    if kind in {"Pod", "pod"}:
        return workload.get("spec", {}) or {}
    return workload.get("spec", {}).get("template", {}).get("spec", {}) or {}


def _workload_name(workload: dict[str, Any]) -> str | None:
    metadata = workload.get("metadata", {}) or {}
    return metadata.get("name") or workload.get("name")


def _workload_namespace(workload: dict[str, Any]) -> str | None:
    metadata = workload.get("metadata", {}) or {}
    return metadata.get("namespace") or workload.get("namespace")


def _find_service_account(service_accounts: Any, namespace: str | None, name: str) -> dict[str, Any] | None:
    if isinstance(service_accounts, dict):
        candidates = service_accounts.values()
    else:
        candidates = service_accounts or []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata", {}) or {}
        if (metadata.get("namespace") or item.get("namespace") or "default") == (namespace or "default") and (metadata.get("name") or item.get("name")) == name:
            return item
    return None


def _projected_token(spec: dict[str, Any]) -> tuple[bool | None, int | None, str | None]:
    found = False
    expiration: int | None = None
    audience: str | None = None
    for volume in spec.get("volumes", []) or []:
        projection = volume.get("projected", {}) if isinstance(volume, dict) else {}
        for source in projection.get("sources", []) or []:
            token = source.get("serviceAccountToken") if isinstance(source, dict) else None
            if not isinstance(token, dict):
                continue
            found = True
            expiration = _int(token.get("expirationSeconds"))
            audience = token.get("audience")
    return (found, expiration, audience) if found else (None, None, None)


def _sa_permissions(namespace: str | None, name: str, rows: Iterable[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], bool]:
    if rows is None:
        return [], False
    wanted = f"system:serviceaccount:{namespace or 'default'}:{name}".lower()
    output: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or wanted not in {subject.lower() for subject in _row_subjects(row)}:
            continue
        output.extend(_row_permissions(row))
    return output, True


def analyze_service_account_token_profile(workload: dict[str, Any], service_accounts: Any = None, rbac_rows: Iterable[dict[str, Any]] | None = None, expected_audience: str | None = None) -> ServiceAccountTokenProfile:
    spec = _pod_spec(workload)
    namespace = _workload_namespace(workload)
    sa_name = str(spec.get("serviceAccountName") or "default")
    sa = _find_service_account(service_accounts, namespace, sa_name)
    pod_auto = _bool(spec.get("automountServiceAccountToken"))
    sa_auto = _bool(sa.get("automountServiceAccountToken")) if sa is not None else None
    if pod_auto is not None:
        effective, source = pod_auto, "pod"
    elif sa_auto is not None:
        effective, source = sa_auto, "service-account"
    elif workload:
        # Kubernetes defaults this field to true; retain the source explicitly.
        effective, source = True, "kubernetes-default"
    else:
        effective, source = None, None
    projected, expiration, audience = _projected_token(spec)
    token_used = projected is True or effective is True
    expiration_ok = None if projected is not True else expiration is not None and 600 <= expiration <= 86400
    audience_ok = None if projected is not True else bool(audience) and (expected_audience is None or audience == expected_audience)
    permissions, permission_evidence = _sa_permissions(namespace, sa_name, rbac_rows)
    if not token_used:
        alignment = "not_required"
    elif not permission_evidence:
        alignment = UNKNOWN
    elif permissions:
        alignment = "aligned"
    else:
        alignment = "no_api_permission"
    reasons: list[str] = []
    if effective is True and projected is not True:
        reasons.append("service-account token automount is enabled without projected-token evidence")
    if expiration_ok is False:
        reasons.append("projected token expiration must be between 600 and 86400 seconds")
    if audience_ok is False:
        reasons.append("projected token audience is missing or does not match the expected API audience")
    if alignment == "no_api_permission":
        reasons.append("token is available but no matching API permission evidence was found")
    if not workload:
        status = UNKNOWN
    elif any(value is False for value in (expiration_ok, audience_ok)):
        status = "FAIL"
    elif alignment == "no_api_permission":
        status = "WARN"
    elif effective is False or (projected is True and expiration_ok is True and audience_ok is True):
        status = "PASS"
    elif effective is None:
        status = UNKNOWN
    else:
        status = "WARN"
    return ServiceAccountTokenProfile(
        namespace=namespace,
        workload=_workload_name(workload),
        service_account=sa_name,
        pod_automount=pod_auto,
        service_account_automount=sa_auto,
        effective_automount=effective,
        automount_source=source,
        projected_token=projected,
        expiration_seconds=expiration,
        audience=str(audience) if audience is not None else None,
        expiration_ok=expiration_ok,
        audience_ok=audience_ok,
        api_permission_alignment=alignment,
        api_permissions=permissions,
        status=status,
        reasons=reasons,
    )


def analyze_service_account_tokens(workloads: Iterable[dict[str, Any]], service_accounts: Any = None, rbac_rows: Iterable[dict[str, Any]] | None = None, expected_audience: str | None = None) -> list[ServiceAccountTokenProfile]:
    return [analyze_service_account_token_profile(workload, service_accounts, rbac_rows, expected_audience) for workload in workloads]


analyze_service_account_token = analyze_service_account_token_profile


def analyze_identity_profiles(rbac_rows: Iterable[dict[str, Any]] | None) -> list[IdentityProfile]:
    if rbac_rows is None:
        return []
    aggregate: dict[str, IdentityProfile] = {}
    for row in rbac_rows:
        if not isinstance(row, dict):
            continue
        subjects = _row_subjects(row)
        permissions = _row_permissions(row)
        if not subjects:
            continue
        for subject in subjects:
            profile = aggregate.get(subject)
            kind = "ServiceAccount" if subject.startswith("system:serviceaccount:") else ("User" if subject.startswith("user:") else "Group")
            namespace = subject.split(":")[2] if subject.startswith("system:serviceaccount:") and len(subject.split(":")) > 2 else None
            if profile is None:
                profile = IdentityProfile(subject=subject, subject_kind=kind, namespace=namespace, dangerous=False, broad=False, system_managed=subject.startswith("system:"), expiry_present=False)
                aggregate[subject] = profile
            binding = row.get("binding") or row.get("binding_name") or row.get("roleBinding")
            role = row.get("role") or row.get("role_name")
            if binding and str(binding) not in profile.bindings:
                profile.bindings.append(str(binding))
            if role and str(role) not in profile.roles:
                profile.roles.append(str(role))
            for permission in permissions:
                if permission not in profile.permissions:
                    profile.permissions.append(permission)
            profile.broad = bool(profile.broad or any(_permission_broad(permission) for permission in permissions))
            dangerous_verbs = {"bind", "escalate", "impersonate"}
            dangerous_in_row = False
            for permission in permissions:
                values = permission.get("verbs") or permission.get("verb") or []
                if isinstance(values, str):
                    values = [values]
                if any(str(value).lower() in dangerous_verbs for value in values):
                    dangerous_in_row = True
                    break
            profile.dangerous = bool(profile.dangerous or profile.broad or dangerous_in_row)
            profile.expiry_present = bool(profile.expiry_present or any("expir" in str(key).lower() or "ttl" in str(key).lower() for key in row))
    for profile in aggregate.values():
        profile.status = "FAIL" if profile.dangerous else "PASS" if profile.permissions else UNKNOWN
        profile.bindings.sort()
        profile.roles.sort()
        profile.permissions.sort(key=lambda item: _permission_key(item))
    return [aggregate[key] for key in sorted(aggregate)]


analyze_identities = analyze_identity_profiles


__all__ = [
    "classify_anonymous_authorization",
    "analyze_anonymous_auth",
    "analyze_oidc_authentication",
    "analyze_oidc",
    "analyze_webhook_authentication",
    "analyze_webhook",
    "analyze_front_proxy_authentication",
    "analyze_front_proxy",
    "analyze_authentication_profile",
    "analyze_authn_profile",
    "analyze_service_account_token_profile",
    "analyze_service_account_token",
    "analyze_service_account_tokens",
    "analyze_identity_profiles",
    "analyze_identities",
]

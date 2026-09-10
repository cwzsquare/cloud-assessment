"""Data profiles for Kubernetes authentication and identity posture.

The profiles deliberately contain configuration *metadata* rather than secrets.  Values
such as token strings, bearer credentials, private keys, and certificate contents are
never represented; file names and presence booleans are safe evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


UNKNOWN = "UNKNOWN"


def _safe(value: Any) -> Any:
    """Return a JSON-friendly redacted value for profile metadata."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        # Do not accidentally serialize a credential if a caller passes raw config.
        blocked = ("token", "secret", "password", "private_key", "private-key", "client_secret", "key_data")
        return {str(key): ("<redacted>" if any(part in str(key).lower() for part in blocked) else _safe(item)) for key, item in value.items()}
    return str(value)


@dataclass
class AuthenticationProfile:
    """Authentication posture observed from kube-apiserver arguments/config."""

    anonymous_auth: bool | None = None
    anonymous_auth_source: str | None = None
    anonymous_authorization: str = UNKNOWN
    anonymous_authorization_status: str = UNKNOWN
    oidc: "StructuredAuthenticationConfig | None" = None
    webhook: "StructuredAuthenticationConfig | None" = None
    front_proxy: "FrontProxyAuthenticationProfile | None" = None
    evidence_present: bool = False
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    @property
    def anonymous_enabled(self) -> bool | None:
        return self.anonymous_auth

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass
class ServiceAccountTokenProfile:
    """Effective service-account token posture for one workload."""

    namespace: str | None = None
    workload: str | None = None
    service_account: str | None = None
    pod_automount: bool | None = None
    service_account_automount: bool | None = None
    effective_automount: bool | None = None
    automount_source: str | None = None
    projected_token: bool | None = None
    expiration_seconds: int | None = None
    audience: str | None = None
    expiration_ok: bool | None = None
    audience_ok: bool | None = None
    api_permission_alignment: str = UNKNOWN
    api_permissions: list[dict[str, Any]] = field(default_factory=list)
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    # Common spelling used by Kubernetes documentation and consumers.
    @property
    def effective_automount_service_account_token(self) -> bool | None:
        return self.effective_automount

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass
class IdentityProfile:
    """Aggregated identity/RBAC posture for one subject."""

    subject: str
    subject_kind: str | None = None
    namespace: str | None = None
    bindings: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    permissions: list[dict[str, Any]] = field(default_factory=list)
    dangerous: bool | None = None
    broad: bool | None = None
    system_managed: bool | None = None
    expiry_present: bool | None = None
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.subject

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass
class StructuredAuthenticationConfig:
    """Redacted summary of a structured authentication configuration file."""

    present: bool = False
    source: str | None = None
    api_version: str | None = None
    issuer_url: str | None = None
    client_id_present: bool | None = None
    username_claim: str | None = None
    groups_claim: str | None = None
    issuer_https: bool | None = None
    claims_configured: bool | None = None
    ca_file_present: bool | None = None
    endpoint: str | None = None
    endpoint_https: bool | None = None
    transport_secure: bool | None = None
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass
class FrontProxyAuthenticationProfile:
    """Front-proxy request-header authentication posture without certificate data."""

    enabled: bool | None = None
    client_ca_file_present: bool | None = None
    client_ca_file: str | None = None
    username_headers: list[str] = field(default_factory=list)
    group_headers: list[str] = field(default_factory=list)
    allowed_names: list[str] = field(default_factory=list)
    endpoint: str | None = None
    endpoint_https: bool | None = None
    transport_secure: bool | None = None
    status: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


# Explicit aliases make profile payloads convenient for API serializers.
AuthnProfile = AuthenticationProfile
SAProfile = ServiceAccountTokenProfile

__all__ = [
    "UNKNOWN",
    "AuthenticationProfile",
    "ServiceAccountTokenProfile",
    "IdentityProfile",
    "StructuredAuthenticationConfig",
    "FrontProxyAuthenticationProfile",
    "AuthnProfile",
    "SAProfile",
]

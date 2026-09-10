"""Pure parsing and semantic checks for etcd and kube-apiserver TLS flags."""
from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


def _bool(value: Any, default: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"true", "yes", "on", "1"}:
        return True
    if text in {"false", "no", "off", "0"}:
        return False
    return default


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [str(value)]


def _flags(flags: Any) -> dict[str, Any]:
    if isinstance(flags, Mapping):
        return {str(k).lstrip("-"): v for k, v in flags.items()}
    if isinstance(flags, str):
        flags = shlex.split(flags)
    tokens = list(flags or [])
    result: dict[str, Any] = {}
    i = 0
    while i < len(tokens):
        token = str(tokens[i])
        if not token.startswith("-"):
            i += 1
            continue
        token = token.lstrip("-")
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value
        elif i + 1 < len(tokens) and not str(tokens[i + 1]).startswith("-"):
            result[token] = tokens[i + 1]
            i += 1
        else:
            result[token] = True
        i += 1
    return result


def _get(values: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in values:
            return values[name]
        alt = name.replace("-", "_")
        if alt in values:
            return values[alt]
    return None


@dataclass(frozen=True)
class EndpointProfile:
    endpoint: str
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    secure: bool | None = None
    valid: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_endpoint(endpoint: str) -> EndpointProfile:
    value = str(endpoint).strip()
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower() or None
        host = parsed.hostname
        port = parsed.port
        if scheme not in {"http", "https"} or not host:
            return EndpointProfile(value, scheme, host, port, None, False, "endpoint must be an http(s) URL")
        return EndpointProfile(value, scheme, host, port, scheme == "https")
    except (TypeError, ValueError) as exc:
        return EndpointProfile(value, valid=False, error=str(exc))


@dataclass(frozen=True)
class TransportSecurityProfile:
    urls: list[EndpointProfile] = field(default_factory=list)
    tls: bool | None = None
    client_cert_auth: bool | None = None
    cert_file: str | None = None
    key_file: str | None = None
    ca_file: str | None = None
    auto_tls: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EtcdSecurityProfile:
    client: TransportSecurityProfile
    peer: TransportSecurityProfile
    status: str = "UNKNOWN"
    errors: list[str] = field(default_factory=list)
    source: str | None = None

    # Convenient compatibility properties for callers that don't need nesting.
    @property
    def client_urls(self) -> list[str]:
        return [x.endpoint for x in self.client.urls]

    @property
    def peer_urls(self) -> list[str]:
        return [x.endpoint for x in self.peer.urls]

    @property
    def client_tls(self) -> bool | None:
        return self.client.tls

    @property
    def peer_tls(self) -> bool | None:
        return self.peer.tls

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _transport(values: Mapping[str, Any], peer: bool = False) -> TransportSecurityProfile:
    prefix = "peer-" if peer else ""
    if peer:
        urls = _values(_get(values, "listen-peer-urls", "initial-advertise-peer-urls", "advertise-peer-urls"))
        cert = _get(values, "peer-cert-file")
        key = _get(values, "peer-key-file")
        ca = _get(values, "peer-trusted-ca-file", "peer-ca-file")
        auth = _bool(_get(values, "peer-client-cert-auth"))
        auto = _bool(_get(values, "peer-auto-tls"))
    else:
        urls = _values(_get(values, "listen-client-urls", "advertise-client-urls"))
        cert = _get(values, "cert-file")
        key = _get(values, "key-file")
        ca = _get(values, "trusted-ca-file", "ca-file")
        auth = _bool(_get(values, "client-cert-auth"))
        auto = _bool(_get(values, "auto-tls"))
    endpoints = [parse_endpoint(x) for x in urls]
    secure = (all(x.secure for x in endpoints) if endpoints else None)
    if auto is True:
        secure = True
    return TransportSecurityProfile(endpoints, secure, auth, _str_or_none(cert), _str_or_none(key), _str_or_none(ca), auto)


def _str_or_none(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def parse_etcd_flags(flags: Any, *, source: str | None = None) -> EtcdSecurityProfile:
    values = _flags(flags)
    client = _transport(values)
    peer = _transport(values, peer=True)
    errors: list[str] = []
    for side, profile in (("client", client), ("peer", peer)):
        if any(not endpoint.valid for endpoint in profile.urls):
            errors.append(f"invalid {side} listener endpoint")
        if profile.tls is True and profile.client_cert_auth is False:
            errors.append(f"{side} TLS does not require client certificates")
    known = bool(client.urls or peer.urls or client.cert_file or peer.cert_file or client.auto_tls is not None or peer.auto_tls is not None)
    status = "UNKNOWN" if not known else ("FAIL" if errors else "PASS")
    return EtcdSecurityProfile(client, peer, status, errors, source)


def parse_etcd_config(config: Mapping[str, Any] | str, *, source: str | None = None) -> EtcdSecurityProfile:
    if isinstance(config, str):
        values = _flags(config)
    else:
        values = dict(config)
    return parse_etcd_flags(values, source=source)


@dataclass(frozen=True)
class ApiServerEtcdClientProfile:
    endpoints: list[EndpointProfile] = field(default_factory=list)
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    tls: bool | None = None
    client_certificate_auth: bool | None = None
    status: str = "UNKNOWN"
    errors: list[str] = field(default_factory=list)
    source: str | None = None

    @property
    def has_client_certificate(self) -> bool | None:
        return bool(self.cert_file) if self.cert_file is not None else None

    @property
    def has_client_key(self) -> bool | None:
        return bool(self.key_file) if self.key_file is not None else None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_apiserver_etcd_client(flags: Any, *, source: str | None = None) -> ApiServerEtcdClientProfile:
    values = _flags(flags)
    endpoints = [parse_endpoint(x) for x in _values(_get(values, "etcd-servers", "etcd_servers"))]
    tls = all(x.secure for x in endpoints) if endpoints else None
    ca = _str_or_none(_get(values, "etcd-cafile", "etcd-ca-file"))
    cert = _str_or_none(_get(values, "etcd-certfile", "etcd-cert-file"))
    key = _str_or_none(_get(values, "etcd-keyfile", "etcd-key-file"))
    errors = ["invalid etcd endpoint"] if any(not x.valid for x in endpoints) else []
    if tls is True and (not ca or not cert or not key):
        errors.append("HTTPS etcd endpoint is missing CA, client certificate, or client key path")
    known = bool(endpoints or ca or cert or key)
    status = "UNKNOWN" if not known else ("FAIL" if errors else "PASS")
    return ApiServerEtcdClientProfile(endpoints, ca, cert, key, tls, bool(cert and key) if cert or key else None, status, errors, source)


parse_apiserver_etcd_flags = parse_apiserver_etcd_client


@dataclass(frozen=True)
class ClusterConsistencyProfile:
    status: str
    node_count: int
    issues: list[str] = field(default_factory=list)
    compared_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_cluster_consistency(profiles: Iterable[EtcdSecurityProfile]) -> ClusterConsistencyProfile:
    items = list(profiles)
    if not items:
        return ClusterConsistencyProfile("UNKNOWN", 0, ["no etcd profiles supplied"])
    issues: list[str] = []
    for field_name in ("client_tls", "peer_tls"):
        values = {getattr(item, field_name) for item in items}
        known = {x for x in values if x is not None}
        if len(known) > 1:
            issues.append(f"inconsistent {field_name} across nodes")
    for field_name in ("client", "peer"):
        auth_values = {getattr(item, field_name).client_cert_auth for item in items}
        known = {x for x in auth_values if x is not None}
        if len(known) > 1:
            issues.append(f"inconsistent {field_name} client certificate authentication across nodes")
    unknown = any(item.status == "UNKNOWN" for item in items)
    status = "FAIL" if issues else ("UNKNOWN" if unknown else "PASS")
    # URL hosts are intentionally not compared: each member normally has a
    # unique IP while transport semantics should still be cluster-consistent.
    return ClusterConsistencyProfile(status, len(items), issues, ["client_tls", "peer_tls", "client_cert_auth", "peer_client_cert_auth"])


check_cluster_consistency = assess_cluster_consistency


def listener_transport_summary(profile: EtcdSecurityProfile) -> dict[str, Any]:
    return {
        "status": profile.status,
        "client": {
            "tls": profile.client.tls,
            "client_cert_auth": profile.client.client_cert_auth,
            "endpoints": [endpoint.to_dict() for endpoint in profile.client.urls],
        },
        "peer": {
            "tls": profile.peer.tls,
            "client_cert_auth": profile.peer.client_cert_auth,
            "endpoints": [endpoint.to_dict() for endpoint in profile.peer.urls],
        },
        "errors": list(profile.errors),
    }


def summarize_listener_security(profile: EtcdSecurityProfile) -> dict[str, Any]:
    return listener_transport_summary(profile)

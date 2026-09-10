"""Kubernetes encryption-provider-config inspection without exposing key bytes."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

_SENSITIVE_NAMES = {"key", "keydata", "key-data", "secret", "token", "password", "privatekey", "private-key"}


def _load_source(source: Any) -> tuple[Any, str | None, str | None]:
    if isinstance(source, Mapping):
        return source, None, None
    if isinstance(source, (str, Path)):
        value = str(source)
        if "\n" not in value and Path(value).exists():
            try:
                return Path(value).read_text(encoding="utf-8"), value, None
            except OSError as exc:
                return None, value, str(exc)
        return value, None, None
    return source, None, None


def _parse_document(value: Any) -> Any:
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        pass
    # PyYAML is an optional convenience already used by the surrounding app;
    # retain a JSON/stdlib path for callers that don't install it.
    try:
        import yaml  # type: ignore

        return yaml.safe_load(value)
    except Exception:
        return None


def _safe_value(value: Any, key: str = "") -> Any:
    if key.lower().replace("_", "-") in _SENSITIVE_NAMES or key.lower().replace("_", "-").endswith("keydata"):
        return "[REDACTED]" if value not in (None, "") else None
    if isinstance(value, Mapping):
        return {str(k): _safe_value(v, str(k)) for k, v in value.items() if str(k).lower() not in _SENSITIVE_NAMES}
    if isinstance(value, list):
        return [_safe_value(v, key) for v in value]
    return value


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _name(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


@dataclass(frozen=True)
class KmsProviderProfile:
    name: str | None = None
    api_version: str | None = None
    endpoint: str | None = None
    timeout: str | None = None
    cache_size: int | None = None
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def cachesize(self) -> int | None:
        return self.cache_size

    @property
    def socket(self) -> str | None:
        return self.endpoint

    @property
    def redacted_config(self) -> dict[str, Any]:
        return self.config

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)




@dataclass(frozen=True)
class EncryptionProviderProfile:
    provider_type: str
    key_names: list[str] = field(default_factory=list)
    kms: KmsProviderProfile | None = None
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.provider_type

    @property
    def type(self) -> str:
        return self.provider_type


    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EncryptionResourceRule:
    resources: list[str] = field(default_factory=list)
    providers: list[EncryptionProviderProfile] = field(default_factory=list)
    api_groups: list[str] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)

    @property
    def provider_order(self) -> list[str]:
        return [p.provider_type for p in self.providers]

    @property
    def key_names(self) -> list[str]:
        return [key for provider in self.providers for key in provider.key_names]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EncryptionProviderProfileResult:
    rules: list[EncryptionResourceRule] = field(default_factory=list)
    status: str = "UNKNOWN"
    provider_order: list[str] = field(default_factory=list)
    key_names: list[str] = field(default_factory=list)
    kms_providers: list[KmsProviderProfile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source: str | None = None

    @property
    def resources(self) -> list[str]:
        return [resource for rule in self.rules for resource in rule.resources]

    @property
    def providers(self) -> list[str]:
        return self.provider_order

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


EncryptionConfigProfile = EncryptionProviderProfileResult


def _provider(value: Any) -> EncryptionProviderProfile | None:
    if not isinstance(value, Mapping) or not value:
        return None
    provider_type = str(next(iter(value))).lower()
    body = value.get(next(iter(value)))
    body = body if isinstance(body, Mapping) else {}
    safe = _safe_value(body)
    key_names: list[str] = []
    for key in _list(body.get("keys")):
        if isinstance(key, Mapping) and key.get("name") is not None:
            key_names.append(str(key["name"]))
    kms: KmsProviderProfile | None = None
    if provider_type == "kms":
        kms = KmsProviderProfile(
            name=_name(body.get("name")),
            api_version=_name(body.get("apiVersion", body.get("api_version"))),
            endpoint=_name(body.get("endpoint", body.get("socket"))),
            timeout=_name(body.get("timeout")),
            cache_size=_int_or_none(body.get("cachesize", body.get("cacheSize"))),
            config=safe if isinstance(safe, dict) else {},
        )
    return EncryptionProviderProfile(provider_type, key_names, kms, safe if isinstance(safe, dict) else {})


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_encryption_config(source: Any, *, source_name: str | None = None) -> EncryptionProviderProfileResult:
    raw, inferred_name, read_error = _load_source(source)
    if read_error:
        return EncryptionProviderProfileResult(source=source_name or inferred_name, errors=[read_error])
    document = _parse_document(raw)
    if not isinstance(document, Mapping):
        return EncryptionProviderProfileResult(source=source_name or inferred_name, errors=["invalid or unavailable encryption config"])
    rules: list[EncryptionResourceRule] = []
    errors: list[str] = []
    for row in _list(document.get("resources")):
        if not isinstance(row, Mapping):
            errors.append("resource rule is not an object")
            continue
        providers = [p for p in (_provider(x) for x in _list(row.get("providers"))) if p is not None]
        resources = [str(x) for x in _list(row.get("resources"))]
        rules.append(EncryptionResourceRule(
            resources=resources,
            providers=providers,
            api_groups=[str(x) for x in _list(row.get("apiGroups", row.get("api_groups")))],
            namespaces=[str(x) for x in _list(row.get("namespaces"))],
        ))
    order = [provider.provider_type for rule in rules for provider in rule.providers]
    keys = [key for rule in rules for key in rule.key_names]
    kms = [provider.kms for rule in rules for provider in rule.providers if provider.kms is not None]
    if not rules:
        status = "UNKNOWN"
        errors.append("no encryption resource rules found")
    elif any(not rule.providers for rule in rules):
        status = "FAIL"
        errors.append("resource rule has no providers")
    elif any(rule.provider_order[-1:] != ["identity"] for rule in rules):
        # identity last is the Kubernetes rotation-safe fallback convention.
        status = "WARN"
        errors.append("identity provider is not last in one or more resource rules")
    else:
        status = "PASS"
    return EncryptionProviderProfileResult(
        rules=rules,
        status=status,
        provider_order=order,
        key_names=keys,
        kms_providers=[x for x in kms if x is not None],
        errors=errors,
        source=source_name or inferred_name,
    )


parse_encryption_provider_config = parse_encryption_config
inspect_encryption_config = parse_encryption_config


def redact_encryption_config(source: Any) -> Any:
    """Return a redacted copy suitable for evidence output."""
    raw, _, _ = _load_source(source)
    document = _parse_document(raw)
    return _safe_value(document)

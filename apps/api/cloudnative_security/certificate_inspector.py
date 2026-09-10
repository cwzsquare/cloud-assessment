"""Public X.509 certificate inspection helpers.

Only public certificate bytes are ever parsed.  Private-key PEM blocks are
ignored, and returned dataclasses contain no key material.  ``ssl`` is used as
the parser so the module has no third-party dependency.
"""
from __future__ import annotations

import re
import shlex
import ssl
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)

_APISERVER_CERT_FLAGS = frozenset(
    {
        "tls-cert-file",
        "client-ca-file",
        "requestheader-client-ca-file",
        "etcd-cafile",
        "etcd-certfile",
    }
)
_ETCD_CERT_FLAGS = frozenset(
    {
        "cert-file",
        "trusted-ca-file",
        "peer-cert-file",
        "peer-trusted-ca-file",
    }
)
_PRIVATE_CERT_FLAG_PARTS = (
    "private-key",
    "privatekey",
    "key-file",
    "keyfile",
    "peer-key",
    "etcd-key",
)




@dataclass(frozen=True)
class CertificateProfile:
    """Safe, JSON-friendly metadata for a public certificate."""

    status: str = "UNKNOWN"
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sans: list[str] = field(default_factory=list)
    version: int | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    is_ca: bool | None = None
    expired: bool | None = None
    days_until_expiry: int | None = None
    expires_within_30_days: bool | None = None
    expected_sans: list[str] = field(default_factory=list)
    san_covered: bool | None = None
    san_coverage_reason: str | None = None
    weak_signature: bool | None = None
    weak_signature_reason: str | None = None
    weak_public_key: bool | None = None
    weak_public_key_reason: str | None = None
    source: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def valid(self) -> bool | None:
        if self.expired is None:
            return None
        return not self.expired

    @property
    def expiring_soon(self) -> bool | None:
        """Compatibility alias for the 30-day expiry check."""
        return self.expires_within_30_days

    @property
    def san_coverage(self) -> bool | None:
        """Compatibility alias for :attr:`san_covered`."""
        return self.san_covered


@dataclass(frozen=True)
class ControlPlaneCertificate:
    """A safe reference to a control-plane public certificate.

    This object intentionally contains only the argument name, public path and
    parsed metadata.  PEM bytes (and all private-key paths) are never fields.
    """

    component: str
    flag: str
    path: str
    profile: CertificateProfile | None = None

    @property
    def certificate_path(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "component": self.component,
            "flag": self.flag,
            "path": self.path,
        }
        if self.profile is not None:
            result["profile"] = self.profile.to_dict()
        return result



def _name(value: Any) -> str | None:
    """Turn ssl's tuple-of-tuples distinguished name into a readable value."""
    if not value:
        return None
    parts: list[str] = []
    try:
        for rdn in value:
            for key, val in rdn:
                parts.append(f"{key}={val}")
    except (TypeError, ValueError):
        return str(value)
    return ", ".join(parts) or None


def _date(value: str | datetime | None) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(str(value), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _safe_source(value: str | Path | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    return None if _is_private_path(text) else text


def _is_private_path(value: str) -> bool:
    lowered = value.lower().replace("_", "-")
    basename = lowered.rsplit("/", 1)[-1]
    return (
        any(part in lowered for part in _PRIVATE_CERT_FLAG_PARTS)
        or basename.endswith(".key")
        or basename in {"key", "private"}
    )


def _flag_tokens(command: Iterable[Any] | str) -> list[str]:
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return [str(token) for token in command]


def _component_name(command: Sequence[str], component: str | None) -> str:
    if component:
        normalized = str(component).lower().replace("_", "-")
        return "apiserver" if normalized in {"kube-apiserver", "api-server"} else normalized
    for token in command:
        name = Path(token).name.lower()
        if name in {"etcd", "etcd-server"} or name.endswith("/etcd"):
            return "etcd"
        if "kube-apiserver" in name or name in {"apiserver", "kubeapi"}:
            return "apiserver"
    return "unknown"


def parse_control_plane_certificate_paths(
    command: Iterable[Any] | str,
    *,
    component: str | None = None,
) -> list[ControlPlaneCertificate]:
    """Extract only public certificate/CA paths from static-Pod arguments.

    The allowlist is component-specific.  In particular, no ``*-key-file``,
    ``peer-key-file`` or ``etcd-keyfile`` argument can become evidence.
    """
    tokens = _flag_tokens(command)
    selected_component = _component_name(tokens, component)
    allowed = _ETCD_CERT_FLAGS if selected_component == "etcd" else _APISERVER_CERT_FLAGS
    result: list[ControlPlaneCertificate] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            index += 1
            continue
        argument = token[2:]
        if "=" in argument:
            flag, path = argument.split("=", 1)
        else:
            flag = argument
            path = tokens[index + 1] if index + 1 < len(tokens) and not tokens[index + 1].startswith("--") else ""
            if path:
                index += 1
        if flag in allowed and path and not _is_private_path(path):
            result.append(ControlPlaneCertificate(selected_component, flag, path))
        index += 1
    return result


def inspect_control_plane_certificates(
    command: Iterable[Any] | str,
    reader: Callable[[str], str | bytes] | None = None,
    *,
    component: str | None = None,
    expected_sans: Iterable[str] | None = None,
) -> list[ControlPlaneCertificate]:
    """Inspect allowlisted control-plane paths while keeping PEM in-process.

    ``reader`` may fetch bytes from a node.  It is called only for paths
    returned by :func:`parse_control_plane_certificate_paths`; callers should
    pass a node collector callback rather than persisting its result.
    """
    entries = parse_control_plane_certificate_paths(command, component=component)
    expected = list(expected_sans or ())
    inspected: list[ControlPlaneCertificate] = []
    for entry in entries:
        if reader is None:
            profile = inspect_certificate(
                entry.path,
                source_name=f"{entry.component}:{entry.flag}:{entry.path}",
                expected_sans=expected,
            )
        else:
            try:
                pem = reader(entry.path)
            except Exception as exc:
                profile = _invalid(f"{entry.component}:{entry.flag}", exc)
            else:
                profile = inspect_certificate(
                    pem,
                    source_name=f"{entry.component}:{entry.flag}:{entry.path}",
                    expected_sans=expected,
                )
        inspected.append(ControlPlaneCertificate(entry.component, entry.flag, entry.path, profile))
    return inspected


# Descriptive aliases used by collectors and older integrations.
parse_static_pod_certificate_paths = parse_control_plane_certificate_paths
inspect_static_pod_certificates = inspect_control_plane_certificates


def _invalid(source: str | Path | None, error: Exception | str) -> CertificateProfile:
    return CertificateProfile(source=_safe_source(source), error=str(error)[:500])
def _decode_public_pem(
    pem: bytes,
    source: str | Path | None,
    expected_sans: Sequence[str] = (),
) -> CertificateProfile:
    # A combined bundle can contain a private key.  Extracting the certificate
    # block first guarantees that the parser and temporary file never see it.
    match = _CERT_RE.search(pem)
    if not match:
        return _invalid(source, "no PEM certificate block found")
    public_pem = match.group(0)
    try:
        # _test_decode_cert accepts a path and returns only public X.509 fields.
        with tempfile.NamedTemporaryFile(prefix="cnsec-cert-", suffix=".pem", mode="wb") as fh:
            fh.write(public_pem)
            fh.flush()
            decoded = ssl._ssl._test_decode_cert(fh.name)  # type: ignore[attr-defined]
    except (OSError, ValueError, ssl.SSLError) as exc:
        return _invalid(source, exc)
    return _profile_from_decoded(decoded, source, expected_sans)


def _decoded_value(decoded: dict[str, Any], *names: str) -> Any:
    for name in names:
        if decoded.get(name) not in (None, ""):
            return decoded[name]
    return None


def _int_value(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _san_name(value: Any) -> str:
    text = str(value).strip().lower()
    return text.split(":", 1)[1].strip() if ":" in text else text


def _san_matches(actual: str, expected: str) -> bool:
    actual_name, expected_name = _san_name(actual), _san_name(expected)
    if actual_name == expected_name:
        return True
    if actual_name.startswith("*."):
        suffix = actual_name[1:]
        return expected_name.endswith(suffix) and expected_name.count(".") == suffix.count(".")
    return False


def _certificate_checks(
    decoded: dict[str, Any],
    sans: list[str],
    expected_sans: Sequence[str],
) -> tuple[str | None, bool | None, str | None, bool | None, str | None, bool | None, str | None]:
    signature = _decoded_value(decoded, "signatureAlgorithm", "signature_algorithm", "signature")
    signature_text = str(signature) if signature is not None else None
    if signature_text is None:
        weak_signature, signature_reason = None, "signature algorithm unavailable"
    elif re.search(r"(?:md2|md4|md5|sha-?1)", signature_text, re.IGNORECASE):
        weak_signature = True
        signature_reason = f"weak signature algorithm: {signature_text}"
    else:
        weak_signature = False
        signature_reason = f"signature algorithm meets baseline: {signature_text}"

    public_key_algorithm = _decoded_value(
        decoded,
        "publicKeyAlgorithm",
        "public_key_algorithm",
        "publicKeyType",
        "public_key_type",
    )
    public_key_size = _int_value(
        _decoded_value(decoded, "publicKeySize", "public_key_size", "keySize", "key_size")
    )
    algorithm_text = str(public_key_algorithm).lower() if public_key_algorithm is not None else ""
    if not algorithm_text or public_key_size is None:
        weak_public_key, public_key_reason = None, "public-key algorithm or size unavailable"
    elif "dsa" in algorithm_text:
        weak_public_key, public_key_reason = True, "DSA public keys are not accepted by the baseline"
    elif "rsa" in algorithm_text and public_key_size < 2048:
        weak_public_key, public_key_reason = True, f"RSA public key is {public_key_size} bits; minimum is 2048"
    elif ("ec" in algorithm_text or "ecdsa" in algorithm_text) and public_key_size < 256:
        weak_public_key, public_key_reason = True, f"EC public key is {public_key_size} bits; minimum is 256"
    else:
        weak_public_key, public_key_reason = False, f"{public_key_algorithm} public key meets baseline"

    if not expected_sans:
        san_covered, san_reason = None, "no expected SAN names supplied"
    else:
        missing = [name for name in expected_sans if not any(_san_matches(actual, name) for actual in sans)]
        san_covered = not missing
        san_reason = "all expected SAN names are covered" if not missing else f"missing SAN names: {', '.join(map(str, missing))}"
    return signature_text, weak_signature, signature_reason, weak_public_key, public_key_reason, san_covered, san_reason


def _profile_from_decoded(
    decoded: dict[str, Any],
    source: str | Path | None,
    expected_sans: Sequence[str] = (),
) -> CertificateProfile:
    before = _decoded_value(decoded, "notBefore", "not_before")
    after = _decoded_value(decoded, "notAfter", "not_after")
    expiry = _date(after)
    now = datetime.now(timezone.utc)
    expired = None if expiry is None else expiry < now
    delta = None if expiry is None else expiry - now
    days = None if delta is None else delta.days
    expires_soon = None if delta is None else not bool(expired) and delta <= timedelta(days=30)
    sans: list[str] = []
    for kind, value in decoded.get("subjectAltName", ()) or ():
        sans.append(f"{kind}:{value}")
    version = _int_value(decoded.get("version"))
    signature, weak_signature, signature_reason, weak_key, key_reason, san_covered, san_reason = _certificate_checks(
        decoded, sans, expected_sans
    )
    if expiry is None:
        status = "UNKNOWN"
    elif expired or expires_soon or weak_signature or weak_key or san_covered is False:
        status = "WARN"
    else:
        status = "PASS"
    is_ca = _decoded_value(decoded, "isCA", "is_ca")
    if is_ca is not None:
        is_ca = bool(is_ca)
    return CertificateProfile(
        status=status,
        subject=_name(decoded.get("subject")),
        issuer=_name(decoded.get("issuer")),
        serial_number=_decoded_value(decoded, "serialNumber", "serial_number"),
        not_before=before,
        not_after=after,
        sans=sans,
        version=version,
        signature_algorithm=signature,
        public_key_algorithm=_decoded_value(decoded, "publicKeyAlgorithm", "public_key_algorithm", "publicKeyType", "public_key_type"),
        public_key_size=_int_value(_decoded_value(decoded, "publicKeySize", "public_key_size", "keySize", "key_size")),
        is_ca=is_ca,
        expired=expired,
        days_until_expiry=days,
        expires_within_30_days=expires_soon,
        expected_sans=[str(name) for name in expected_sans],
        san_covered=san_covered,
        san_coverage_reason=san_reason,
        weak_signature=weak_signature,
        weak_signature_reason=signature_reason,
        weak_public_key=weak_key,
        weak_public_key_reason=key_reason,
        source=_safe_source(source),
    )


def inspect_certificate(
    source: str | Path | bytes | bytearray | memoryview,
    *,
    source_name: str | Path | None = None,
    expected_sans: Iterable[str] | None = None,
) -> CertificateProfile:
    """Inspect a certificate PEM/path and return metadata, never key material.

    ``source`` may be PEM bytes/text or a filesystem path.  A missing path,
    invalid PEM, DER input, and an empty value all produce ``UNKNOWN`` with an
    error description instead of raising.  When a path is supplied, only that
    public certificate file is read; private keys are not followed.
    """
    label = source_name
    expected = list(expected_sans or ())
    if isinstance(source, str) and "-----BEGIN CERTIFICATE-----" in source:
        return _decode_public_pem(source.encode(), label, expected)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _decode_public_pem(bytes(source), label, expected)
    path = Path(source)
    label = label or path
    try:
        data = path.read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        return _invalid(label, exc)
    return _decode_public_pem(data, label, expected)


def inspect_public_certificate(
    source: str | Path | bytes | bytearray | memoryview,
    *,
    source_name: str | Path | None = None,
    expected_sans: Iterable[str] | None = None,
) -> CertificateProfile:
    """Explicit alias documenting that private keys are not inspected."""
    return inspect_certificate(source, source_name=source_name, expected_sans=expected_sans)


def parse_certificate(source: str | Path | bytes | bytearray | memoryview, **kwargs: Any) -> CertificateProfile:
    return inspect_certificate(source, **kwargs)


def inspect_certificate_file(path: str | Path) -> CertificateProfile:
    return inspect_certificate(path)

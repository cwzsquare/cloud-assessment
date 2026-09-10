"""Public X.509 certificate inspection helpers.

Only public certificate bytes are ever parsed.  Private-key PEM blocks are
ignored, and returned dataclasses contain no key material.  ``ssl`` is used as
the parser so the module has no third-party dependency.
"""
from __future__ import annotations

import re
import ssl
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
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
    source: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def valid(self) -> bool | None:
        if self.expired is None:
            return None
        return not self.expired


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


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _safe_source(value: str | Path | None) -> str | None:
    return str(value) if value is not None else None


def _invalid(source: str | Path | None, error: Exception | str) -> CertificateProfile:
    return CertificateProfile(source=_safe_source(source), error=str(error)[:500])


def _decode_public_pem(pem: bytes, source: str | Path | None) -> CertificateProfile:
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
    return _profile_from_decoded(decoded, source)


def _profile_from_decoded(decoded: dict[str, Any], source: str | Path | None) -> CertificateProfile:
    before = decoded.get("notBefore")
    after = decoded.get("notAfter")
    expiry = _date(after)
    now = datetime.now(timezone.utc)
    expired = expiry is not None and expiry < now
    days = (expiry - now).days if expiry is not None else None
    sans: list[str] = []
    for kind, value in decoded.get("subjectAltName", ()) or ():
        sans.append(f"{kind}:{value}")
    # ssl exposes extension values but not signature/key algorithm details.  Keep
    # those fields explicitly unknown rather than making an unsafe inference.
    version = decoded.get("version")
    try:
        version = int(version) if version is not None else None
    except (TypeError, ValueError):
        version = None
    return CertificateProfile(
        status="PASS" if not expired else "WARN",
        subject=_name(decoded.get("subject")),
        issuer=_name(decoded.get("issuer")),
        serial_number=decoded.get("serialNumber"),
        not_before=before,
        not_after=after,
        sans=sans,
        version=version,
        expired=expired,
        days_until_expiry=days,
        source=_safe_source(source),
    )


def inspect_certificate(
    source: str | Path | bytes | bytearray | memoryview,
    *,
    source_name: str | Path | None = None,
) -> CertificateProfile:
    """Inspect a certificate PEM/path and return metadata, never key material.

    ``source`` may be PEM bytes/text or a filesystem path.  A missing path,
    invalid PEM, DER input, and an empty value all produce ``UNKNOWN`` with an
    error description instead of raising.  When a path is supplied, only that
    public certificate file is read; private keys are not followed.
    """
    label = source_name
    if isinstance(source, str) and "-----BEGIN CERTIFICATE-----" in source:
        return _decode_public_pem(source.encode(), label)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _decode_public_pem(bytes(source), label)
    path = Path(source)
    label = label or path
    try:
        data = path.read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        return _invalid(label, exc)
    return _decode_public_pem(data, label)


def inspect_public_certificate(
    source: str | Path | bytes | bytearray | memoryview,
    *,
    source_name: str | Path | None = None,
) -> CertificateProfile:
    """Explicit alias documenting that private keys are not inspected."""
    return inspect_certificate(source, source_name=source_name)


def parse_certificate(source: str | Path | bytes | bytearray | memoryview, **kwargs: Any) -> CertificateProfile:
    return inspect_certificate(source, **kwargs)


def inspect_certificate_file(path: str | Path) -> CertificateProfile:
    return inspect_certificate(path)

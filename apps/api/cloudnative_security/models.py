from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


FindingStatus = Literal["PASS", "FAIL", "WARN", "UNKNOWN", "NOT_APPLICABLE"]
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class AssetRef:
    kind: str
    name: str
    namespace: str | None = None
    api_version: str | None = None
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        ns = self.namespace or "_cluster"
        return f"{self.kind}/{ns}/{self.name}"


@dataclass(frozen=True)
class Evidence:
    summary: str
    object_ref: AssetRef | None = None
    json_path: str | None = None
    observed: Any | None = None
    expected: Any | None = None
    raw_snippet: Any | None = None


@dataclass(frozen=True)
class Checkpoint:
    id: str
    tender_no: int
    name: str
    rule_group: str
    domain: str
    weight: float
    dimensions: list[str]
    data_sources: list[str]


@dataclass(frozen=True)
class Finding:
    id: str
    task_id: str
    tool_id: str
    checkpoint_id: str
    rule_id: str
    title: str
    status: FindingStatus
    severity: Severity
    score: float
    asset: AssetRef | None
    evidence: list[Evidence]
    remediation: str
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""


@dataclass(frozen=True)
class CheckpointScore:
    checkpoint_id: str
    name: str
    domain: str
    weight: float
    status: FindingStatus
    score: float
    finding_count: int
    failed_count: int
    warn_count: int
    unknown_count: int


@dataclass(frozen=True)
class AssessmentReport:
    schema_version: str
    task_id: str
    generated_at: str
    summary: dict[str, Any]
    checkpoint_scores: list[CheckpointScore]
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


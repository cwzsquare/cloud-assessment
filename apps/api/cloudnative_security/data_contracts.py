"""Contracts for collection and normalization pipeline runs.

The contracts in this module intentionally contain metadata and counters rather
than raw payloads.  A collector can therefore pass rich objects through a
pipeline without accidentally putting credentials or other sensitive evidence
in run history.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
import json
from typing import Any, Literal
from uuid import uuid4


# Pipeline status vocabulary.  SUCCESS is used instead of ``SUCCEEDED`` to
# match the existing assessment task status vocabulary.
PENDING = "PENDING"
RUNNING = "RUNNING"
SUCCESS = "SUCCESS"
# ``SUCCEEDED`` is a value-compatible spelling for integrations whose
# orchestrator uses that term; emitted run records continue to use SUCCESS.
SUCCEEDED = SUCCESS
PARTIAL = "PARTIAL"
FAILED = "FAILED"
SKIPPED = "SKIPPED"

RunStatus = Literal["PENDING", "RUNNING", "SUCCESS", "PARTIAL", "FAILED", "SKIPPED"]
CollectionRunStatus = RunStatus
ProcessingRunStatus = RunStatus
ProcessingStepStatus = RunStatus

# Explicitly named aliases make the vocabulary convenient for callers that
# prefer constants grouped by contract.
STATUS_PENDING = PENDING
STATUS_RUNNING = RUNNING
STATUS_SUCCESS = SUCCESS
STATUS_SUCCEEDED = SUCCEEDED
STATUS_PARTIAL = PARTIAL
STATUS_FAILED = FAILED
STATUS_SKIPPED = SKIPPED


def utc_now() -> str:
    """Return an aware, UTC ISO-8601 timestamp."""

    return datetime.now(timezone.utc).isoformat()


def new_run_id(prefix: str) -> str:
    """Create a compact, non-secret identifier for a run or source."""

    return f"{prefix}-{uuid4().hex}"


def _json_value(value: Any) -> Any:
    """Convert supported values to values accepted by :mod:`json`.

    The run records only receive summaries and counters from ``DataPipeline``;
    this helper additionally makes manually supplied summaries safe to export.
    Unknown objects are represented by their string form instead of leaking an
    unserializable object into API responses.
    """

    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class _Serializable:
    """Mixin shared by public run contracts."""

    def to_dict(self) -> dict[str, Any]:
        return _json_value(asdict(self))

    def to_json(self, *, ensure_ascii: bool = False) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=ensure_ascii, sort_keys=True)


@dataclass
class SourceDescriptor(_Serializable):
    """A non-sensitive description of an evidence source.

    ``uri`` is intentionally metadata only.  Authentication material must be
    represented by a reference in ``metadata`` (for example ``secret_ref``),
    never by the secret itself.
    """

    source_id: str = field(default_factory=lambda: new_run_id("source"))
    source_type: str = "unknown"
    name: str = ""
    uri: str | None = None
    version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Compatibility alias for APIs that call source identifiers ``id``."""

        return self.source_id


@dataclass
class ProcessingStepRun(_Serializable):
    """Outcome and metrics for one processing step."""

    step_id: str = ""
    step_name: str = ""
    status: ProcessingStepStatus = PENDING
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    input_count: int = 0
    output_count: int = 0
    drop_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def dropped_count(self) -> int:
        return self.drop_count

    @property
    def error(self) -> str | None:
        return self.errors[0] if self.errors else None

    @property
    def duration(self) -> float:
        """Duration in milliseconds, retained as a short ergonomic alias."""

        return self.duration_ms

    @property
    def input(self) -> int:
        return self.input_count

    @property
    def output(self) -> int:
        return self.output_count

    @property
    def drop(self) -> int:
        return self.drop_count

    @property
    def warning(self) -> str | None:
        return self.warnings[0] if self.warnings else None

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def error_count(self) -> int:
        return len(self.errors)


@dataclass
class CollectionRun(_Serializable):
    """Metadata and aggregate counters for an evidence collection run."""

    @property
    def source_descriptor(self) -> SourceDescriptor | None:
        return self.source

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    run_id: str = field(default_factory=lambda: new_run_id("collection"))
    source: SourceDescriptor | None = None
    status: CollectionRunStatus = PENDING
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    input_count: int = 0
    output_count: int = 0
    drop_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.run_id

    @property
    def dropped_count(self) -> int:
        return self.drop_count

    @property
    def error(self) -> str | None:
        return self.errors[0] if self.errors else None


@dataclass
class ProcessingRun(_Serializable):
    """A processing pipeline execution and its preserved step history."""

    run_id: str = field(default_factory=lambda: new_run_id("processing"))
    collection_run_id: str | None = None
    status: ProcessingRunStatus = PENDING
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    steps: list[ProcessingStepRun] = field(default_factory=list)
    input_count: int = 0
    output_count: int = 0
    drop_count: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def processing_steps(self) -> list[ProcessingStepRun]:
        return self.steps

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def id(self) -> str:
        return self.run_id

    @property
    def step_runs(self) -> list[ProcessingStepRun]:
        return self.steps

    @property
    def dropped_count(self) -> int:
        return self.drop_count

    @property
    def error(self) -> str | None:
        return self.errors[0] if self.errors else None


__all__ = [
    "CollectionRun",
    "CollectionRunStatus",
    "FAILED",
    "PARTIAL",
    "PENDING",
    "ProcessingRun",
    "ProcessingRunStatus",
    "ProcessingStepRun",
    "ProcessingStepStatus",
    "RunStatus",
    "RUNNING",
    "SKIPPED",
    "SUCCESS",
    "SUCCEEDED",
    "STATUS_FAILED",
    "STATUS_PARTIAL",
    "STATUS_PENDING",
    "STATUS_RUNNING",
    "STATUS_SKIPPED",
    "STATUS_SUCCESS",
    "STATUS_SUCCEEDED",
    "SourceDescriptor",
    "new_run_id",
    "utc_now",
]

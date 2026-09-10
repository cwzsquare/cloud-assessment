"""Retryable, auditable execution for evidence collection calls.

The executor records metadata only.  Collection payloads never enter an
attempt record, and exception text is redacted before it is persisted.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import inspect
import json
import re
import subprocess
import time
from typing import Any, Callable, Mapping


class ErrorCode:
    CONNECTION = "connection"
    CONNECTION_ERROR = CONNECTION
    AUTHENTICATION = "authentication"
    AUTHENTICATION_ERROR = AUTHENTICATION
    PERMISSION = "permission"
    PERMISSION_ERROR = PERMISSION
    NOT_FOUND = "not_found"
    NOT_FOUND_ERROR = NOT_FOUND
    CONFIG_PARSE = "config_parse"
    CONFIG_PARSE_ERROR = CONFIG_PARSE
    COMMAND = "command"
    COMMAND_ERROR = COMMAND
    TIMEOUT = "timeout"
    TIMEOUT_ERROR = TIMEOUT
    INPUT_FORMAT = "input_format"
    INPUT_FORMAT_ERROR = INPUT_FORMAT


_NON_RETRYABLE_DEFAULTS = {
    ErrorCode.AUTHENTICATION,
    ErrorCode.PERMISSION,
    ErrorCode.NOT_FOUND,
    ErrorCode.CONFIG_PARSE,
    ErrorCode.INPUT_FORMAT,
}
_SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+)[^\s,;]+|((?:password|passwd|token|secret|private[_-]?key|api[_-]?key)\s*[=:]\s*)[^\s,;]+|-----BEGIN [^-]+-----.*?-----END [^-]+-----",
    re.DOTALL,
)
_PATH_SECRET_PATTERN = re.compile(r"(?i)(/[^\s'\"]*(?:\.pem|\.key|private[^\s'\"]*))")


def sanitize_error_message(value: Any) -> str:
    """Return bounded error text without credentials, key material, or output."""
    text = str(value or "").replace("\x00", " ")
    text = _SECRET_PATTERN.sub(lambda match: f"{match.group(1) or match.group(2) or ''}[REDACTED]", text)
    text = _PATH_SECRET_PATTERN.sub("[REDACTED_PATH]", text)
    return text[:1000] or "collection failed"


def classify_collection_error(error: BaseException) -> str:
    """Map a collection exception to the stable evidence error vocabulary."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return ErrorCode.TIMEOUT
    if isinstance(error, ConnectionError):
        return ErrorCode.CONNECTION
    if isinstance(error, PermissionError):
        return ErrorCode.PERMISSION
    if isinstance(error, FileNotFoundError):
        return ErrorCode.NOT_FOUND
    if isinstance(error, subprocess.CalledProcessError):
        code = int(error.returncode or 0)
        message = sanitize_error_message(error)
        if code in {401, 403} or any(word in message.lower() for word in ("unauthoriz", "authentication", "invalid token", "credential")):
            return ErrorCode.AUTHENTICATION if code == 401 or "auth" in message.lower() else ErrorCode.PERMISSION
        return ErrorCode.COMMAND
    message = sanitize_error_message(error).lower()
    error_type = type(error).__name__.lower()
    if "auth" in error_type:
        return ErrorCode.AUTHENTICATION
    if "permission" in error_type or "authoriz" in error_type:
        return ErrorCode.PERMISSION
    if "notfound" in error_type or "not_found" in error_type:
        return ErrorCode.NOT_FOUND
    if "timeout" in error_type:
        return ErrorCode.TIMEOUT
    if "config" in error_type and "parse" in error_type:
        return ErrorCode.CONFIG_PARSE
    if "input" in error_type and "format" in error_type:
        return ErrorCode.INPUT_FORMAT
    if "connection" in error_type:
        return ErrorCode.CONNECTION
    if any(word in message for word in ("timed out", "timeout", "deadline exceeded")):
        return ErrorCode.TIMEOUT
    if any(word in message for word in ("unauthoriz", "authentication failed", "invalid token", "credential")):
        return ErrorCode.AUTHENTICATION
    if any(word in message for word in ("permission denied", "forbidden", "access denied", "not permitted")):
        return ErrorCode.PERMISSION
    if any(word in message for word in ("no such file", "not found", "does not exist", "unknown command")):
        return ErrorCode.NOT_FOUND
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError)) or any(word in message for word in ("yaml", "json", "parse", "invalid configuration", "malformed")):
        return ErrorCode.CONFIG_PARSE
    if any(word in message for word in ("invalid input", "input format", "schema", "unsupported format", "requires ", "missing required")):
        return ErrorCode.INPUT_FORMAT
    if any(word in message for word in ("connection", "connect", "network", "dns", "refused", "unreachable", "reset by peer", "broken pipe")):
        return ErrorCode.CONNECTION
    return ErrorCode.COMMAND


@dataclass(frozen=True)
class RetryPolicy:
    """Retry settings. ``max_attempts`` includes the first invocation."""

    max_attempts: int = 3
    wait_seconds: float = 0.0
    backoff: float = 2.0
    retryable_error_codes: frozenset[str] | None = None
    non_retryable_error_codes: frozenset[str] = field(default_factory=lambda: frozenset(_NON_RETRYABLE_DEFAULTS))

    @classmethod
    def from_value(cls, value: "RetryPolicy | Mapping[str, Any] | None") -> "RetryPolicy":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            return cls()
        max_attempts = value.get("max_attempts", value.get("max_retries", 3))
        if "max_retries" in value and "max_attempts" not in value:
            max_attempts = int(max_attempts) + 1
        retryable = value.get("retryable_error_codes", value.get("retryable_codes"))
        non_retryable = value.get("non_retryable_error_codes", value.get("non_retryable_codes", _NON_RETRYABLE_DEFAULTS))
        wait_seconds = value.get("wait_seconds", value.get("fixed_wait_seconds", value.get("fixed_wait", value.get("delay", 0.0))))
        backoff = value.get("backoff", value.get("backoff_factor", value.get("exponential_backoff", value.get("exponential_factor", 2.0))))
        return cls(
            max_attempts=max(1, int(max_attempts)),
            wait_seconds=max(0.0, float(wait_seconds)),
            backoff=max(1.0, float(backoff)),
            retryable_error_codes=frozenset(str(item) for item in retryable) if retryable is not None else None,
            non_retryable_error_codes=frozenset(str(item) for item in non_retryable),
        )


@dataclass
class CollectionAttempt:
    run_id: str
    attempt: int
    started_at: str
    finished_at: str | None = None
    status: str = "RUNNING"
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CollectionRunRecord:
    run_id: str
    task_id: str
    source_id: str
    started_at: str
    finished_at: str | None = None
    status: str = "RUNNING"
    object_count: int = 0
    byte_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    content_hash: str = ""
    attempts: list[CollectionAttempt] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["attempts"] = [attempt.to_dict() for attempt in self.attempts]
        return payload


class CollectionExecutionError(RuntimeError):
    """Final collection failure with its persisted run and attempt history."""

    def __init__(self, error: BaseException, run: CollectionRunRecord) -> None:
        self.original_error = error
        self.run = run
        self.attempts = run.attempts
        self.error_code = classify_collection_error(error)
        self.error_message = sanitize_error_message(error)
        super().__init__(f"{self.error_code}: {self.error_message}")


class CollectionExecutor:
    def __init__(self, store: Any | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        self.store = store
        self.sleep = sleep
        self.last_run: CollectionRunRecord | None = None
        self.last_attempts: list[CollectionAttempt] = []

    @staticmethod
    def _source_values(source: Any) -> tuple[str, str, str]:
        if isinstance(source, Mapping):
            metadata = source.get("metadata") or {}
            source_id = str(source.get("source_id") or source.get("id") or source.get("tool_id") or "unknown")
            task_id = str(source.get("task_id") or metadata.get("task_id") or "")
            name = str(source.get("name") or source.get("display_name") or source_id)
            return source_id, task_id, name
        source_id = str(getattr(source, "source_id", getattr(source, "id", getattr(source, "tool_id", "unknown"))))
        metadata = getattr(source, "metadata", {}) or {}
        task_id = str(getattr(source, "task_id", None) or metadata.get("task_id") or "")
        return source_id, task_id, str(getattr(source, "name", None) or source_id)

    @staticmethod
    def _invoke(operation: Callable[..., Any], source: Any) -> Any:
        try:
            signature = inspect.signature(operation)
        except (TypeError, ValueError):
            return operation()
        required = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        return operation(source) if required else operation()

    def _persist_attempt(self, attempt: CollectionAttempt) -> None:
        if self.store is not None and hasattr(self.store, "save_collection_attempt"):
            self.store.save_collection_attempt(attempt)

    def execute(self, source: Any, callable: Callable[..., Any], retry_policy: RetryPolicy | Mapping[str, Any] | None = None) -> Any:
        policy = RetryPolicy.from_value(retry_policy)
        source_id, task_id, _ = self._source_values(source)
        run_id = f"collection-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        run = CollectionRunRecord(run_id, task_id, source_id, datetime.now(timezone.utc).isoformat())
        self.last_run, self.last_attempts = run, run.attempts
        last_error: BaseException | None = None
        for number in range(1, policy.max_attempts + 1):
            attempt = CollectionAttempt(run_id, number, datetime.now(timezone.utc).isoformat())
            run.attempts.append(attempt)
            try:
                result = self._invoke(callable, source)
            except BaseException as error:  # collection boundaries must preserve all failures
                last_error = error
                attempt.status = "FAILED"
                attempt.error_code = classify_collection_error(error)
                attempt.error_message = sanitize_error_message(error)
                attempt.finished_at = datetime.now(timezone.utc).isoformat()
                run.error_count += 1
                self._persist_attempt(attempt)
                retryable = attempt.error_code not in policy.non_retryable_error_codes
                if policy.retryable_error_codes is not None:
                    retryable = attempt.error_code in policy.retryable_error_codes
                if not retryable or number >= policy.max_attempts:
                    break
                delay = policy.wait_seconds * (policy.backoff ** (number - 1))
                if delay:
                    self.sleep(delay)
                continue
            attempt.status = "SUCCESS"
            attempt.finished_at = datetime.now(timezone.utc).isoformat()
            run.status = "SUCCESS"
            run.finished_at = attempt.finished_at
            run.object_count = len(getattr(result, "objects", result)) if isinstance(getattr(result, "objects", result), (list, tuple, dict, set)) else 0
            run.warning_count = len(getattr(result, "warnings", []) or [])
            self._persist_attempt(attempt)
            if self.store is not None and hasattr(self.store, "save_collection_run"):
                self.store.save_collection_run(run)
            return result
        run.status = "FAILED"
        run.finished_at = datetime.now(timezone.utc).isoformat()
        if self.store is not None and hasattr(self.store, "save_collection_run"):
            self.store.save_collection_run(run)
        raise CollectionExecutionError(last_error or RuntimeError("collection failed"), run)


__all__ = [
    "CollectionAttempt", "CollectionExecutionError", "CollectionExecutor", "CollectionRunRecord",
    "ErrorCode", "RetryPolicy", "classify_collection_error", "sanitize_error_message",
]

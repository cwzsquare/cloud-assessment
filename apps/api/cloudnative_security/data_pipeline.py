"""Small, dependency-free execution engine for assessment data processing.

The pipeline deliberately stores only counters and diagnostic metadata in run
records.  Step callables may return arbitrary application data, but that data
is passed to the next callable in memory and is not copied into a run record.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sized
from dataclasses import dataclass, field
import inspect
from time import perf_counter
from typing import Any, TypeAlias

from .data_contracts import (
    FAILED,
    PARTIAL,
    PENDING,
    RUNNING,
    SKIPPED,
    SUCCESS,
    ProcessingRun,
    ProcessingStepRun,
    utc_now,
)


StepCallable: TypeAlias = Callable[[Any], Any]


@dataclass(frozen=True)
class PipelineStepDefinition:
    """Catalog metadata; a definition has no executable fake implementation."""

    name: str
    description: str = ""
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }


# Alias kept descriptive for callers that prefer the shorter term.
StepDefinition = PipelineStepDefinition


_DEFAULT_STEP_DEFINITIONS: tuple[PipelineStepDefinition, ...] = (
    PipelineStepDefinition("collect", "Collect source observations"),
    PipelineStepDefinition("validate", "Validate source and payload shape"),
    PipelineStepDefinition("parse", "Parse source-specific records"),
    PipelineStepDefinition("normalize", "Normalize fields to the common model"),
    PipelineStepDefinition("deduplicate", "Remove duplicate observations"),
    PipelineStepDefinition("redact", "Redact sensitive values before persistence"),
    PipelineStepDefinition("enrich", "Attach asset and source context"),
    PipelineStepDefinition("quality", "Calculate evidence quality metrics"),
    PipelineStepDefinition("classify", "Classify observations and findings"),
    PipelineStepDefinition("evaluate", "Evaluate configured security rules"),
    PipelineStepDefinition("aggregate", "Aggregate findings and metrics"),
    PipelineStepDefinition("score", "Calculate scores and priorities"),
    PipelineStepDefinition("render", "Build report-ready output"),
    PipelineStepDefinition("persist", "Persist normalized results"),
)


def default_step_catalog() -> list[PipelineStepDefinition]:
    """Return the standard 14-step catalog without assigning fake callables."""

    return list(_DEFAULT_STEP_DEFINITIONS)


def default_14_step_catalog() -> list[PipelineStepDefinition]:
    """Explicitly named alias for :func:`default_step_catalog`."""

    return default_step_catalog()


def build_default_catalog() -> list[PipelineStepDefinition]:
    """Compatibility alias useful to an orchestrator factory."""

    return default_step_catalog()


def _count(value: Any) -> int:
    """Count records without consuming iterators or inspecting payloads."""

    if value is None:
        return 0
    if isinstance(value, (str, bytes, bytearray)):
        return 1
    if isinstance(value, Sized):
        try:
            return max(0, len(value))
        except (TypeError, ValueError):
            pass
    return 1


def _as_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return [str(value)]


@dataclass
class _StepExecution:
    record: ProcessingStepRun
    output: Any


@dataclass
class DataPipeline:
    """Execute named steps while preserving an isolated record per step.

    ``steps`` can be a mapping of names to one-argument callables.  Definitions
    from the default catalog are still visible in ``catalog`` and become
    SKIPPED records when no implementation is registered; the catalog itself
    never performs pretend work.
    """

    steps: dict[str, StepCallable] = field(default_factory=dict)
    catalog: list[PipelineStepDefinition] = field(default_factory=default_step_catalog)
    last_run: ProcessingRun | None = field(default=None, init=False, repr=False)
    _active_run: ProcessingRun | None = field(default=None, init=False, repr=False)

    def __init__(
        self,
        steps: Mapping[str, StepCallable] | Iterable[tuple[str, StepCallable]] | None = None,
        *,
        catalog: Iterable[PipelineStepDefinition | str] | None = None,
    ) -> None:
        self.steps = {}
        self.catalog = self._coerce_catalog(catalog)
        self.last_run = None
        self._active_run = None
        if steps is not None:
            entries = steps.items() if isinstance(steps, Mapping) else steps
            for name, function in entries:
                self.register(name, function)

    @staticmethod
    def _coerce_catalog(
        catalog: Iterable[PipelineStepDefinition | str] | None,
    ) -> list[PipelineStepDefinition]:
        if catalog is None:
            return default_step_catalog()
        return [item if isinstance(item, PipelineStepDefinition) else PipelineStepDefinition(str(item)) for item in catalog]

    def register(self, name: str, function: StepCallable) -> "DataPipeline":
        """Register a named implementation and return this pipeline."""

        if not name or not isinstance(name, str):
            raise ValueError("step name must be a non-empty string")
        if not callable(function):
            raise TypeError(f"step {name!r} must be callable")
        self.steps[name] = function
        if not any(item.name == name for item in self.catalog):
            self.catalog.append(PipelineStepDefinition(name))
        return self

    add_step = register

    def run(
        self,
        input_data: Any = None,
        *,
        context: Any = None,
        steps: Iterable[str | tuple[str, StepCallable]] | None = None,
        collection_run_id: str | None = None,
    ) -> ProcessingRun:
        """Run named steps in order and return a JSON-friendly run contract.

        A raised exception marks only its step FAILED.  The previous output is
        retained as the next step's input, allowing later independent steps to
        run and making a middle-step failure PARTIAL rather than losing the
        completed history.
        """

        run = ProcessingRun(collection_run_id=collection_run_id, status=RUNNING)
        run.input_count = _count(input_data)
        self._active_run = run
        self.last_run = run
        current = input_data

        selected = list(steps) if steps is not None else list(self.steps)
        if steps is None and not selected:
            selected = [item.name for item in self.catalog]

        temporary: dict[str, StepCallable] = {}
        for item in selected:
            if isinstance(item, tuple):
                name, function = item
                if not callable(function):
                    raise TypeError(f"step {name!r} must be callable")
                temporary[name] = function

        for item in selected:
            name = item[0] if isinstance(item, tuple) else item
            function = temporary.get(name, self.steps.get(name))
            execution = self._execute(name, function, current, context=context)
            self.record_step(execution.record, run=run)
            if execution.record.status in {SUCCESS, PARTIAL}:
                current = execution.output

        run.output_count = _count(current)
        run.drop_count = sum(step.drop_count for step in run.steps)
        run.warnings = [warning for step in run.steps for warning in step.warnings]
        run.errors = [error for step in run.steps for error in step.errors]
        run.summary = {
            "step_count": len(run.steps),
            "success_count": sum(step.status == SUCCESS for step in run.steps),
            "partial_count": sum(step.status == PARTIAL for step in run.steps),
            "failed_count": sum(step.status == FAILED for step in run.steps),
            "skipped_count": sum(step.status == SKIPPED for step in run.steps),
        }
        statuses = [step.status for step in run.steps]
        if not statuses or all(status == SKIPPED for status in statuses):
            run.status = SKIPPED
        elif any(status == FAILED for status in statuses):
            run.status = PARTIAL if any(status in {SUCCESS, PARTIAL} for status in statuses) else FAILED
        elif any(status == PARTIAL for status in statuses):
            run.status = PARTIAL
        else:
            run.status = SUCCESS
        run.completed_at = utc_now()
        self._active_run = None
        return run

    def run_step(
        self,
        name: str,
        step: StepCallable | Any = None,
        input_data: Any = None,
        *,
        data: Any = None,
        context: Any = None,
        run: ProcessingRun | None = None,
    ) -> ProcessingStepRun:
        """Execute one named step and return its record.

        For convenience, ``step`` may be a callable (``run_step(name, fn,
        data)``), or omitted when the name was registered.  Exceptions are
        captured in the returned record rather than escaping.
        """

        function: StepCallable | None
        if callable(step):
            function = step
        else:
            function = self.steps.get(name)
            if input_data is None and step is not None:
                input_data = step
        if data is not None:
            input_data = data
        execution = self._execute(name, function, input_data, context=context)
        target = run or self._active_run
        if target is not None:
            self.record_step(execution.record, run=target)
        return execution.record

    def _execute(self, name: str, function: StepCallable | None, input_data: Any, *, context: Any = None) -> _StepExecution:
        started = utc_now()
        start_clock = perf_counter()
        input_count = _count(input_data)
        if function is None:
            record = ProcessingStepRun(
                step_id=name,
                step_name=name,
                status=SKIPPED,
                started_at=started,
                completed_at=utc_now(),
                input_count=input_count,
                summary={"reason": "no callable registered"},
            )
            record.duration_ms = round((perf_counter() - start_clock) * 1000, 3)
            return _StepExecution(record, input_data)
        try:
            # One-argument functions are the stable public contract.  A
            # two-argument callable can opt into context without executing
            # user code twice when that code itself raises TypeError.
            try:
                signature = inspect.signature(function)
                positional = [
                    parameter
                    for parameter in signature.parameters.values()
                    if parameter.kind
                    in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                accepts_varargs = any(
                    parameter.kind == inspect.Parameter.VAR_POSITIONAL
                    for parameter in signature.parameters.values()
                )
            except (TypeError, ValueError):
                positional, accepts_varargs = [], False
            if accepts_varargs or len(positional) >= 2:
                result = function(input_data, context)  # type: ignore[misc]
            else:
                result = function(input_data)
            output, warnings, errors, drop_count, summary, status = self._unpack_result(result, input_count)
            output_count = _count(output)
            if drop_count is None:
                drop_count = max(0, input_count - output_count)
            record = ProcessingStepRun(
                step_id=name,
                step_name=name,
                status=status,
                started_at=started,
                completed_at=utc_now(),
                input_count=input_count,
                output_count=output_count,
                drop_count=drop_count,
                warnings=warnings,
                errors=errors,
                summary=summary,
            )
            record.duration_ms = round((perf_counter() - start_clock) * 1000, 3)
            return _StepExecution(record, output)
        except Exception as exc:  # per-step isolation is intentional
            record = ProcessingStepRun(
                step_id=name,
                step_name=name,
                status=FAILED,
                started_at=started,
                completed_at=utc_now(),
                input_count=input_count,
                output_count=0,
                errors=[f"{type(exc).__name__}: {exc}"],
                summary={"exception_type": type(exc).__name__},
            )
            record.duration_ms = round((perf_counter() - start_clock) * 1000, 3)
            return _StepExecution(record, input_data)

    @staticmethod
    def _unpack_result(result: Any, input_count: int) -> tuple[Any, list[str], list[str], int | None, dict[str, Any], str]:
        """Accept a plain output or an optional reserved-key outcome mapping."""

        warnings: list[str] = []
        errors: list[str] = []
        drop_count: int | None = None
        summary: dict[str, Any] = {}
        status = SUCCESS
        output = result
        if isinstance(result, Mapping) and any(key in result for key in ("output", "warnings", "errors", "drop_count", "status", "summary")):
            output = result.get("output", result.get("data"))
            warnings = _as_text_list(result.get("warnings"))
            errors = _as_text_list(result.get("errors"))
            if result.get("drop_count") is not None:
                drop_count = max(0, int(result["drop_count"]))
            if isinstance(result.get("summary"), Mapping):
                summary = dict(result["summary"])
            elif result.get("summary") is not None:
                summary = {"detail": result["summary"]}
            candidate = str(result.get("status", SUCCESS)).upper()
            status = candidate if candidate in {SUCCESS, PARTIAL, FAILED, SKIPPED} else SUCCESS
        if errors and status == SUCCESS:
            status = PARTIAL
        summary.setdefault("input_count", input_count)
        return output, warnings, errors, drop_count, summary, status

    def record_step(
        self,
        step: ProcessingStepRun | str | None = None,
        *,
        run: ProcessingRun | None = None,
        name: str | None = None,
        status: str = SUCCESS,
        input_count: int = 0,
        output_count: int = 0,
        drop_count: int = 0,
        warnings: Iterable[Any] | None = None,
        errors: Iterable[Any] | None = None,
        duration_ms: float = 0.0,
        summary: Mapping[str, Any] | None = None,
        input: int | None = None,
        output: int | None = None,
        drop: int | None = None,
        warning: Any = None,
        error: Any = None,
        duration: float | None = None,
    ) -> ProcessingStepRun:
        """Record a completed step, either from a contract or keyword fields.

        Singular aliases (``input``, ``output``, ``drop``, ``warning``,
        ``error``, ``duration``) keep this method convenient for adapters that
        already expose compact metric names.
        """

        if isinstance(step, str):
            name, step = step, None
        if input is not None:
            input_count = input
        if output is not None:
            output_count = output
        if drop is not None:
            drop_count = drop
        if warning is not None:
            warnings = [warning] if warnings is None else [*warnings, warning]
        if error is not None:
            errors = [error] if errors is None else [*errors, error]
        if duration is not None:
            duration_ms = duration
        if step is None:
            step = ProcessingStepRun(
                step_id=name or "",
                step_name=name or "",
                status=status.upper(),  # type: ignore[arg-type]
                completed_at=utc_now(),
                input_count=max(0, input_count),
                output_count=max(0, output_count),
                drop_count=max(0, drop_count),
                warnings=_as_text_list(warnings),
                errors=_as_text_list(errors),
                duration_ms=max(0.0, duration_ms),
                summary=dict(summary or {}),
            )
        target = run or self._active_run
        if target is not None and step not in target.steps:
            target.steps.append(step)
        return step


__all__ = [
    "DataPipeline",
    "PipelineStepDefinition",
    "StepCallable",
    "StepDefinition",
    "build_default_catalog",
    "default_14_step_catalog",
    "default_step_catalog",
]

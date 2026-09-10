from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from .checkpoints import ASSESSMENT_CHECKPOINTS
from .models import AssessmentReport, Checkpoint, CheckpointScore, Finding, FindingStatus, utc_now


NON_SCORING_STATUSES = {"UNKNOWN", "NOT_APPLICABLE"}
CRITICAL_CHECKPOINTS = {"CN-22", "CN-29", "CN-35"}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
STATUS_RANK = {"FAIL": 4, "WARN": 2, "UNKNOWN": 1, "PASS": 0, "NOT_APPLICABLE": 0}


def _checkpoint_value(checkpoint: Checkpoint | Mapping[str, Any], name: str, default: Any = None) -> Any:
    if isinstance(checkpoint, Mapping):
        return checkpoint.get(name, default)
    return getattr(checkpoint, name, default)


def checkpoint_is_enabled(checkpoint: Checkpoint | Mapping[str, Any]) -> bool:
    return bool(_checkpoint_value(checkpoint, "enabled", True))


def _rule_is_enabled(finding: Finding, checkpoint: Checkpoint | Mapping[str, Any]) -> bool:
    rule_enabled = _checkpoint_value(checkpoint, "rule_enabled", {})
    if rule_enabled is False:
        return False
    rule_enabled = rule_enabled or {}
    if not isinstance(rule_enabled, Mapping):
        return True
    if finding.rule_id in rule_enabled:
        return bool(rule_enabled[finding.rule_id])
    group = str(_checkpoint_value(checkpoint, "rule_group", "") or "")
    if group and group in rule_enabled:
        return bool(rule_enabled[group])
    for key, enabled in rule_enabled.items():
        key_str = str(key)
        if key_str and finding.rule_id.startswith(f"{key_str}-"):
            return bool(enabled)
    return True


def _finding_is_applicable(
    finding: Finding,
    applicability: Mapping[str, Any] | bool | None,
    target_context: Mapping[str, Any] | None = None,
) -> bool:
    if applicability is False:
        return False
    if not isinstance(applicability, Mapping):
        return True
    scope_value = applicability.get("scope", "all")
    if scope_value is False:
        return False
    scope = str(scope_value).lower()
    if scope in {"false", "disabled", "none", "not_applicable", "not-applicable", "n/a"}:
        return False

    # Explicit target constraints are evaluated against the supplied context
    # when available; absent context remains UNKNOWN rather than guessed N/A.
    context = target_context or {}
    for key in ("target_id", "target_ids"):
        expected = applicability.get(key)
        if expected is None or not context:
            continue
        expected_values = {str(expected)} if not isinstance(expected, (list, tuple, set)) else {str(item) for item in expected}
        if str(context.get("target_id", "")) not in expected_values:
            return False

    asset = finding.asset
    include_cluster_scoped = bool(applicability.get("include_cluster_scoped", True))
    if not asset and not include_cluster_scoped:
        return False
    if asset and asset.namespace is None and not include_cluster_scoped:
        return False

    namespaces = applicability.get("namespaces")
    if namespaces:
        namespace_set = {str(item) for item in namespaces}
        if asset and asset.namespace is not None and asset.namespace not in namespace_set:
            return False

    kinds = applicability.get("kinds")
    if kinds:
        kind_set = {str(item).lower() for item in kinds}
        if not asset or asset.kind.lower() not in kind_set:
            return False

    tools = applicability.get("tools")
    if tools and finding.tool_id not in {str(item) for item in tools}:
        return False

    statuses = applicability.get("statuses")
    if statuses and finding.status not in {str(item) for item in statuses}:
        return False

    severities = applicability.get("severities")
    if severities and finding.severity not in {str(item) for item in severities}:
        return False

    return True


def checkpoint_is_explicitly_not_applicable(
    checkpoint: Checkpoint | Mapping[str, Any],
    target_context: Mapping[str, Any] | None = None,
) -> bool:
    applicability = _checkpoint_value(checkpoint, "applicability", None)
    if applicability is False:
        return True
    if not isinstance(applicability, Mapping):
        return False
    for key in ("applicable", "enabled", "is_applicable"):
        if applicability.get(key) is False:
            return True
    scope_value = applicability.get("scope", "all")
    if scope_value is False:
        return True
    scope = str(scope_value).lower()
    if scope in {"false", "disabled", "none", "not_applicable", "not-applicable", "n/a"}:
        return True
    context = target_context or {}
    for key in ("target_id", "target_ids"):
        expected = applicability.get(key)
        if expected is None or not context:
            continue
        expected_values = {str(expected)} if not isinstance(expected, (list, tuple, set)) else {str(item) for item in expected}
        if str(context.get("target_id", "")) not in expected_values:
            return True
    return False


def effective_findings_for_checkpoint(
    checkpoint: Checkpoint | Mapping[str, Any],
    findings: Iterable[Finding],
    target_context: Mapping[str, Any] | None = None,
) -> list[Finding]:
    """Return the one effective finding set used by filtering and scoring."""
    if not checkpoint_is_enabled(checkpoint):
        return []
    applicability = _checkpoint_value(checkpoint, "applicability", None)
    checkpoint_id = str(_checkpoint_value(checkpoint, "id", ""))
    return [
        finding
        for finding in findings
        if finding.checkpoint_id == checkpoint_id
        and _rule_is_enabled(finding, checkpoint)
        and _finding_is_applicable(finding, applicability, target_context)
    ]




def checkpoint_status(findings: list[Finding], score: float, checkpoint_id: str) -> FindingStatus:
    scored = [finding for finding in findings if finding.status not in NON_SCORING_STATUSES]
    if not scored:
        return "UNKNOWN"
    if any(finding.status == "FAIL" and finding.severity in {"critical", "high"} for finding in scored):
        return "FAIL"
    if checkpoint_id in CRITICAL_CHECKPOINTS and any(finding.status == "FAIL" for finding in scored):
        return "FAIL"
    if score >= 85:
        return "PASS"
    if score >= 60:
        return "WARN"
    return "FAIL"


def status_score(status: FindingStatus) -> float:
    return {"PASS": 1.0, "WARN": 0.5, "FAIL": 0.0, "UNKNOWN": 0.0, "NOT_APPLICABLE": 1.0}[status]


def checkpoint_numeric_score(findings: list[Finding]) -> tuple[float | None, int]:
    scored = [finding for finding in findings if finding.status not in NON_SCORING_STATUSES]
    if not scored:
        return None, 0
    return round(sum(finding.score for finding in scored) / len(scored) * 100, 2), len(scored)


def remediation_priority(findings: list[Finding], limit: int = 25) -> list[dict[str, Any]]:
    candidates = [
        finding
        for finding in findings
        if finding.status in {"FAIL", "WARN", "UNKNOWN"} and finding.status != "NOT_APPLICABLE"
    ]

    rows: list[dict[str, Any]] = []
    for finding in candidates:
        severity_score = SEVERITY_RANK.get(finding.severity, 1)
        status_score_value = STATUS_RANK.get(finding.status, 0)
        critical_checkpoint_bonus = 3 if finding.checkpoint_id in CRITICAL_CHECKPOINTS else 0
        risk_score = severity_score * status_score_value + critical_checkpoint_bonus
        if finding.status == "UNKNOWN":
            risk_score = max(1, severity_score)
        priority = "P0" if risk_score >= 19 else "P1" if risk_score >= 13 else "P2" if risk_score >= 7 else "P3"
        if finding.status == "UNKNOWN":
            priority = "P3"
        asset_key = "_cluster"
        if finding.asset:
            namespace = finding.asset.namespace or "_cluster"
            asset_key = f"{finding.asset.kind}/{namespace}/{finding.asset.name}"
        rows.append(
            {
                "priority": priority,
                "risk_score": risk_score,
                "checkpoint_id": finding.checkpoint_id,
                "rule_id": finding.rule_id,
                "tool_id": finding.tool_id,
                "title": finding.title,
                "status": finding.status,
                "severity": finding.severity,
                "asset": asset_key,
                "remediation": finding.remediation,
                "reason": _priority_reason(finding, priority),
            }
        )
    return sorted(rows, key=lambda row: (-int(row["risk_score"]), str(row["checkpoint_id"]), str(row["rule_id"])))[:limit]


def _priority_reason(finding: Finding, priority: str) -> str:
    if finding.status == "UNKNOWN":
        return f"{priority}: 证据不可见或采集不足，需要补充 {finding.checkpoint_id} 取证源"
    if finding.status == "FAIL":
        return f"{priority}: {finding.severity} 失败项影响 {finding.checkpoint_id} 符合度"
    return f"{priority}: {finding.severity} 弱项建议纳入整改计划"


def build_report(
    task_id: str,
    findings: list[Finding],
    checkpoints: Iterable[Checkpoint | Mapping[str, Any]] | None = None,
    target_context: Mapping[str, Any] | None = None,
) -> AssessmentReport:
    selected_checkpoints = [
        checkpoint
        for checkpoint in (checkpoints or ASSESSMENT_CHECKPOINTS)
        if checkpoint_is_enabled(checkpoint)
    ]
    effective_by_checkpoint: dict[str, list[Finding]] = {}
    effective_ids: set[int] = set()
    for checkpoint in selected_checkpoints:
        checkpoint_id = str(_checkpoint_value(checkpoint, "id", ""))
        effective = effective_findings_for_checkpoint(checkpoint, findings, target_context)
        effective_by_checkpoint[checkpoint_id] = effective
        effective_ids.update(id(finding) for finding in effective)
    effective_findings = [finding for finding in findings if id(finding) in effective_ids]

    checkpoint_scores: list[CheckpointScore] = []
    weighted_total = 0.0
    weight_sum = 0.0
    unknown_weight = 0.0
    for checkpoint in selected_checkpoints:
        checkpoint_id = str(_checkpoint_value(checkpoint, "id", ""))
        checkpoint_findings = effective_by_checkpoint.get(checkpoint_id, [])
        name = str(_checkpoint_value(checkpoint, "name", checkpoint_id))
        domain = str(_checkpoint_value(checkpoint, "domain", ""))
        weight = float(_checkpoint_value(checkpoint, "weight", 0.0))
        if checkpoint_is_explicitly_not_applicable(checkpoint, target_context):
            status: FindingStatus = "NOT_APPLICABLE"
            score = 0.0
        else:
            numeric_score, _ = checkpoint_numeric_score(checkpoint_findings)
            if numeric_score is None:
                # A rule-disabled or evidence-missing checkpoint remains UNKNOWN;
                # only an explicit applicability false becomes N/A.
                status = "NOT_APPLICABLE" if checkpoint_findings and all(
                    finding.status == "NOT_APPLICABLE" for finding in checkpoint_findings
                ) else "UNKNOWN"
                score = 0.0
                if status == "UNKNOWN":
                    unknown_weight += weight
            else:
                score = numeric_score
                status = checkpoint_status(checkpoint_findings, score, checkpoint_id)
                weighted_total += score * weight
                weight_sum += weight
        checkpoint_scores.append(
            CheckpointScore(
                checkpoint_id=checkpoint_id,
                name=name,
                domain=domain,
                weight=weight,
                status=status,
                score=score,
                finding_count=len(checkpoint_findings),
                failed_count=sum(1 for item in checkpoint_findings if item.status == "FAIL"),
                warn_count=sum(1 for item in checkpoint_findings if item.status == "WARN"),
                unknown_count=sum(1 for item in checkpoint_findings if item.status == "UNKNOWN"),
            )
        )

    severity_count: dict[str, int] = defaultdict(int)
    status_count: dict[str, int] = defaultdict(int)
    domain_scores: dict[str, list[float]] = defaultdict(list)
    domain_unknown_count: dict[str, int] = defaultdict(int)
    for finding in effective_findings:
        severity_count[finding.severity] += 1
        status_count[finding.status] += 1
    for score in checkpoint_scores:
        if score.status == "UNKNOWN":
            domain_unknown_count[score.domain] += 1
        elif score.status != "NOT_APPLICABLE":
            domain_scores[score.domain].append(score.score)

    overall_score = round(weighted_total / weight_sum, 2) if weight_sum else 0.0
    evidence_coverage = round(weight_sum / (weight_sum + unknown_weight) * 100, 2) if (weight_sum + unknown_weight) else 0.0
    critical_fail_count = sum(1 for finding in effective_findings if finding.status == "FAIL" and finding.severity == "critical")
    high_fail_count = sum(1 for finding in effective_findings if finding.status == "FAIL" and finding.severity == "high")
    if critical_fail_count:
        conclusion = "不符合，存在 critical 必检失败项"
    elif high_fail_count >= 3:
        conclusion = "不符合，存在多个 high 风险失败项"
    elif evidence_coverage < 70:
        conclusion = "证据不足"
    elif overall_score >= 85:
        conclusion = "符合"
    elif overall_score >= 70:
        conclusion = "基本符合"
    else:
        conclusion = "不符合"

    summary: dict[str, Any] = {
        "overall_score": overall_score,
        "conclusion": conclusion,
        "checkpoint_total": len(selected_checkpoints),
        "finding_total": len(effective_findings),
        "evidence_coverage": evidence_coverage,
        "scored_weight": round(weight_sum, 2),
        "unknown_weight": round(unknown_weight, 2),
        "critical_fail_count": critical_fail_count,
        "high_fail_count": high_fail_count,
        "severity_count": dict(sorted(severity_count.items())),
        "status_count": dict(sorted(status_count.items())),
        "remediation_priority": remediation_priority(effective_findings),
        "by_domain": [
            {
                "domain": domain,
                "score": round(sum(values) / len(values), 2) if values else 0.0,
                "scored_checkpoint_count": len(values),
                "unknown_checkpoint_count": domain_unknown_count.get(domain, 0),
            }
            for domain, values in sorted(domain_scores.items())
        ],
    }
    return AssessmentReport("1.0", task_id, utc_now(), summary, checkpoint_scores, effective_findings)

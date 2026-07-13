from __future__ import annotations

from collections import defaultdict
from typing import Any

from .checkpoints import ASSESSMENT_CHECKPOINTS
from .models import AssessmentReport, Checkpoint, CheckpointScore, Finding, FindingStatus, utc_now


NON_SCORING_STATUSES = {"UNKNOWN", "NOT_APPLICABLE"}
CRITICAL_CHECKPOINTS = {"CN-22", "CN-29", "CN-35"}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
STATUS_RANK = {"FAIL": 4, "WARN": 2, "UNKNOWN": 1, "PASS": 0, "NOT_APPLICABLE": 0}


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


def build_report(task_id: str, findings: list[Finding], checkpoints: list[Checkpoint] | None = None) -> AssessmentReport:
    selected_checkpoints = checkpoints or ASSESSMENT_CHECKPOINTS
    by_checkpoint: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_checkpoint[finding.checkpoint_id].append(finding)

    checkpoint_scores: list[CheckpointScore] = []
    weighted_total = 0.0
    weight_sum = 0.0
    unknown_weight = 0.0
    for checkpoint in selected_checkpoints:
        checkpoint_findings = by_checkpoint.get(checkpoint.id, [])
        numeric_score, scored_rule_count = checkpoint_numeric_score(checkpoint_findings)
        if numeric_score is None:
            status = "UNKNOWN"
            score = 0.0
            unknown_weight += checkpoint.weight
        else:
            score = numeric_score
            status = checkpoint_status(checkpoint_findings, score, checkpoint.id)
            weighted_total += score * checkpoint.weight
            weight_sum += checkpoint.weight
        checkpoint_scores.append(
            CheckpointScore(
                checkpoint_id=checkpoint.id,
                name=checkpoint.name,
                domain=checkpoint.domain,
                weight=checkpoint.weight,
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
    for finding in findings:
        severity_count[finding.severity] += 1
        status_count[finding.status] += 1
    for score in checkpoint_scores:
        if score.status == "UNKNOWN":
            domain_unknown_count[score.domain] += 1
        else:
            domain_scores[score.domain].append(score.score)

    overall_score = round(weighted_total / weight_sum, 2) if weight_sum else 0.0
    evidence_coverage = round(weight_sum / (weight_sum + unknown_weight) * 100, 2) if (weight_sum + unknown_weight) else 0.0
    critical_fail_count = sum(1 for finding in findings if finding.status == "FAIL" and finding.severity == "critical")
    high_fail_count = sum(1 for finding in findings if finding.status == "FAIL" and finding.severity == "high")
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
        "finding_total": len(findings),
        "evidence_coverage": evidence_coverage,
        "scored_weight": round(weight_sum, 2),
        "unknown_weight": round(unknown_weight, 2),
        "critical_fail_count": critical_fail_count,
        "high_fail_count": high_fail_count,
        "severity_count": dict(sorted(severity_count.items())),
        "status_count": dict(sorted(status_count.items())),
        "remediation_priority": remediation_priority(findings),
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
    return AssessmentReport("1.0", task_id, utc_now(), summary, checkpoint_scores, findings)

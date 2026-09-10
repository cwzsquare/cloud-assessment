from __future__ import annotations

from dataclasses import asdict, is_dataclass
from html import escape as html_escape
from pathlib import Path
from typing import Any


CLOUD_NATIVE_DOMAINS = [
    "不可变基础设施与弹性安全评估",
    "动态访问控制与身份安全评估",
    "容器持久化安全评估",
]
INTEGRATION_DOMAINS = ["工具集成数据处理"]
VISUALIZATION_DOMAINS = ["集成可视化展示"]


def report_to_dict(report: Any) -> dict[str, Any]:
    if report is None:
        return {}
    if isinstance(report, dict):
        if "report" in report and isinstance(report["report"], dict):
            payload = dict(report["report"])
            # OrchestratorResult.to_dict() keeps the full structured payload
            # beside the report; retain it for the structured report chapter.
            for key in ("structured", "structured_analysis"):
                if key in report and key not in payload:
                    payload[key] = report[key]
            return payload
        return report
    if hasattr(report, "to_dict"):
        payload = report.to_dict()
        if isinstance(payload, dict) and isinstance(payload.get("report"), dict):
            inner = dict(payload["report"])
            for key in ("structured", "structured_analysis"):
                if key in payload and key not in inner:
                    inner[key] = payload[key]
            return inner
        return payload
    if is_dataclass(report):
        return asdict(report)
    raise TypeError(f"unsupported report type: {type(report)!r}")


def render_markdown_report(report: Any) -> str:
    data = report_to_dict(report)
    if not data:
        return "# Report not found\n"

    summary = _dict(data.get("summary"))
    lines = [
        "# 云原生安全评估报告",
        "",
        "## 1. 评估摘要",
        "",
        f"- Task ID: `{data.get('task_id', '')}`",
        f"- Generated At: `{data.get('generated_at', '')}`",
        f"- Tools: `{', '.join(_tool_ids(summary.get('tools'))) or 'unknown'}`",
        f"- Overall Score: `{summary.get('overall_score', '')}`",
        f"- Conclusion: **{summary.get('conclusion', '')}**",
        f"- Evidence Coverage: `{summary.get('evidence_coverage', '')}%`",
        f"- Severity Count: `{_inline_json(summary.get('severity_count'))}`",
        "",
        "### 工具聚合摘要",
        "",
        *_markdown_tool_summary(summary),
        "",
        "## 2. 标书检查点覆盖情况",
        "",
    ]
    lines.extend(_markdown_matrix("云原生三大域", data, CLOUD_NATIVE_DOMAINS))
    lines.extend(_markdown_matrix("工具集成数据处理", data, INTEGRATION_DOMAINS))
    lines.extend(_markdown_matrix("集成可视化展示", data, VISUALIZATION_DOMAINS))

    lines.extend(["", "## 3. 云原生安全评估结果", ""])
    for domain in CLOUD_NATIVE_DOMAINS:
        lines.extend(_markdown_domain_result(domain, data))

    lines.extend(["", "## 4. 重点风险清单", ""])
    key_risks = _key_risks(data)
    if not key_risks:
        lines.append("- 未发现 Critical/High 失败项。")
    for finding in key_risks[:50]:
        lines.extend(_markdown_finding(finding))

    lines.extend(["", "### 整改优先级", ""])
    lines.extend(_markdown_remediation_priority(summary))

    lines.extend(["", "## 5. 指标赋权与符合度判定", ""])
    lines.append(
        f"- 计分口径: UNKNOWN 检查点不计入得分分母；Critical/High 失败项会触发符合度门禁。"
    )
    lines.append(f"- Scored Weight: `{summary.get('scored_weight', '')}`")
    lines.append(f"- Unknown Weight: `{summary.get('unknown_weight', '')}`")
    lines.append("")
    lines.extend(_markdown_matrix("权重与状态", data, None))

    lines.extend(["", "## 6. 数据质量与限制", ""])
    lines.extend(_markdown_data_quality(summary, data))
    lines.extend(["", "## 7. 数据处理与质量", ""])
    lines.extend(_markdown_structured_quality(data, _structured_payload(data)))
    lines.extend(["", "## 8. 身份认证画像", ""])
    lines.extend(_markdown_authentication(_structured_payload(data)))
    lines.extend(["", "### RBAC 身份汇总", ""])
    lines.extend(_markdown_identity(_structured_payload(data)))
    lines.extend(["", "## 9. 服务账号令牌摘要", ""])
    lines.extend(_markdown_service_account_tokens(_structured_payload(data)))
    lines.extend(["", "## 10. 证书状态", ""])
    lines.extend(_markdown_certificates(_structured_payload(data)))
    lines.extend(["", "## 11. etcd 节点安全", ""])
    lines.extend(_markdown_etcd(_structured_payload(data)))
    lines.extend(["", "## 12. 静态加密配置", ""])
    lines.extend(_markdown_encryption(_structured_payload(data)))
    lines.extend(["", "## 13. 配置一致性", ""])
    lines.extend(_markdown_consistency(_structured_payload(data)))

    lines.extend(["", "## 14. 附录", ""])
    lines.append(f"- Schema Version: `{data.get('schema_version', '')}`")
    data_quality = _dict(summary.get("data_quality"))
    lines.append(f"- Raw Snapshot Count: `{data_quality.get('raw_snapshot_count', '')}`")
    lines.append(f"- Normalized Finding Count: `{data_quality.get('normalized_finding_count', '')}`")
    refs = _references(data)
    if refs:
        lines.append("- References:")
        lines.extend(f"  - {ref}" for ref in refs[:100])
    else:
        lines.append("- References: 当前报告未采集到外部引用。")
    return "\n".join(lines) + "\n"


def render_html_report(report: Any) -> str:
    data = report_to_dict(report)
    if not data:
        return "<!doctype html><html><body><h1>Report not found</h1></body></html>\n"
    summary = _dict(data.get("summary"))
    structured = _structured_payload(data)
    key_risks = _key_risks(data)
    references = _references(data)
    html = [
        "<!doctype html>",
        '<html lang="zh-CN">',
        "<head>",
        '<meta charset="utf-8" />',
        '<meta name="viewport" content="width=device-width, initial-scale=1" />',
        f"<title>云原生安全评估报告 - {_h(data.get('task_id', ''))}</title>",
        "<style>",
        _html_css(),
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<h1>云原生安全评估报告</h1>",
        '<section class="summary">',
        "<h2>1. 评估摘要</h2>",
        "<dl>",
        _dl("Task ID", data.get("task_id")),
        _dl("Generated At", data.get("generated_at")),
        _dl("Tools", ", ".join(_tool_ids(summary.get("tools"))) or "unknown"),
        _dl("Overall Score", summary.get("overall_score")),
        _dl("Conclusion", summary.get("conclusion")),
        _dl("Evidence Coverage", f"{summary.get('evidence_coverage', '')}%"),
        _dl("Severity Count", _inline_json(summary.get("severity_count"))),
        "</dl>",
        "<h3>工具聚合摘要</h3>",
        _html_tool_summary(summary),
        "</section>",
        "<section><h2>2. 标书检查点覆盖情况</h2>",
        _html_matrix("云原生三大域", data, CLOUD_NATIVE_DOMAINS),
        _html_matrix("工具集成数据处理", data, INTEGRATION_DOMAINS),
        _html_matrix("集成可视化展示", data, VISUALIZATION_DOMAINS),
        "</section>",
        "<section><h2>3. 云原生安全评估结果</h2>",
    ]
    for domain in CLOUD_NATIVE_DOMAINS:
        html.append(_html_domain_result(domain, data))
    html.extend(["</section>", "<section><h2>4. 重点风险清单</h2>"])
    if key_risks:
        html.append("<ol>")
        html.extend(_html_finding(finding) for finding in key_risks[:50])
        html.append("</ol>")
    else:
        html.append("<p>未发现 Critical/High 失败项。</p>")
    html.extend(["<h3>整改优先级</h3>", _html_remediation_priority(summary)])
    html.extend(
        [
            "</section>",
            "<section><h2>5. 指标赋权与符合度判定</h2>",
            "<p>计分口径: UNKNOWN 检查点不计入得分分母；Critical/High 失败项会触发符合度门禁。</p>",
            "<ul>",
            f"<li>Scored Weight: <code>{_h(summary.get('scored_weight', ''))}</code></li>",
            f"<li>Unknown Weight: <code>{_h(summary.get('unknown_weight', ''))}</code></li>",
            "</ul>",
            _html_matrix("权重与状态", data, None),
            "</section>",
            "<section><h2>6. 数据质量与限制</h2>",
            _html_data_quality(summary, data),
            "</section>",
            '<section><h2>7. 数据处理与质量</h2>',
            _html_structured_quality(data, structured),
            "</section>",
            '<section><h2>8. 身份认证画像</h2>',
            _html_authentication(structured),
            "<h3>RBAC 身份汇总</h3>",
            _html_identity(structured),
            '<section><h2>9. 服务账号令牌摘要</h2>',
            _html_service_account_tokens(structured),
            "</section>",
            '<section><h2>10. 证书状态</h2>',
            _html_certificates(structured),
            "</section>",
            '<section><h2>11. etcd 节点安全</h2>',
            _html_etcd(structured),
            "</section>",
            '<section><h2>12. 静态加密配置</h2>',
            _html_encryption(structured),
            "</section>",
            '<section><h2>13. 配置一致性</h2>',
            _html_consistency(structured),
            "</section>",
            "<section><h2>14. 附录</h2>",
            "<ul>",
            f"<li>Schema Version: <code>{_h(data.get('schema_version', ''))}</code></li>",
            f"<li>Raw Snapshot Count: <code>{_h(_dict(summary.get('data_quality')).get('raw_snapshot_count', ''))}</code></li>",
            f"<li>Normalized Finding Count: <code>{_h(_dict(summary.get('data_quality')).get('normalized_finding_count', ''))}</code></li>",
            "</ul>",
        ]
    )
    if references:
        html.append("<h3>References</h3><ul>")
        html.extend(f"<li>{_h(ref)}</li>" for ref in references[:100])
        html.append("</ul>")
    else:
        html.append("<p>References: 当前报告未采集到外部引用。</p>")
    html.extend(["</section>", "</main>", "</body>", "</html>"])
    return "\n".join(html) + "\n"


def write_markdown_report(report: Any, path: str | Path) -> None:
    _write_text(path, render_markdown_report(report))


def write_html_report(report: Any, path: str | Path) -> None:
    _write_text(path, render_html_report(report))


def _write_text(path: str | Path, text: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
_SENSITIVE_MARKERS = (
    "token",
    "secret",
    "password",
    "private_key",
    "private-key",
    "private key",
    "key_data",
    "key-data",
    "key data",
)


def _structured_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Collect structured data without requiring a full OrchestratorResult."""
    summary = _dict(report.get("summary"))
    candidates = [
        report.get("structured"),
        report.get("structured_analysis"),
        summary.get("structured"),
        summary.get("structured_analysis"),
    ]
    merged: dict[str, Any] = {}
    for candidate in candidates:
        candidate_dict = _dict(candidate)
        for key, value in candidate_dict.items():
            if key not in merged:
                merged[key] = value
            elif isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = {**merged[key], **value}
            elif isinstance(value, (dict, list)) and not merged[key]:
                merged[key] = value
    return merged


def _value(mapping: dict[str, Any], key: str, default: str = "UNKNOWN") -> Any:
    value = mapping.get(key)
    return default if value is None or value == "" else value


def _count(mapping: dict[str, Any], key: str, fallback: Any = "UNKNOWN") -> Any:
    if key in mapping:
        value = mapping[key]
        if isinstance(value, list):
            return len(value)
        return 0 if value is None else value
    return fallback


def _profiles(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [_dict(item) for item in value if _dict(item)]
    item = _dict(value)
    if not item:
        return []
    for key in ("profiles", "items", "results", "nodes"):
        if isinstance(item.get(key), list):
            return [_dict(row) for row in item[key] if _dict(row)]
    return [item]


def _status_counts(items: list[dict[str, Any]]) -> str:
    if not items:
        return "UNKNOWN"
    counts: dict[str, int] = {}
    for item in items:
        status = str(_value(item, "status")).upper()
        counts[status] = counts.get(status, 0) + 1
    return ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))


def _bool_counts(items: list[dict[str, Any]], key: str) -> str:
    known = [item.get(key) for item in items if item.get(key) is not None]
    if not known:
        return "UNKNOWN"
    true_count = sum(value is True for value in known)
    false_count = sum(value is False for value in known)
    return f"启用={true_count}, 未启用={false_count}"


def _bool_value(value: Any) -> str:
    if value is True:
        return "启用"
    if value is False:
        return "未启用"
    return "UNKNOWN"


def _safe_issue(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if any(marker in text.lower() for marker in _SENSITIVE_MARKERS):
        return "敏感内容已脱敏"
    return text[:300]


def _issues(items: list[dict[str, Any]], keys: tuple[str, ...] = ("reasons", "errors", "issues")) -> list[str]:
    result: list[str] = []
    for item in items:
        for key in keys:
            values = item.get(key)
            if not isinstance(values, list):
                values = [values] if values else []
            for value in values:
                issue = _safe_issue(value)
                if issue and issue not in result:
                    result.append(issue)
    return result[:20]


def _issue_lines(issues: list[str], prefix: str = "异常项") -> list[str]:
    if not issues:
        return [f"- {prefix}: 暂无证据"]
    return [f"- {prefix}:"] + [f"  - {issue}" for issue in issues]


def _markdown_structured_quality(report: dict[str, Any], structured: dict[str, Any]) -> list[str]:
    summary = _dict(report.get("summary"))
    quality = _dict(structured.get("quality_summary")) or _dict(summary.get("data_quality"))
    processing = _dict(structured.get("processing_run"))
    counts = _dict(structured.get("module_counts"))
    source_rows = _profiles(structured.get("sources"))
    collection_rows = _profiles(structured.get("collection_runs"))
    conflicts = _list(structured.get("data_conflicts"))
    cleaning = _list(structured.get("cleaning_actions"))
    warnings = _list(structured.get("data_quality_results"))
    lines = [
        f"- 处理状态: `{_value(processing, 'status')}`",
        f"- 数据完整性: `{_value(quality, 'completeness')}%`",
        f"- 数据新鲜度: `{_value(quality, 'freshness')}%`",
        f"- 重复率: `{_value(quality, 'duplicate_rate')}%`",
        f"- UNKNOWN 比例: `{_value(quality, 'unknown_rate')}%`",
        f"- 原始快照/规范化 finding: `{_value(quality, 'raw_snapshot_count', _value(counts, 'objects'))}` / `{_value(quality, 'normalized_finding_count', _value(counts, 'findings'))}`",
        f"- 来源/采集运行: `{len(source_rows) if source_rows else _value(counts, 'sources')}` / `{len(collection_rows) if collection_rows else _value(counts, 'collection_runs')}`",
        f"- 质量结果/数据冲突/清洗动作: `{len(warnings) if warnings else _value(counts, 'quality_results')}` / `{len(conflicts) if 'data_conflicts' in structured else 'UNKNOWN'}` / `{len(cleaning) if 'cleaning_actions' in structured else 'UNKNOWN'}`",
        f"- Schema 错误/采集警告: `{_value(quality, 'schema_error_count')}` / `{_value(quality, 'collection_warning_count')}`",
    ]
    processing_issues = _issues([processing]) if processing else []
    return lines + _issue_lines(processing_issues, "处理异常")


def _markdown_authentication(structured: dict[str, Any]) -> list[str]:
    profile = _dict(structured.get("authentication"))
    nested = [_dict(profile.get(key)) for key in ("oidc", "webhook", "front_proxy") if _dict(profile.get(key))]
    issues = _issues([profile, *nested])
    return [
        f"- 状态: `{_value(profile, 'status')}`",
        f"- 证据: `{_bool_value(profile.get('evidence_present')) if 'evidence_present' in profile else '暂无证据'}`",
        f"- 匿名访问: `{_bool_value(profile.get('anonymous_auth'))}`",
        f"- 匿名授权状态: `{_value(profile, 'anonymous_authorization_status')}`",
        f"- OIDC/Webhook/Front Proxy: `{_value(_dict(profile.get('oidc')), 'status')}` / `{_value(_dict(profile.get('webhook')), 'status')}` / `{_value(_dict(profile.get('front_proxy')), 'status')}`",
        "- 安全摘要: 仅呈现认证机制状态和安全布尔值，不输出认证配置原文。",
        *_issue_lines(issues),
    ]


def _markdown_identity(structured: dict[str, Any]) -> list[str]:
    profiles = _profiles(structured.get("identities"))
    dangerous = sum(item.get("dangerous") is True for item in profiles)
    broad = sum(item.get("broad") is True for item in profiles)
    return [
        f"- 身份数量: `{len(profiles) if 'identities' in structured else 'UNKNOWN'}`",
        f"- 状态分布: `{_status_counts(profiles)}`",
        f"- 高风险/宽权限身份: `{dangerous}` / `{broad}`" if profiles else "- 高风险/宽权限身份: `UNKNOWN` / `UNKNOWN`",
        f"- 异常身份数: `{sum(item.get('dangerous') is True or item.get('broad') is True for item in profiles) if profiles else 'UNKNOWN'}`",
        "- 安全摘要: 仅汇总身份风险标记、状态和权限异常，不输出主体权限明细。",
        *_issue_lines(_issues(profiles)),
    ]


def _markdown_service_account_tokens(structured: dict[str, Any]) -> list[str]:
    profiles = _profiles(structured.get("service_account_tokens"))
    expiration_bad = sum(item.get("expiration_ok") is False for item in profiles)
    audience_bad = sum(item.get("audience_ok") is False for item in profiles)
    alignment = [item for item in profiles if item.get("api_permission_alignment") is not None]
    return [
        f"- 工作负载数量: `{len(profiles) if 'service_account_tokens' in structured else 'UNKNOWN'}`",
        f"- 状态分布: `{_status_counts(profiles)}`",
        f"- 有效自动挂载/Projected Token: `{_bool_counts(profiles, 'effective_automount')}` / `{_bool_counts(profiles, 'projected_token')}`",
        f"- 过期策略/受众异常: `{expiration_bad if profiles else 'UNKNOWN'}` / `{audience_bad if profiles else 'UNKNOWN'}`",
        f"- API 权限对齐状态: `{_status_counts([{'status': item.get('api_permission_alignment')} for item in alignment]) if alignment else 'UNKNOWN'}`",
        "- 安全摘要: 仅呈现令牌生命周期、挂载和权限对齐统计，不输出令牌值或服务账号原文。",
        *_issue_lines(_issues(profiles)),
    ]


def _markdown_certificates(structured: dict[str, Any]) -> list[str]:
    profiles = _profiles(structured.get("certificates"))
    expired = sum(item.get("expired") is True for item in profiles)
    expiring = sum(isinstance(item.get("days_until_expiry"), (int, float)) and item["days_until_expiry"] <= 30 for item in profiles)
    return [
        f"- 证书数量: `{len(profiles) if 'certificates' in structured else 'UNKNOWN'}`",
        f"- 状态分布: `{_status_counts(profiles)}`",
        f"- 已过期/30 日内到期: `{expired if profiles else 'UNKNOWN'}` / `{expiring if profiles else 'UNKNOWN'}`",
        f"- 解析错误数: `{sum(bool(item.get('error')) for item in profiles) if profiles else 'UNKNOWN'}`",
        "- 安全摘要: 仅展示证书状态、有效期风险和解析结果，不输出私钥或证书原文。",
        *_issue_lines(_issues(profiles, ("error", "reasons", "errors"))),
    ]


def _markdown_etcd(structured: dict[str, Any]) -> list[str]:
    profiles = _profiles(structured.get("etcd"))
    clients = [_dict(item.get("client")) for item in profiles]
    peers = [_dict(item.get("peer")) for item in profiles]
    apiserver = _profiles(structured.get("apiserver_etcd"))
    return [
        f"- etcd 节点数量: `{len(profiles) if 'etcd' in structured else 'UNKNOWN'}`",
        f"- 节点状态分布: `{_status_counts(profiles)}`",
        f"- 客户端/Peer TLS: `{_bool_counts(clients, 'tls')}` / `{_bool_counts(peers, 'tls')}`",
        f"- 客户端证书认证: `{_bool_counts(clients, 'client_cert_auth')}` / `{_bool_counts(peers, 'client_cert_auth')}`",
        f"- apiserver-etcd 客户端状态: `{_status_counts(apiserver)}`",
        "- 安全摘要: 仅呈现节点传输安全和证书认证开关，不输出证书、私钥路径或端点详情。",
        *_issue_lines(_issues(profiles)),
    ]


def _markdown_encryption(structured: dict[str, Any]) -> list[str]:
    profiles = _profiles(structured.get("encryption"))
    rules = sum(len(_list(item.get("rules"))) for item in profiles)
    providers = []
    for item in profiles:
        providers.extend(str(value) for value in _list(item.get("provider_order")) if value)
    return [
        f"- 配置数量: `{len(profiles) if 'encryption' in structured else 'UNKNOWN'}`",
        f"- 状态分布: `{_status_counts(profiles)}`",
        f"- 资源规则/KMS 提供方: `{rules if profiles else 'UNKNOWN'}` / `{sum(len(_list(item.get('kms_providers'))) for item in profiles) if profiles else 'UNKNOWN'}`",
        f"- Provider 类型摘要: `{', '.join(sorted(set(providers))) if providers else '暂无证据'}`",
        "- 安全摘要: 仅呈现 provider 类型、规则数量和状态，不输出 key、key data 或配置原文。",
        *_issue_lines(_issues(profiles)),
    ]


def _markdown_consistency(structured: dict[str, Any]) -> list[str]:
    profile = _dict(structured.get("config_consistency"))
    issues = _issues([profile], ("issues", "errors", "reasons"))
    return [
        f"- 一致性状态: `{_value(profile, 'status')}`",
        f"- 比较节点数: `{_value(profile, 'node_count')}`",
        f"- 比较字段: `{', '.join(str(item) for item in _list(profile.get('compared_fields'))) or '暂无证据'}`",
        "- 安全摘要: 一致性检查聚焦 etcd 节点传输和客户端证书认证策略。",
        *_issue_lines(issues),
    ]


def _html_list(items: list[tuple[str, Any]]) -> str:
    body = "".join(f"<li>{_h(label)}: <code>{_h(value)}</code></li>" for label, value in items)
    return f"<ul>{body}</ul>"


def _html_issues(issues: list[str], label: str = "异常项") -> str:
    if not issues:
        return f"<p>{_h(label)}: 暂无证据</p>"
    return f"<h3>{_h(label)}</h3><ul>{''.join(f'<li>{_h(issue)}</li>' for issue in issues)}</ul>"


def _html_structured_quality(report: dict[str, Any], structured: dict[str, Any]) -> str:
    lines = _markdown_structured_quality(report, structured)
    return "<ul>" + "".join(f"<li>{_h(line[2:])}</li>" for line in lines if line.startswith("- ")) + "</ul>"


def _html_authentication(structured: dict[str, Any]) -> str:
    profile = _dict(structured.get("authentication"))
    nested = [_dict(profile.get(key)) for key in ("oidc", "webhook", "front_proxy") if _dict(profile.get(key))]
    return _html_list([
        ("状态", _value(profile, "status")),
        ("证据", _bool_value(profile.get("evidence_present")) if "evidence_present" in profile else "暂无证据"),
        ("匿名访问", _bool_value(profile.get("anonymous_auth"))),
        ("匿名授权状态", _value(profile, "anonymous_authorization_status")),
        ("OIDC/Webhook/Front Proxy", " / ".join(_value(_dict(profile.get(key)), "status") for key in ("oidc", "webhook", "front_proxy"))),
    ]) + "<p>安全摘要: 仅呈现认证机制状态和安全布尔值，不输出认证配置原文。</p>" + _html_issues(_issues([profile, *nested]))


def _html_identity(structured: dict[str, Any]) -> str:
    profiles = _profiles(structured.get("identities"))
    dangerous = sum(item.get("dangerous") is True for item in profiles)
    broad = sum(item.get("broad") is True for item in profiles)
    return _html_list([
        ("身份数量", len(profiles) if "identities" in structured else "UNKNOWN"),
        ("状态分布", _status_counts(profiles)),
        ("高风险/宽权限身份", f"{dangerous} / {broad}" if profiles else "UNKNOWN / UNKNOWN"),
        ("异常身份数", sum(item.get("dangerous") is True or item.get("broad") is True for item in profiles) if profiles else "UNKNOWN"),
    ]) + "<p>安全摘要: 仅汇总身份风险标记、状态和权限异常，不输出主体权限明细。</p>" + _html_issues(_issues(profiles))


def _html_service_account_tokens(structured: dict[str, Any]) -> str:
    profiles = _profiles(structured.get("service_account_tokens"))
    expiration_bad = sum(item.get("expiration_ok") is False for item in profiles)
    audience_bad = sum(item.get("audience_ok") is False for item in profiles)
    return _html_list([
        ("工作负载数量", len(profiles) if "service_account_tokens" in structured else "UNKNOWN"),
        ("状态分布", _status_counts(profiles)),
        ("有效自动挂载/Projected Token", f"{_bool_counts(profiles, 'effective_automount')} / {_bool_counts(profiles, 'projected_token')}"),
        ("过期策略/受众异常", f"{expiration_bad if profiles else 'UNKNOWN'} / {audience_bad if profiles else 'UNKNOWN'}"),
    ]) + "<p>安全摘要: 仅呈现令牌生命周期、挂载和权限对齐统计，不输出令牌值或服务账号原文。</p>" + _html_issues(_issues(profiles))


def _html_certificates(structured: dict[str, Any]) -> str:
    profiles = _profiles(structured.get("certificates"))
    expired = sum(item.get("expired") is True for item in profiles)
    expiring = sum(isinstance(item.get("days_until_expiry"), (int, float)) and item["days_until_expiry"] <= 30 for item in profiles)
    return _html_list([
        ("证书数量", len(profiles) if "certificates" in structured else "UNKNOWN"),
        ("状态分布", _status_counts(profiles)),
        ("已过期/30 日内到期", f"{expired if profiles else 'UNKNOWN'} / {expiring if profiles else 'UNKNOWN'}"),
        ("解析错误数", sum(bool(item.get("error")) for item in profiles) if profiles else "UNKNOWN"),
    ]) + "<p>安全摘要: 仅展示证书状态、有效期风险和解析结果，不输出私钥或证书原文。</p>" + _html_issues(_issues(profiles, ("error", "reasons", "errors")))


def _html_etcd(structured: dict[str, Any]) -> str:
    profiles = _profiles(structured.get("etcd"))
    clients = [_dict(item.get("client")) for item in profiles]
    peers = [_dict(item.get("peer")) for item in profiles]
    apiserver = _profiles(structured.get("apiserver_etcd"))
    return _html_list([
        ("etcd 节点数量", len(profiles) if "etcd" in structured else "UNKNOWN"),
        ("节点状态分布", _status_counts(profiles)),
        ("客户端/Peer TLS", f"{_bool_counts(clients, 'tls')} / {_bool_counts(peers, 'tls')}"),
        ("客户端证书认证", f"{_bool_counts(clients, 'client_cert_auth')} / {_bool_counts(peers, 'client_cert_auth')}"),
        ("apiserver-etcd 客户端状态", _status_counts(apiserver)),
    ]) + "<p>安全摘要: 仅呈现节点传输安全和证书认证开关，不输出证书、私钥路径或端点详情。</p>" + _html_issues(_issues(profiles))


def _html_encryption(structured: dict[str, Any]) -> str:
    profiles = _profiles(structured.get("encryption"))
    rules = sum(len(_list(item.get("rules"))) for item in profiles)
    providers = [str(value) for item in profiles for value in _list(item.get("provider_order")) if value]
    return _html_list([
        ("配置数量", len(profiles) if "encryption" in structured else "UNKNOWN"),
        ("状态分布", _status_counts(profiles)),
        ("资源规则/KMS 提供方", f"{rules if profiles else 'UNKNOWN'} / {sum(len(_list(item.get('kms_providers'))) for item in profiles) if profiles else 'UNKNOWN'}"),
        ("Provider 类型摘要", ", ".join(sorted(set(providers))) if providers else "暂无证据"),
    ]) + "<p>安全摘要: 仅呈现 provider 类型、规则数量和状态，不输出 key、key data 或配置原文。</p>" + _html_issues(_issues(profiles))


def _html_consistency(structured: dict[str, Any]) -> str:
    profile = _dict(structured.get("config_consistency"))
    issues = _issues([profile], ("issues", "errors", "reasons"))
    return _html_list([
        ("一致性状态", _value(profile, "status")),
        ("比较节点数", _value(profile, "node_count")),
        ("比较字段", ", ".join(str(item) for item in _list(profile.get("compared_fields"))) or "暂无证据"),
    ]) + "<p>安全摘要: 一致性检查聚焦 etcd 节点传输和客户端证书认证策略。</p>" + _html_issues(issues)



def _markdown_matrix(title: str, report: dict[str, Any], domains: list[str] | None) -> list[str]:
    rows = _checkpoint_rows(report, domains)
    lines = [
        f"### {title}",
        "",
        "| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    if not rows:
        lines.append("| _none_ |  |  |  |  |  |  |")
        return lines
    for score in rows:
        lines.append(
            f"| {score.get('checkpoint_id')} {score.get('name')} | {score.get('domain')} | {score.get('weight')} | {score.get('status')} | {score.get('score')} | {score.get('finding_count')} | {score.get('failed_count')}/{score.get('warn_count')}/{score.get('unknown_count')} |"
        )
    return lines


def _markdown_domain_result(domain: str, report: dict[str, Any]) -> list[str]:
    domain_summary = _domain_summary(report, domain)
    lines = [
        f"### {domain}",
        "",
        f"- Domain Score: `{domain_summary.get('score', 'N/A')}`",
        f"- Scored Checkpoints: `{domain_summary.get('scored_checkpoint_count', 0)}`",
        f"- Unknown Checkpoints: `{domain_summary.get('unknown_checkpoint_count', 0)}`",
        "",
    ]
    risks = [finding for finding in _findings(report) if _dict(finding).get("checkpoint_id") in _domain_checkpoint_ids(report, domain)]
    if risks:
        for finding in sorted(risks, key=_finding_sort_key)[:10]:
            lines.extend(_markdown_finding(finding))
    else:
        lines.append("- 当前域未生成 finding。")
    return lines


def _markdown_tool_summary(summary: dict[str, Any]) -> list[str]:
    rows = [_dict(item) for item in _list(summary.get("tool_summary"))]
    lines = [
        "| Tool | Status | Schema | Findings | Fail/Warn/Unknown | Warnings | Raw Keys |",
        "|---|---|---|---:|---|---:|---|",
    ]
    if not rows:
        lines.append("| _none_ |  |  |  |  |  |  |")
        return lines
    for row in rows:
        fail_warn_unknown = f"{row.get('fail_count', 0)}/{row.get('warn_count', 0)}/{row.get('unknown_count', 0)}"
        raw_keys = ", ".join(str(item) for item in _list(row.get("summary_keys"))[:8])
        status = f"{row.get('status', 'ready')}{' (stub/mock)' if row.get('stub_mode') else ''}"
        lines.append(
            f"| {row.get('tool_id')} | {status} | {row.get('schema_version')} | {row.get('finding_count')} | {fail_warn_unknown} | {row.get('warning_count')} | {raw_keys} |"
        )
    return lines


def _markdown_remediation_priority(summary: dict[str, Any]) -> list[str]:
    rows = [_dict(item) for item in _list(summary.get("remediation_priority"))]
    lines = [
        "| Priority | Score | Checkpoint | Rule | Severity/Status | Asset | Remediation |",
        "|---|---:|---|---|---|---|---|",
    ]
    if not rows:
        lines.append("| _none_ |  |  |  |  |  |  |")
        return lines
    for row in rows[:20]:
        lines.append(
            f"| {row.get('priority')} | {row.get('risk_score')} | {row.get('checkpoint_id')} | {row.get('rule_id')} | {row.get('severity')}/{row.get('status')} | {row.get('asset')} | {row.get('remediation')} |"
        )
    return lines


def _markdown_finding(finding: dict[str, Any]) -> list[str]:
    asset = _asset_key(_dict(finding.get("asset")))
    evidence = _list(finding.get("evidence"))
    lines = [
        f"- **{finding.get('status')} {finding.get('severity')}** `{finding.get('checkpoint_id')}` `{finding.get('rule_id')}` {finding.get('title')} ({asset})",
    ]
    if evidence:
        first = _dict(evidence[0])
        lines.append(f"  - Evidence: {first.get('summary')}")
    lines.append(f"  - Remediation: {finding.get('remediation')}")
    return lines


def _markdown_data_quality(summary: dict[str, Any], report: dict[str, Any]) -> list[str]:
    data_quality = _dict(summary.get("data_quality"))
    lines = [
        f"- Completeness: `{data_quality.get('completeness', '')}%`",
        f"- Freshness: `{data_quality.get('freshness', '')}%`",
        f"- Duplicate Rate: `{data_quality.get('duplicate_rate', '')}%`",
        f"- Unknown Rate: `{data_quality.get('unknown_rate', '')}%`",
        f"- Schema Errors: `{data_quality.get('schema_error_count', '')}`",
        f"- Collection Warnings: `{data_quality.get('collection_warning_count', '')}`",
    ]
    unknowns = [finding for finding in _findings(report) if _dict(finding).get("status") == "UNKNOWN"]
    if unknowns:
        lines.append("- UNKNOWN 原因样例:")
        for finding in unknowns[:20]:
            evidence = _list(_dict(finding).get("evidence"))
            reason = _dict(evidence[0]).get("summary") if evidence else _dict(finding).get("title")
            lines.append(f"  - `{_dict(finding).get('checkpoint_id')}` {reason}")
    else:
        lines.append("- UNKNOWN 原因样例: 无。")
    lines.append("- 限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。")
    return lines


def _html_matrix(title: str, report: dict[str, Any], domains: list[str] | None) -> str:
    rows = _checkpoint_rows(report, domains)
    body = []
    for score in rows:
        body.append(
            "<tr>"
            f"<td><code>{_h(score.get('checkpoint_id'))}</code> {_h(score.get('name'))}</td>"
            f"<td>{_h(score.get('domain'))}</td>"
            f"<td>{_h(score.get('weight'))}</td>"
            f"<td><span class=\"status {_h(str(score.get('status', '')).lower())}\">{_h(score.get('status'))}</span></td>"
            f"<td>{_h(score.get('score'))}</td>"
            f"<td>{_h(score.get('finding_count'))}</td>"
            f"<td>{_h(score.get('failed_count'))}/{_h(score.get('warn_count'))}/{_h(score.get('unknown_count'))}</td>"
            "</tr>"
        )
    if not body:
        body.append('<tr><td colspan="7">暂无检查点</td></tr>')
    return (
        f"<h3>{_h(title)}</h3>"
        "<table><thead><tr><th>Checkpoint</th><th>Domain</th><th>Weight</th><th>Status</th><th>Score</th><th>Findings</th><th>Fail/Warn/Unknown</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _html_domain_result(domain: str, report: dict[str, Any]) -> str:
    domain_summary = _domain_summary(report, domain)
    parts = [
        f"<h3>{_h(domain)}</h3>",
        "<ul>",
        f"<li>Domain Score: <code>{_h(domain_summary.get('score', 'N/A'))}</code></li>",
        f"<li>Scored Checkpoints: <code>{_h(domain_summary.get('scored_checkpoint_count', 0))}</code></li>",
        f"<li>Unknown Checkpoints: <code>{_h(domain_summary.get('unknown_checkpoint_count', 0))}</code></li>",
        "</ul>",
    ]
    risks = [finding for finding in _findings(report) if _dict(finding).get("checkpoint_id") in _domain_checkpoint_ids(report, domain)]
    if risks:
        parts.append("<ol>")
        parts.extend(_html_finding(finding) for finding in sorted(risks, key=_finding_sort_key)[:10])
        parts.append("</ol>")
    else:
        parts.append("<p>当前域未生成 finding。</p>")
    return "".join(parts)


def _html_tool_summary(summary: dict[str, Any]) -> str:
    rows = [_dict(item) for item in _list(summary.get("tool_summary"))]
    body = []
    for row in rows:
        fail_warn_unknown = f"{row.get('fail_count', 0)}/{row.get('warn_count', 0)}/{row.get('unknown_count', 0)}"
        raw_keys = ", ".join(str(item) for item in _list(row.get("summary_keys"))[:8])
        status = f"{row.get('status', 'ready')}{' (stub/mock)' if row.get('stub_mode') else ''}"
        body.append(
            "<tr>"
            f"<td><code>{_h(row.get('tool_id'))}</code></td>"
            f"<td>{_h(status)}</td>"
            f"<td>{_h(row.get('schema_version'))}</td>"
            f"<td>{_h(row.get('finding_count'))}</td>"
            f"<td>{_h(fail_warn_unknown)}</td>"
            f"<td>{_h(row.get('warning_count'))}</td>"
            f"<td>{_h(raw_keys)}</td>"
            "</tr>"
        )
    if not body:
        body.append('<tr><td colspan="7">暂无工具摘要</td></tr>')
    return (
        "<table><thead><tr><th>Tool</th><th>Status</th><th>Schema</th><th>Findings</th><th>Fail/Warn/Unknown</th><th>Warnings</th><th>Raw Keys</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _html_remediation_priority(summary: dict[str, Any]) -> str:
    rows = [_dict(item) for item in _list(summary.get("remediation_priority"))]
    body = []
    for row in rows[:20]:
        body.append(
            "<tr>"
            f"<td><strong>{_h(row.get('priority'))}</strong></td>"
            f"<td>{_h(row.get('risk_score'))}</td>"
            f"<td><code>{_h(row.get('checkpoint_id'))}</code></td>"
            f"<td><code>{_h(row.get('rule_id'))}</code></td>"
            f"<td>{_h(row.get('severity'))}/{_h(row.get('status'))}</td>"
            f"<td>{_h(row.get('asset'))}</td>"
            f"<td>{_h(row.get('remediation'))}</td>"
            "</tr>"
        )
    if not body:
        body.append('<tr><td colspan="7">暂无整改优先级</td></tr>')
    return (
        "<table><thead><tr><th>Priority</th><th>Score</th><th>Checkpoint</th><th>Rule</th><th>Severity/Status</th><th>Asset</th><th>Remediation</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _html_finding(finding: dict[str, Any]) -> str:
    finding = _dict(finding)
    evidence = _list(finding.get("evidence"))
    evidence_text = _dict(evidence[0]).get("summary") if evidence else ""
    return (
        "<li>"
        f"<strong>{_h(finding.get('status'))} {_h(finding.get('severity'))}</strong> "
        f"<code>{_h(finding.get('checkpoint_id'))}</code> <code>{_h(finding.get('rule_id'))}</code> "
        f"{_h(finding.get('title'))} <span class=\"asset\">{_h(_asset_key(_dict(finding.get('asset'))))}</span>"
        f"<p>Evidence: {_h(evidence_text)}</p>"
        f"<p>Remediation: {_h(finding.get('remediation'))}</p>"
        "</li>"
    )


def _html_data_quality(summary: dict[str, Any], report: dict[str, Any]) -> str:
    data_quality = _dict(summary.get("data_quality"))
    unknowns = [finding for finding in _findings(report) if _dict(finding).get("status") == "UNKNOWN"]
    parts = [
        "<ul>",
        f"<li>Completeness: <code>{_h(data_quality.get('completeness', ''))}%</code></li>",
        f"<li>Freshness: <code>{_h(data_quality.get('freshness', ''))}%</code></li>",
        f"<li>Duplicate Rate: <code>{_h(data_quality.get('duplicate_rate', ''))}%</code></li>",
        f"<li>Unknown Rate: <code>{_h(data_quality.get('unknown_rate', ''))}%</code></li>",
        f"<li>Schema Errors: <code>{_h(data_quality.get('schema_error_count', ''))}</code></li>",
        f"<li>Collection Warnings: <code>{_h(data_quality.get('collection_warning_count', ''))}</code></li>",
        "</ul>",
    ]
    if unknowns:
        parts.append("<h3>UNKNOWN 原因样例</h3><ul>")
        for finding in unknowns[:20]:
            evidence = _list(_dict(finding).get("evidence"))
            reason = _dict(evidence[0]).get("summary") if evidence else _dict(finding).get("title")
            parts.append(f"<li><code>{_h(_dict(finding).get('checkpoint_id'))}</code> {_h(reason)}</li>")
        parts.append("</ul>")
    else:
        parts.append("<p>UNKNOWN 原因样例: 无。</p>")
    parts.append("<p>限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。</p>")
    return "".join(parts)


def _checkpoint_rows(report: dict[str, Any], domains: list[str] | None) -> list[dict[str, Any]]:
    rows = [_dict(item) for item in _list(report.get("checkpoint_scores"))]
    if domains is None:
        return rows
    domain_set = set(domains)
    return [row for row in rows if row.get("domain") in domain_set]


def _domain_checkpoint_ids(report: dict[str, Any], domain: str) -> set[str]:
    return {str(row.get("checkpoint_id")) for row in _checkpoint_rows(report, [domain])}


def _domain_summary(report: dict[str, Any], domain: str) -> dict[str, Any]:
    for item in _list(_dict(report.get("summary")).get("by_domain")):
        row = _dict(item)
        if row.get("domain") == domain:
            return row
    return {}


def _key_risks(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        finding
        for finding in sorted((_dict(item) for item in _findings(report)), key=_finding_sort_key)
        if finding.get("status") == "FAIL" and finding.get("severity") in {"critical", "high"}
    ]


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [_dict(item) for item in _list(report.get("findings"))]


def _references(report: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for finding in _findings(report):
        for ref in _list(finding.get("references")):
            ref_text = str(ref)
            if ref_text and ref_text not in seen:
                seen.add(ref_text)
                refs.append(ref_text)
    return refs


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, str]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    status_rank = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "PASS": 3, "NOT_APPLICABLE": 4}
    return (
        severity_rank.get(str(finding.get("severity")), 9),
        status_rank.get(str(finding.get("status")), 9),
        str(finding.get("checkpoint_id", "")),
    )


def _asset_key(asset: dict[str, Any]) -> str:
    if not asset:
        return "_cluster"
    namespace = asset.get("namespace") or "_cluster"
    return f"{asset.get('kind', '_cluster')}/{namespace}/{asset.get('name', '')}"


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    return {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _tool_ids(value: Any) -> list[str]:
    ids: list[str] = []
    for item in _list(value):
        if isinstance(item, dict):
            tool_id = item.get("tool_id") or item.get("id") or item.get("name")
            if tool_id:
                ids.append(str(tool_id))
        else:
            ids.append(str(item))
    return ids


def _inline_json(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items())
    return str(value or "")


def _h(value: Any) -> str:
    return html_escape(str(value if value is not None else ""))


def _dl(key: str, value: Any) -> str:
    return f"<dt>{_h(key)}</dt><dd>{_h(value)}</dd>"


def _html_css() -> str:
    return """
:root { color-scheme: light; --text: #1f2937; --muted: #667085; --line: #d0d5dd; --bg: #f8fafc; --accent: #0f766e; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.55; }
main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 56px; }
h1 { margin: 0 0 24px; font-size: 32px; }
h2 { margin: 32px 0 14px; padding-top: 18px; border-top: 2px solid var(--line); font-size: 22px; }
h3 { margin: 22px 0 10px; font-size: 17px; }
section { margin-bottom: 24px; }
dl { display: grid; grid-template-columns: 180px 1fr; gap: 8px 18px; margin: 0; }
dt { color: var(--muted); font-weight: 600; }
dd { margin: 0; }
table { width: 100%; border-collapse: collapse; margin: 10px 0 20px; background: #fff; }
th, td { border: 1px solid var(--line); padding: 8px 10px; text-align: left; vertical-align: top; font-size: 13px; }
th { background: #eef2f6; }
code { padding: 1px 4px; background: #eef2f6; border-radius: 4px; }
.status.fail { color: #b42318; font-weight: 700; }
.status.warn, .status.unknown { color: #b54708; font-weight: 700; }
.status.pass { color: #047857; font-weight: 700; }
.asset { color: var(--muted); }
li { margin: 8px 0; }
p { margin: 6px 0; }
@media print { body { background: #fff; } main { max-width: none; padding: 0; } a { color: inherit; } }
""".strip()

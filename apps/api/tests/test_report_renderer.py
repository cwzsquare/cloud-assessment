from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudnative_security.adapters import AssessmentRequest
from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.report_renderer import render_html_report, render_markdown_report, write_html_report, write_markdown_report


class ReportRendererTest(unittest.TestCase):
    def setUp(self) -> None:
        request = AssessmentRequest(
            task_id="renderer-test",
            profile="all_tools_demo",
            manifest="ops/cnsec-lab/manifests",
        )
        self.report = AssessmentOrchestrator().run(request).report

    def test_markdown_and_html_include_required_sections(self) -> None:
        markdown = render_markdown_report(self.report)
        html = render_html_report(self.report)
        sections = [
            "评估摘要",
            "标书检查点覆盖情况",
            "云原生安全评估结果",
            "重点风险清单",
            "指标赋权与符合度判定",
            "数据质量与限制",
            "附录",
        ]
        for section in sections:
            self.assertIn(section, markdown)
            self.assertIn(section, html)
        self.assertIn("工具聚合摘要", markdown)
        self.assertIn("cloud_native", markdown)
        self.assertIn("stub (stub/mock)", markdown)
        self.assertIn("工具聚合摘要", html)
        self.assertIn("stub (stub/mock)", html)
        self.assertIn("<dt>Tools</dt><dd>cloud_api_stub, cloud_native, registry_stub, smart_cloud_stub, platform</dd>", html)
        self.assertIn("整改优先级", markdown)
        self.assertIn("整改优先级", html)
        self.assertIn("UNKNOWN 原因样例", markdown)
        self.assertIn("<!doctype html>", html)
    def test_structured_sections_are_summary_only_and_redacted(self) -> None:
        report = {
            "task_id": "structured-renderer-test",
            "summary": {
                "structured_analysis": {
                    "quality_summary": {"completeness": 80, "collection_warning_count": 1},
                    "authentication": {
                        "status": "WARN",
                        "evidence_present": True,
                        "anonymous_auth": False,
                        "reasons": ["plain-secret-token must never be shown"],
                    },
                    "identities": [{"status": "WARN", "dangerous": True}],
                    "service_account_tokens": [
                        {"status": "FAIL", "effective_automount": True, "reasons": ["private-key-data omitted"]},
                    ],
                    "certificates": [{"status": "PASS", "expired": False, "days_until_expiry": 90}],
                    "etcd": [
                        {
                            "status": "PASS",
                            "client": {"tls": True, "client_cert_auth": True},
                            "peer": {"tls": True, "client_cert_auth": True},
                        }
                    ],
                    "encryption": [
                        {
                            "status": "PASS",
                            "provider_order": ["aescbc", "identity"],
                            "rules": [{"providers": [{"provider_type": "aescbc", "config": {"key_data": "PRIVATE-KEY-DATA"}}]}],
                        }
                    ],
                    "config_consistency": {"status": "PASS", "node_count": 1},
                }
            },
        }
        markdown = render_markdown_report(report)
        html = render_html_report(report)
        for title in ("数据处理与质量", "身份认证画像", "服务账号令牌摘要", "证书状态", "etcd 节点安全", "静态加密配置", "配置一致性"):
            self.assertIn(title, markdown)
            self.assertIn(title, html)
        rendered = markdown + html
        for sensitive in ("plain-secret-token", "PRIVATE-KEY-DATA", "private-key-data"):
            self.assertNotIn(sensitive, rendered)

    def test_report_writers_create_files(self) -> None:
        with TemporaryDirectory() as temp_dir:
            markdown_path = Path(temp_dir) / "report.md"
            html_path = Path(temp_dir) / "report.html"
            write_markdown_report(self.report, markdown_path)
            write_html_report(self.report, html_path)
            self.assertIn("云原生安全评估报告", markdown_path.read_text())
            self.assertIn("<!doctype html>", html_path.read_text())


if __name__ == "__main__":
    unittest.main()

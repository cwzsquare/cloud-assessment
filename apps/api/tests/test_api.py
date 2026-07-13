from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cloudnative_security.adapters import AssessmentRequest
from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.server import ApiHandler
from cloudnative_security.storage import AssessmentStore


class ApiServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.store = AssessmentStore(f"{self.temp_dir.name}/assessment.sqlite3")
        request = AssessmentRequest(
            task_id="api-test-task",
            profile="all_tools_demo",
            manifest="ops/cnsec-lab/manifests",
        )
        result = AssessmentOrchestrator().run(request)
        self.store.save_result(result)

        handler = type("TestApiHandler", (ApiHandler,), {})
        handler.store = self.store
        handler.orchestrator = AssessmentOrchestrator()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.temp_dir.cleanup()

    def get_json(self, path: str) -> object:
        with urlopen(f"{self.base_url}{path}", timeout=10) as response:
            self.assertEqual(200, response.status)
            return json.loads(response.read())

    def request_json(self, method: str, path: str, payload: dict[str, object]) -> tuple[int, object]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_task_schema_findings_report_and_raw_snapshot_endpoints(self) -> None:
        tasks = self.get_json("/api/assessments")
        self.assertEqual("api-test-task", tasks[0]["id"])
        self.assertEqual("success", tasks[0]["status"])

        events = self.get_json("/api/assessments/api-test-task/events")
        self.assertGreaterEqual(len(events), 7)
        self.assertEqual("collect", events[0]["stage"])
        self.assertEqual("report", events[-1]["stage"])

        progress = self.get_json("/api/assessments/api-test-task/progress")
        self.assertEqual(100, progress["latest"]["progress"])

        finding_schema = self.get_json("/api/schema/Finding")
        self.assertIn("checkpoint_id", finding_schema["properties"])
        raw_snapshot_schema = self.get_json("/api/schema/RawSnapshot")
        self.assertIn("content_hash", raw_snapshot_schema["properties"])

        snapshots = self.get_json("/api/raw-snapshots?task_id=api-test-task")
        self.assertEqual({"cloud_native", "cloud_api_stub", "smart_cloud_stub", "registry_stub"}, {item["source"] for item in snapshots})
        self.assertIn("summary", snapshots[0])
        self.assertRegex(snapshots[0]["content_hash"], r"^[0-9a-f]{64}$")
        cloud_native_snapshot = [item for item in snapshots if item["source"] == "cloud_native"][0]
        self.assertIn("rbac_matrix", cloud_native_snapshot["summary"])

        rbac_matrix = self.get_json("/api/assessments/api-test-task/rbac-matrix")
        self.assertIn("rows", rbac_matrix)
        self.assertIn("dangerous_row_count", rbac_matrix["summary"])
        self.assertIn("required_resource_coverage", rbac_matrix)
        self.assertIn("required_resource_coverage_percent", rbac_matrix["summary"])
        self.assertIn("pods", rbac_matrix["required_resource_coverage"]["resources"])
        filtered_rbac = self.get_json("/api/assessments/api-test-task/rbac-matrix?subject=metrics-server&resource=pods&limit=5")
        self.assertFalse(filtered_rbac["filters"]["dangerous_only"])
        self.assertLessEqual(filtered_rbac["row_count"], 5)
        self.assertTrue(filtered_rbac["rows"])
        self.assertTrue(all("metrics-server" in row["subject"] for row in filtered_rbac["rows"]))
        self.assertTrue(all("pods" in row["resources"] for row in filtered_rbac["rows"]))

        filtered = self.get_json("/api/findings?task_id=api-test-task&tool_id=cloud_native&status=FAIL")
        self.assertTrue(filtered)
        self.assertTrue(all(item["tool_id"] == "cloud_native" and item["status"] == "FAIL" for item in filtered))

        finding = self.get_json(f"/api/findings/{filtered[0]['id']}")
        self.assertIsInstance(finding["evidence"], list)
        self.assertIn("remediation", finding)

        with urlopen(f"{self.base_url}/api/reports/api-test-task.md", timeout=10) as response:
            self.assertEqual(200, response.status)
            self.assertIn("text/markdown", response.headers.get("Content-Type", ""))
            markdown = response.read().decode()
            self.assertIn("# 云原生安全评估报告", markdown)
            self.assertIn("## 2. 标书检查点覆盖情况", markdown)
            self.assertIn("## 4. 重点风险清单", markdown)
            self.assertIn("整改优先级", markdown)
            self.assertIn("## 6. 数据质量与限制", markdown)
            self.assertIn("UNKNOWN 原因样例", markdown)

        with urlopen(f"{self.base_url}/api/reports/api-test-task.html", timeout=10) as response:
            self.assertEqual(200, response.status)
            self.assertIn("text/html", response.headers.get("Content-Type", ""))
            html = response.read().decode()
            self.assertIn("<!doctype html>", html)
            self.assertIn("标书检查点覆盖情况", html)
            self.assertIn("重点风险清单", html)
            self.assertIn("整改优先级", html)
            self.assertIn("数据质量与限制", html)

        report = self.get_json("/api/reports/api-test-task")
        tool_summary = report["summary"]["tool_summary"]
        self.assertTrue(any(item["tool_id"] == "cloud_native" for item in tool_summary))
        self.assertTrue(all("finding_count" in item for item in tool_summary))
        remediation_priority = report["summary"]["remediation_priority"]
        self.assertTrue(remediation_priority)
        self.assertTrue(all("priority" in item and "remediation" in item for item in remediation_priority))

    def test_assessment_post_records_progress_and_cancel_event(self) -> None:
        status, target = self.request_json(
            "POST",
            "/api/targets",
            {
                "id": "target-local-manifest",
                "name": "Local manifest demo",
                "type": "kubernetes",
                "connection_mode": "manifest",
                "manifest": "ops/cnsec-lab/manifests",
                "labels": {"env": "test"},
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("target-local-manifest", target["id"])
        target_schema = self.get_json("/api/schema/Target")
        self.assertIn("connection_mode", target_schema["properties"])
        targets = self.get_json("/api/targets")
        self.assertTrue(any(item["id"] == "target-local-manifest" for item in targets))
        loaded_target = self.get_json("/api/targets/target-local-manifest")
        self.assertEqual("manifest", loaded_target["connection_mode"])

        status, manual_checkpoint = self.request_json(
            "POST",
            "/api/checkpoints",
            {
                "id": "MANUAL-API",
                "tender_no": 1003,
                "name": "API 即时响应动态指标",
                "rule_group": "MANUAL",
                "domain": "人工检查",
                "weight": 2.0,
                "dimensions": ["人工录入"],
                "data_sources": ["operator"],
                "enabled": True,
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("MANUAL-API", manual_checkpoint["id"])

        status, payload = self.request_json(
            "POST",
            "/api/assessments",
            {
                "task_id": "api-created-task",
                "profile": "all_tools_demo",
                "target_id": "target-local-manifest",
            },
        )
        self.assertEqual(200, status)
        self.assertEqual("api-created-task", payload["report"]["task_id"])
        self.assertEqual("target-local-manifest", payload["request"]["target_id"])
        self.assertTrue(any(item["checkpoint_id"] == "MANUAL-API" for item in payload["report"]["checkpoint_scores"]))

        events = self.get_json("/api/assessments/api-created-task/events")
        self.assertEqual("collect", events[0]["stage"])
        self.assertEqual(100, events[-1]["progress"])

        status, task = self.request_json("POST", "/api/assessments/api-created-task/cancel", {})
        self.assertEqual(200, status)
        self.assertEqual("canceled", task["status"])
        events = self.get_json("/api/assessments/api-created-task/events")
        self.assertEqual("cancel", events[-1]["stage"])

        request = Request(f"{self.base_url}/api/targets/target-local-manifest", method="DELETE")
        with urlopen(request, timeout=10) as response:
            self.assertEqual(200, response.status)
            self.assertTrue(json.loads(response.read())["deleted"])

    def test_checkpoint_create_and_weight_patch(self) -> None:
        status, checkpoint = self.request_json(
            "POST",
            "/api/checkpoints",
            {
                "id": "MANUAL-1",
                "tender_no": 1001,
                "name": "手工补充指标",
                "rule_group": "MANUAL",
                "domain": "人工检查",
                "weight": 1.0,
                "dimensions": ["人工录入"],
                "data_sources": ["operator"],
                "enabled": True,
                "applicability": {"scope": "demo", "namespaces": ["cnsec-bad"]},
                "rule_enabled": {"MANUAL-RULE-1": True},
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("MANUAL-1", checkpoint["id"])
        self.assertTrue(checkpoint["enabled"])
        self.assertEqual("demo", checkpoint["applicability"]["scope"])
        self.assertTrue(checkpoint["rule_enabled"]["MANUAL-RULE-1"])

        status, patched = self.request_json("PATCH", "/api/checkpoints/MANUAL-1/weight", {"weight": 2.5})
        self.assertEqual(200, status)
        self.assertEqual(2.5, patched["weight"])
        status, error = self.request_json("PATCH", "/api/checkpoints/MANUAL-1/weight", {"weight": -1})
        self.assertEqual(400, status)
        self.assertIn("non-negative", error["error"])
        status, patched = self.request_json(
            "PATCH",
            "/api/checkpoints/MANUAL-1",
            {
                "enabled": False,
                "applicability": {"scope": "manual", "namespaces": ["cnsec-good"]},
                "rule_enabled": {"MANUAL-RULE-1": False, "MANUAL-RULE-2": True},
            },
        )
        self.assertEqual(200, status)
        self.assertFalse(patched["enabled"])
        self.assertEqual(["cnsec-good"], patched["applicability"]["namespaces"])
        self.assertFalse(patched["rule_enabled"]["MANUAL-RULE-1"])

        checkpoints = self.get_json("/api/checkpoints")
        manual = [item for item in checkpoints if item["id"] == "MANUAL-1"][0]
        self.assertEqual(2.5, manual["weight"])
        self.assertFalse(manual["enabled"])
        checkpoint_schema = self.get_json("/api/schema/Checkpoint")
        self.assertIn("applicability", checkpoint_schema["properties"])

        status, enabled_manual = self.request_json(
            "POST",
            "/api/checkpoints",
            {
                "id": "MANUAL-2",
                "tender_no": 1002,
                "name": "启用的手工指标",
                "rule_group": "MANUAL",
                "domain": "人工检查",
                "weight": 3.0,
                "dimensions": ["人工录入"],
                "data_sources": ["operator"],
                "enabled": True,
                "applicability": {"scope": "manual"},
                "rule_enabled": {"MANUAL-RULE-2": True},
            },
        )
        self.assertEqual(201, status)
        self.assertTrue(enabled_manual["enabled"])
        status, report = self.request_json("POST", "/api/reports/api-test-task/recalculate", {})
        self.assertEqual(200, status)
        manual_score = [item for item in report["checkpoint_scores"] if item["checkpoint_id"] == "MANUAL-2"][0]
        self.assertEqual("UNKNOWN", manual_score["status"])
        self.assertEqual(3.0, manual_score["weight"])

        before = self.get_json("/api/reports/api-test-task")["summary"]["overall_score"]
        status, patched = self.request_json("PATCH", "/api/checkpoints/CN-29/weight", {"weight": 10.0})
        self.assertEqual(200, status)
        self.assertEqual(10.0, patched["weight"])
        status, report = self.request_json("POST", "/api/reports/api-test-task/recalculate", {})
        self.assertEqual(200, status)
        self.assertNotEqual(before, report["summary"]["overall_score"])

        status, patched = self.request_json("PATCH", "/api/checkpoints/CN-29", {"enabled": False})
        self.assertEqual(200, status)
        self.assertFalse(patched["enabled"])
        status, report = self.request_json("POST", "/api/reports/api-test-task/recalculate", {})
        self.assertEqual(200, status)
        self.assertFalse(any(item["checkpoint_id"] == "CN-29" for item in report["checkpoint_scores"]))
        self.assertFalse(any(item["checkpoint_id"] == "CN-29" for item in report["findings"]))
        self.assertGreaterEqual(report["summary"]["dynamic_filter"]["excluded_by_reason"]["disabled_checkpoint"], 1)

    def test_checkpoint_rule_switch_and_applicability_filter_report_findings(self) -> None:
        status, patched = self.request_json(
            "PATCH",
            "/api/checkpoints/CN-29",
            {"rule_enabled": {"CN-IAM-002-dangerous-rbac": False}},
        )
        self.assertEqual(200, status)
        self.assertFalse(patched["rule_enabled"]["CN-IAM-002-dangerous-rbac"])
        status, report = self.request_json("POST", "/api/reports/api-test-task/recalculate", {})
        self.assertEqual(200, status)
        self.assertFalse(any(item["rule_id"] == "CN-IAM-002-dangerous-rbac" for item in report["findings"]))
        self.assertTrue(any(item["rule_id"] == "CN-IAM-002-context-policy" for item in report["findings"]))
        self.assertGreaterEqual(report["summary"]["dynamic_filter"]["excluded_by_reason"]["disabled_rule"], 1)

        status, patched = self.request_json(
            "PATCH",
            "/api/checkpoints/CN-37",
            {"applicability": {"scope": "namespace", "namespaces": ["cnsec-good"], "include_cluster_scoped": False}},
        )
        self.assertEqual(200, status)
        self.assertEqual(["cnsec-good"], patched["applicability"]["namespaces"])
        status, report = self.request_json("POST", "/api/reports/api-test-task/recalculate", {})
        self.assertEqual(200, status)
        cn37_score = [item for item in report["checkpoint_scores"] if item["checkpoint_id"] == "CN-37"][0]
        self.assertEqual("PASS", cn37_score["status"])
        self.assertEqual(2, cn37_score["finding_count"])
        cn37_findings = [item for item in report["findings"] if item["checkpoint_id"] == "CN-37"]
        self.assertTrue(cn37_findings)
        self.assertTrue(all(item["asset"]["namespace"] == "cnsec-good" for item in cn37_findings))
        self.assertGreaterEqual(report["summary"]["dynamic_filter"]["excluded_by_reason"]["not_applicable"], 1)

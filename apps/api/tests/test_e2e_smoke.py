from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from tempfile import TemporaryDirectory
from urllib.request import Request, urlopen

from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.server import ApiHandler
from cloudnative_security.storage import AssessmentStore


class EndToEndSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.store = AssessmentStore(f"{self.temp_dir.name}/assessment.sqlite3")
        handler = type("E2EApiHandler", (ApiHandler,), {})
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

    def request_json(self, method: str, path: str, payload: dict[str, object]) -> tuple[int, object]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())

    def get_json(self, path: str) -> object:
        with urlopen(f"{self.base_url}{path}", timeout=20) as response:
            self.assertEqual(200, response.status)
            return json.loads(response.read())

    def test_fixture_manifest_to_assessment_to_html_report(self) -> None:
        status, target = self.request_json(
            "POST",
            "/api/targets",
            {
                "id": "fixture-k8s-bad",
                "name": "Fixture K8s Bad",
                "type": "kubernetes",
                "connection_mode": "manifest",
                "manifest": "fixtures",
                "labels": {"fixture": "bad", "e2e": "true"},
            },
        )
        self.assertEqual(201, status)
        self.assertEqual("fixture-k8s-bad", target["id"])

        status, payload = self.request_json(
            "POST",
            "/api/assessments",
            {
                "task_id": "e2e-fixture-task",
                "profile": "all_tools_demo",
                "target_id": "fixture-k8s-bad",
            },
        )
        self.assertEqual(200, status)
        report = payload["report"]
        self.assertEqual(38, report["summary"]["checkpoint_total"])
        self.assertGreaterEqual(report["summary"]["finding_total"], 40)
        integration = self.get_json("/api/integration?task_id=e2e-fixture-task")
        self.assertEqual("integration/v1", integration["schema_version"])
        self.assertEqual(23, len(integration["points"]))
        self.assertEqual("real", next(item for item in integration["points"] if item["id"] == "INT-9")["mode"])
        self.assertEqual("placeholder", next(item for item in integration["points"] if item["id"] == "INT-8")["mode"])
        self.assertEqual("real", next(item for item in integration["points"] if item["id"] == "VIZ-18")["mode"])

        findings = self.get_json("/api/findings?task_id=e2e-fixture-task")
        failed = [item for item in findings if item["status"] == "FAIL"]
        self.assertGreaterEqual(len(failed), 10)
        self.assertTrue(any(item["checkpoint_id"] == "CN-27" for item in findings))
        self.assertTrue(any(item["checkpoint_id"] == "CN-37" for item in findings))

        with urlopen(f"{self.base_url}/api/reports/e2e-fixture-task.html", timeout=20) as response:
            self.assertEqual(200, response.status)
            body = response.read().decode()
            self.assertIn("<!doctype html>", body)
            self.assertIn("重点风险清单", body)
            self.assertIn("数据质量与限制", body)


if __name__ == "__main__":
    unittest.main()

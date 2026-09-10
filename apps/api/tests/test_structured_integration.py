from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory

from cloudnative_security.adapters import AssessmentRequest
from cloudnative_security.models import AssetRef, Evidence, Finding
from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.scoring import build_report, effective_findings_for_checkpoint
from cloudnative_security.storage import AssessmentStore
from cloudnative_security.structured_analysis import normalize_structured_payload


class StructuredIntegrationTest(unittest.TestCase):
    @staticmethod
    def finding(rule_id: str, status: str, asset: AssetRef | None = None) -> Finding:
        return Finding(
            id=f"f-{rule_id}-{asset.name if asset else 'cluster'}",
            task_id="t",
            tool_id="cloud_native",
            checkpoint_id="CP-1",
            rule_id=rule_id,
            title=rule_id,
            status=status,
            severity="high" if status == "FAIL" else "info",
            score={"PASS": 1.0, "WARN": 0.5, "FAIL": 0.0, "UNKNOWN": 0.0, "NOT_APPLICABLE": 1.0}[status],
            asset=asset,
            evidence=[Evidence("evidence")],
            remediation="fix",
        )

    def test_disabled_checkpoint_removes_findings_and_score(self) -> None:
        finding = self.finding("R-1", "FAIL")
        report = build_report("t", [finding], [{"id": "CP-1", "name": "x", "domain": "d", "weight": 1, "enabled": False}])
        self.assertEqual([], report.findings)
        self.assertEqual([], report.checkpoint_scores)

    def test_false_applicability_returns_not_applicable(self) -> None:
        finding = self.finding("R-1", "FAIL")
        report = build_report("t", [finding], [{"id": "CP-1", "name": "x", "domain": "d", "weight": 1, "applicability": False}])
        self.assertEqual([], report.findings)
        self.assertEqual("NOT_APPLICABLE", report.checkpoint_scores[0].status)

    def test_rule_disabled_preserves_other_rule_score(self) -> None:
        findings = [self.finding("R-1", "FAIL"), self.finding("R-2", "PASS")]
        checkpoint = {"id": "CP-1", "name": "x", "domain": "d", "weight": 1, "rule_enabled": {"R-1": False}}
        effective = effective_findings_for_checkpoint(checkpoint, findings)
        report = build_report("t", findings, [checkpoint])
        self.assertEqual(["R-2"], [item.rule_id for item in effective])
        self.assertEqual(["R-2"], [item.rule_id for item in report.findings])
        self.assertEqual("PASS", report.checkpoint_scores[0].status)

    def test_namespace_applicability_excludes_cluster_and_other_namespace(self) -> None:
        findings = [
            self.finding("R-good", "PASS", AssetRef("Pod", "good", "selected")),
            self.finding("R-other", "FAIL", AssetRef("Pod", "other", "excluded")),
            self.finding("R-cluster", "FAIL", None),
        ]
        checkpoint = {
            "id": "CP-1",
            "name": "x",
            "domain": "d",
            "weight": 1,
            "applicability": {"scope": "namespace", "namespaces": ["selected"], "include_cluster_scoped": False},
        }
        report = build_report("t", findings, [checkpoint])
        self.assertEqual(["R-good"], [item.rule_id for item in report.findings])
        self.assertEqual("PASS", report.checkpoint_scores[0].status)
    def test_legacy_structured_payload_is_normalized(self) -> None:
        payload = normalize_structured_payload(
            {
                "schema_version": "structured-assessment/v0",
                "processing": {"status": "SUCCESS"},
                "quality": [{"rule_id": "Q-1"}],
                "authn": {"status": "UNKNOWN"},
                "asset_relationships": {"nodes": [{"id": "asset-1"}], "edges": []},
            }
        )
        self.assertEqual("structured-assessment/v1", payload["schema_version"])
        self.assertEqual("SUCCESS", payload["processing_run"]["status"])
        self.assertEqual("Q-1", payload["data_quality_results"][0]["rule_id"])
        self.assertEqual("UNKNOWN", payload["authentication"]["status"])
        self.assertEqual("asset-1", payload["asset_graph"]["nodes"][0]["id"])
        self.assertEqual("structured-assessment/v0", payload["compatibility"]["source_schema_version"])

    def test_assessment_persists_pipeline_quality_lineage_and_module_products(self) -> None:
        with TemporaryDirectory() as directory:
            task_id = "structured-integration-test"
            result = AssessmentOrchestrator().run(
                AssessmentRequest(task_id=task_id, profile="cloud_native_full", manifest="fixtures/k8s-bad")
            )
            self.assertEqual(14, len(result.structured["processing_steps"]))
            self.assertEqual("SUCCESS", result.structured["processing_run"]["status"])
            self.assertEqual(7, len(result.structured["data_quality_results"]))
            self.assertTrue(result.structured["lineage"]["nodes"])
            self.assertTrue(result.structured["asset_graph"]["nodes"])
            self.assertIn("field_mapping_rules", result.structured)
            self.assertIn("config_consistency", result.structured)

            store = AssessmentStore(f"{directory}/assessment.sqlite3")
            store.save_result(result)
            persisted = store.get_structured_payload(task_id)
            self.assertEqual(14, len(persisted["processing_steps"]))
            self.assertEqual("input_loading", persisted["processing_steps"][0]["step_name"])
            self.assertTrue(persisted["lineage"]["edges"])
            self.assertTrue(persisted["asset_graph"]["nodes"])
            self.assertNotIn("plain-text-password", json.dumps(persisted, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory

from cloudnative_security.adapters import AssessmentRequest
from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.storage import AssessmentStore


class StructuredIntegrationTest(unittest.TestCase):
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

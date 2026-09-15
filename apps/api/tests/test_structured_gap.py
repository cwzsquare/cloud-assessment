from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudnative_security.adapters import AssessmentRequest
from cloudnative_security.orchestrator import AssessmentOrchestrator
from cloudnative_security.storage import AssessmentStore


ROOT = Path(__file__).resolve().parents[3]


class StructuredGapBehaviorTest(unittest.TestCase):
    def test_fixture_exercises_anomalies_associations_and_custom_rules(self) -> None:
        config = json.loads((ROOT / "fixtures/structured-gap-processing.json").read_text())
        result = AssessmentOrchestrator().run(
            AssessmentRequest(
                task_id="structured-gap-test",
                manifest=str(ROOT / "fixtures/structured-gap"),
                options={"processing": config},
            )
        )
        structured = result.structured
        self.assertEqual(2, len(structured["anomalies"]))
        self.assertEqual(6, len(structured["associations"]["groups"]))
        statuses = {item["rule_id"]: item["status"] for item in structured["data_quality_results"]}
        self.assertEqual("PASS", statuses["fixture_unique_object_key"])
        self.assertEqual("FAIL", statuses["fixture_entity_present"])
        self.assertTrue(structured["quality_metrics"]["metrics"])
        self.assertTrue(structured["lineage"]["nodes"])

    def test_structured_products_round_trip_with_task_scoping(self) -> None:
        config = json.loads((ROOT / "fixtures/structured-gap-processing.json").read_text())
        result = AssessmentOrchestrator().run(
            AssessmentRequest(
                task_id="structured-gap-round-trip",
                manifest=str(ROOT / "fixtures/structured-gap"),
                options={"processing": config},
            )
        )
        with TemporaryDirectory() as directory:
            store = AssessmentStore(str(Path(directory) / "assessment.sqlite3"))
            store.save_result(result)
            self.assertEqual(2, len(store.list_quality_anomalies(result.request.task_id)))
            self.assertEqual(6, len(store.list_association_groups(result.request.task_id)))
            self.assertEqual("structured/v1", store.get_processing_config(result.request.task_id)["target_format"])
            self.assertTrue(store.get_quality_lineage(result.request.task_id, "fixture_entity_present")["nodes"])
            self.assertEqual([], store.list_quality_anomalies("missing-task"))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from cloudnative_security.data_lineage import (
    build_lineage_graph,
    trace_from_asset,
    trace_from_finding,
)


class LineageGraphTest(unittest.TestCase):
    def test_builds_deduplicated_chain_and_reverse_trace(self) -> None:
        snapshots = [{"id": 7, "task_id": "task-1", "source": "collector", "content_hash": "abc"}, {"id": 7, "source": "collector"}]
        assets = [{"kind": "Deployment", "namespace": "apps", "name": "web", "snapshot_id": 7}]
        findings = [{"id": "finding-1", "task_id": "task-1", "checkpoint_id": "CP-1", "rule_id": "R-1", "asset": assets[0], "status": "FAIL"}]
        graph = build_lineage_graph(snapshots, assets, findings, [{"id": "CP-1", "name": "deployment policy"}], [{"task_id": "task-1", "findings": findings, "checkpoint_scores": [{"checkpoint_id": "CP-1"}]}])

        self.assertEqual([node.id for node in graph.nodes], sorted({node.id for node in graph.nodes}))
        self.assertEqual(len([node for node in graph.nodes if node.id == "raw_snapshot:7"]), 1)
        relations = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
        self.assertIn(("source:collector", "raw_snapshot:7", "produces"), relations)
        self.assertIn(("raw_snapshot:7", "asset:Deployment/apps/web", "normalizes"), relations)
        self.assertIn(("asset:Deployment/apps/web", "finding:finding-1", "has_finding"), relations)
        self.assertIn(("finding:finding-1", "checkpoint:CP-1", "evaluates"), relations)
        self.assertIn(("checkpoint:CP-1", "report:task-1", "included_in"), relations)
        self.assertEqual([node.id for node in trace_from_finding(graph, "finding-1")], [
            "finding:finding-1", "asset:Deployment/apps/web", "raw_snapshot:7", "source:collector"
        ])
        self.assertEqual([node.id for node in trace_from_asset(graph, "asset:Deployment/apps/web")], [
            "asset:Deployment/apps/web", "raw_snapshot:7", "source:collector"
        ])

    def test_missing_references_do_not_create_unknown_nodes(self) -> None:
        graph = build_lineage_graph(
            raw_snapshots=[{"id": 1, "source": "collector"}],
            findings=[{"id": "f", "checkpoint_id": "missing", "asset": None}],
        )
        self.assertNotIn("checkpoint:missing", {node.id for node in graph.nodes})
        self.assertNotIn("asset:unknown", {node.id for node in graph.nodes})
        self.assertEqual([], trace_from_finding(graph, "does-not-exist"))

    def test_lineage_metadata_does_not_retain_secret_values(self) -> None:
        graph = build_lineage_graph(raw_snapshots=[{"id": 1, "source": "collector", "password": "do-not-store", "token": "bearer-value"}])
        payload = graph.to_dict()
        self.assertNotIn("do-not-store", str(payload))
        self.assertNotIn("bearer-value", str(payload))


if __name__ == "__main__":
    unittest.main()

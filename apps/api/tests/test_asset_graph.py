from __future__ import annotations

import unittest

from cloudnative_security.asset_graph import build_asset_graph


class AssetGraphTest(unittest.TestCase):
    def test_kubernetes_relationships_and_secret_redaction(self) -> None:
        objects = [
            {"kind": "ServiceAccount", "metadata": {"name": "web", "namespace": "apps"}},
            {"kind": "Secret", "metadata": {"name": "credentials", "namespace": "apps"}, "data": {"password": "c2VjcmV0"}},
            {"kind": "ConfigMap", "metadata": {"name": "settings", "namespace": "apps"}, "data": {"mode": "safe"}},
            {"kind": "PersistentVolumeClaim", "metadata": {"name": "data", "namespace": "apps"}},
            {"kind": "Node", "metadata": {"name": "worker-1"}},
            {"kind": "Deployment", "metadata": {"name": "web", "namespace": "apps"}, "spec": {"replicas": 1, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"serviceAccountName": "web", "nodeName": "worker-1", "volumes": [{"secret": {"secretName": "credentials"}}, {"configMap": {"name": "settings"}}, {"persistentVolumeClaim": {"claimName": "data"}}]}}}},
            {"kind": "Service", "metadata": {"name": "web", "namespace": "apps"}, "spec": {"selector": {"app": "web"}}},
            {"kind": "Ingress", "metadata": {"name": "web", "namespace": "apps"}, "spec": {"rules": [{"http": {"paths": [{"backend": {"service": {"name": "web"}}}]}}]}},
        ]
        graph = build_asset_graph(objects)
        relations = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
        deployment = "Deployment/apps/web"
        self.assertIn((deployment, "ServiceAccount/apps/web", "uses_service_account"), relations)
        self.assertIn((deployment, "Secret/apps/credentials", "mounts_secret"), relations)
        self.assertIn((deployment, "ConfigMap/apps/settings", "mounts_configmap"), relations)
        self.assertIn((deployment, "PersistentVolumeClaim/apps/data", "mounts_pvc"), relations)
        self.assertIn(("Service/apps/web", deployment, "selects"), relations)
        self.assertIn(("Ingress/apps/web", "Service/apps/web", "routes_to"), relations)
        self.assertNotIn("c2VjcmV0", str(graph.to_dict()))

    def test_rbac_rows_create_known_nodes_and_dedupe(self) -> None:
        rows = [{
            "subject": "ServiceAccount:apps/auditor", "subject_kind": "ServiceAccount", "subject_name": "auditor", "subject_namespace": "apps",
            "binding_kind": "RoleBinding", "binding_name": "auditor", "binding_namespace": "apps",
            "role_kind": "Role", "role_name": "reader", "role_namespace": "apps",
            "api_groups": [""], "resources": ["pods"], "verbs": ["get"],
        }] * 2
        graph = build_asset_graph([], rows)
        self.assertEqual(len(graph.nodes), len({node.id for node in graph.nodes}))
        self.assertEqual(len(graph.edges), len({(edge.source, edge.target, edge.relation) for edge in graph.edges}))
        relations = {(edge.source, edge.target, edge.relation) for edge in graph.edges}
        self.assertIn(("RoleBinding/apps/auditor", "Role/apps/reader", "binds_to"), relations)
        self.assertIn(("RoleBinding/apps/auditor", "ServiceAccount/apps/auditor", "grants_to"), relations)
        self.assertTrue(any(node.kind == "Permission" for node in graph.nodes))

    def test_absent_object_references_are_not_fabricated(self) -> None:
        graph = build_asset_graph([{"kind": "Deployment", "metadata": {"name": "web", "namespace": "apps"}, "spec": {"template": {"spec": {"serviceAccountName": "missing"}}}}])
        self.assertNotIn("ServiceAccount/apps/missing", {node.id for node in graph.nodes})
        self.assertFalse(any(edge.relation == "uses_service_account" for edge in graph.edges))


if __name__ == "__main__":
    unittest.main()

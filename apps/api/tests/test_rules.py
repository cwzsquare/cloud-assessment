from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudnative_security.adapters import AdapterResult, AssessmentRequest, CloudNativeAdapter
from cloudnative_security.checkpoints import ASSESSMENT_CHECKPOINTS, CLOUD_NATIVE_CHECKPOINTS, VISUALIZATION_CHECKPOINTS
from cloudnative_security.collector import ResourceIndex, load_manifest_path, node_internal_ips, parse_auth_log_text
from cloudnative_security.orchestrator import AssessmentOrchestrator, data_quality_summary
from cloudnative_security.models import AssetRef, Evidence
from cloudnative_security.rbac_matrix import build_rbac_matrix
from cloudnative_security.rules import _finding, _spec_hash, run_rules
from cloudnative_security.scoring import build_report
from cloudnative_security.storage import AssessmentStore


class CloudNativeRulesTest(unittest.TestCase):
    def test_manifest_scan_covers_all_cloud_native_checkpoints(self) -> None:
        index = load_manifest_path("ops/cnsec-lab/manifests")
        findings = run_rules(index, "test-task")
        covered = {finding.checkpoint_id for finding in findings}
        expected = {checkpoint.id for checkpoint in CLOUD_NATIVE_CHECKPOINTS}
        self.assertEqual(expected, covered)

    def test_bad_lab_manifests_produce_actionable_findings(self) -> None:
        index = load_manifest_path("ops/cnsec-lab/manifests")
        findings = run_rules(index, "test-task")
        self.assertGreaterEqual(len(findings), 30)
        self.assertTrue(any(f.status == "FAIL" and f.checkpoint_id == "CN-29" for f in findings))
        self.assertTrue(any(f.status == "FAIL" and f.checkpoint_id == "CN-37" for f in findings))
        for finding in findings:
            self.assertTrue(finding.evidence)
            self.assertTrue(finding.remediation)
            self.assertTrue(finding.fingerprint)

    def test_runtime_log_fixtures_generate_falco_and_authlog_findings(self) -> None:
        index = load_manifest_path("fixtures")
        self.assertTrue(index.by_kind("AuthLogEvent"))
        self.assertTrue(index.by_kind("FalcoEvent"))
        findings = run_rules(index, "runtime-log-fixtures")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertIn("CN-IAM-003-authlog-ssh-bruteforce", by_rule)
        self.assertEqual("FAIL", by_rule["CN-IAM-003-authlog-ssh-bruteforce"].status)
        self.assertIn("CN-PER-004-runtime-abnormal-write", by_rule)
        self.assertTrue(any(finding.rule_id.startswith("CN-PER-004-runtime-") and finding.status in {"FAIL", "WARN"} for finding in findings))
        self.assertIn("CN-PER-004-volume-mount-escape", by_rule)
        volume_escape = by_rule["CN-PER-004-volume-mount-escape"]
        self.assertTrue(volume_escape.evidence[0].observed["volume_refs"])
        self.assertTrue(any(row["volumeType"] == "hostPath" for row in volume_escape.evidence[0].observed["volume_refs"]))

    def test_bare_falco_jsonl_is_loaded_as_runtime_event(self) -> None:
        with TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "falco_events.jsonl"
            log_path.write_text(
                '{"time":"2026-06-17T10:11:00Z","priority":"Error","rule":"Write below binary dir","output":"File below a known binary directory opened for writing","k8s":{"ns":"cnsec-bad","pod":"postgres-bad-0","container":"postgres"},"output_fields":{"fd.name":"/var/lib/postgresql/data/tmp.sh","proc.name":"sh"}}\n'
            )
            index = load_manifest_path(log_path)
        falco_events = index.by_kind("FalcoEvent")
        self.assertEqual(1, len(falco_events))
        self.assertEqual("cnsec-bad", falco_events[0]["metadata"]["namespace"])
        findings = [finding for finding in run_rules(index, "bare-falco-jsonl") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("FAIL", by_rule["CN-PER-004-runtime-abnormal-write"].status)
        self.assertEqual("Pod", by_rule["CN-PER-004-runtime-abnormal-write"].asset.kind)
        self.assertEqual("postgres-bad-0", by_rule["CN-PER-004-runtime-abnormal-write"].asset.name)

    def test_persistence_runtime_monitoring_covers_audit_event_and_pvc_anomalies(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "shared-data", "namespace": "cnsec-bad"}, "spec": {"accessModes": ["ReadWriteOnce"]}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "writer-a", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "busybox", "volumeMounts": [{"name": "data", "mountPath": "/data"}]}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "shared-data"}}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "writer-b", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "busybox", "volumeMounts": [{"name": "data", "mountPath": "/var/lib/kubelet/pods"}]}], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "shared-data"}}]}}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "hostpath-escape", "namespace": "cnsec-bad"},
                    "spec": {"containers": [{"name": "debug", "image": "busybox", "volumeMounts": [{"name": "sock", "mountPath": "/run/containerd/containerd.sock", "mountPropagation": "Bidirectional"}]}], "volumes": [{"name": "sock", "hostPath": {"path": "/run/containerd/containerd.sock"}}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "projected-secrets", "namespace": "cnsec-good"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "busybox",
                                "volumeMounts": [
                                    {"name": "sa-token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"},
                                    {"name": "config", "mountPath": "/etc/app"},
                                    {"name": "cache", "mountPath": "/etc/cache"},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "sa-token", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}},
                            {"name": "config", "configMap": {"name": "app-config"}},
                            {"name": "cache", "emptyDir": {}},
                        ],
                    },
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "FalcoEvent",
                    "metadata": {"name": "nested-write", "namespace": "cnsec-bad"},
                    "priority": "Critical",
                    "rule": "Write below binary dir",
                    "output": "File opened for writing",
                    "output_fields": {"fd.name": "/etc/shadow", "proc.name": "sh"},
                    "k8s": {"ns": "cnsec-bad", "pod": "writer-a", "container": "app"},
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuditLogEvent",
                    "metadata": {"name": "delete-pvc", "namespace": "cnsec-bad"},
                    "verb": "delete",
                    "user": {"username": "mallory@example.test"},
                    "objectRef": {"resource": "persistentvolumeclaims", "namespace": "cnsec-bad", "name": "shared-data"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "failed-mount", "namespace": "cnsec-bad"},
                    "reason": "FailedMount",
                    "message": "MountVolume.SetUp failed for PVC shared-data: forbidden hostPath /etc",
                    "involvedObject": {"kind": "Pod", "namespace": "cnsec-bad", "name": "writer-b"},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("PASS", by_rule["CN-PER-004-falco-events"].status)
        self.assertTrue(by_rule["CN-PER-004-falco-events"].evidence[0].observed["source_present"])
        self.assertEqual("FAIL", by_rule["CN-PER-004-runtime-event-classification"].status)
        category_counts = by_rule["CN-PER-004-runtime-event-classification"].evidence[0].observed["counts"]
        self.assertGreaterEqual(category_counts["abnormal_write"], 1)
        self.assertGreaterEqual(category_counts["sensitive_path"], 1)
        self.assertGreaterEqual(category_counts["shell"], 1)
        self.assertGreaterEqual(category_counts["pvc_or_volume"], 1)
        self.assertIn("CN-PER-004-runtime-abnormal-write", by_rule)
        abnormal_write = by_rule["CN-PER-004-runtime-abnormal-write"]
        self.assertEqual("FAIL", abnormal_write.status)
        self.assertEqual("Pod", abnormal_write.asset.kind)
        self.assertEqual("writer-a", abnormal_write.asset.name)
        self.assertEqual("cnsec-bad", abnormal_write.asset.namespace)
        self.assertIn("abnormal_write", abnormal_write.evidence[0].observed["categories"])
        self.assertEqual("Pod/cnsec-bad/writer-a", abnormal_write.evidence[0].observed["linked_asset"])
        self.assertEqual("FAIL", by_rule["CN-PER-004-risky-volume-mount"].status)
        mount_observed = by_rule["CN-PER-004-risky-volume-mount"].evidence[0].observed
        mount_risks = mount_observed["risks"]
        self.assertTrue(any(row["asset"] == "Pod/cnsec-bad/hostpath-escape" for row in mount_risks))
        hostpath_risk = [row for row in mount_risks if row["asset"] == "Pod/cnsec-bad/hostpath-escape"][0]
        self.assertEqual("hostPath", hostpath_risk["volumeType"])
        self.assertFalse(any(row["asset"] == "Pod/cnsec-good/projected-secrets" for row in mount_risks))
        self.assertEqual("FAIL", by_rule["CN-PER-004-audit-persistence-event"].status)
        self.assertTrue(any("persistentvolumeclaims delete operation" in row["risks"] for row in by_rule["CN-PER-004-audit-persistence-event"].evidence[0].observed["risks"]))
        self.assertEqual("FAIL", by_rule["CN-PER-004-pvc-mount-anomaly"].status)
        self.assertTrue(any("RWO PVC mounted by multiple workloads" in row["risks"] for row in by_rule["CN-PER-004-pvc-mount-anomaly"].evidence[0].observed["risks"]))
        self.assertTrue(any(row["pvc"] == "shared-data" for row in by_rule["CN-PER-004-pvc-mount-anomaly"].evidence[0].observed["risks"]))
        falco_event = [finding for finding in findings if finding.rule_id == "CN-PER-004-runtime-abnormal-write"][0]
        self.assertEqual("/etc/shadow", falco_event.evidence[0].observed["file"])
        self.assertEqual("writer-a", falco_event.evidence[0].observed["pod"])
        self.assertEqual("app", falco_event.evidence[0].observed["container"])
        self.assertTrue(any(row["pvc"] == "shared-data" for row in falco_event.evidence[0].observed["pvc_refs"]))
        ledger = by_rule["CN-PER-004-incident-ledger"].evidence[0].observed
        self.assertTrue(ledger["incidents"])
        self.assertFalse(any(incident["time"] is None for incident in ledger["incidents"]))

    def test_persistence_runtime_monitoring_keeps_empty_stream_unknown_with_falco_source(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {"name": "falco", "namespace": "falco", "labels": {"app.kubernetes.io/name": "falco"}},
                    "spec": {"template": {"spec": {"containers": [{"name": "falco", "image": "falcosecurity/falco:0.44.1"}]}}},
                }
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-empty") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("PASS", by_rule["CN-PER-004-falco-events"].status)
        self.assertEqual("UNKNOWN", by_rule["CN-PER-004-runtime-event-classification"].status)
        observed = by_rule["CN-PER-004-runtime-event-classification"].evidence[0].observed
        self.assertTrue(observed["source"]["source_present"])
        self.assertFalse(observed["source"]["event_stream_present"])
        self.assertEqual([], observed["risks"])

    def test_persistence_runtime_monitoring_passes_benign_event_stream(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuditLogEvent",
                    "metadata": {"name": "pod-status-update", "namespace": "cnsec-good"},
                    "verb": "update",
                    "user": {"username": "system:serviceaccount:kube-system:deployment-controller"},
                    "objectRef": {"resource": "pods", "namespace": "cnsec-good", "name": "good-web-abc"},
                }
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-benign") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("PASS", by_rule["CN-PER-004-runtime-event-classification"].status)
        observed = by_rule["CN-PER-004-runtime-event-classification"].evidence[0].observed
        self.assertTrue(observed["source"]["event_stream_present"])
        self.assertEqual([], observed["risks"])

    def test_persistence_runtime_monitoring_counts_kubernetes_event_stream(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "normal-pulled", "namespace": "cnsec-good"},
                    "reason": "Pulled",
                    "message": "Successfully pulled image",
                    "involvedObject": {"kind": "Pod", "namespace": "cnsec-good", "name": "good-web-abc"},
                }
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-k8s-event") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        observed = by_rule["CN-PER-004-runtime-event-classification"].evidence[0].observed
        self.assertEqual("PASS", by_rule["CN-PER-004-runtime-event-classification"].status)
        self.assertTrue(observed["source"]["source_present"])
        self.assertTrue(observed["source"]["event_stream_present"])

    def test_persistence_runtime_classifies_kubernetes_volume_events(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "bad-volume-mount", "namespace": "cnsec-bad"},
                    "reason": "FailedMount",
                    "message": "MountVolume.SetUp failed for PVC db-data: forbidden hostPath /etc",
                    "involvedObject": {"kind": "Pod", "namespace": "cnsec-bad", "name": "postgres-bad-0"},
                }
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-volume-event") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        classification = by_rule["CN-PER-004-runtime-event-classification"]
        self.assertEqual("FAIL", classification.status)
        observed = classification.evidence[0].observed
        self.assertGreaterEqual(observed["counts"]["pvc_or_volume"], 1)
        self.assertGreaterEqual(observed["counts"]["sensitive_path"], 1)
        self.assertEqual(0, observed["counts"]["abnormal_write"])
        self.assertTrue(any(row["source_kind"] == "Event" for row in observed["risks"]))
        audit = by_rule["CN-PER-004-audit-persistence-event"]
        self.assertEqual("FAIL", audit.status)
        self.assertTrue(audit.evidence[0].observed["risks"])
        self.assertEqual("unknown", audit.evidence[0].observed["risks"][0]["time"])
        ledger = by_rule["CN-PER-004-incident-ledger"]
        event_incidents = [incident for incident in ledger.evidence[0].observed["incidents"] if incident["source"] == "event"]
        self.assertEqual("unknown", event_incidents[0]["time"])

    def test_persistence_runtime_splits_platform_policy_events_from_business_risks(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "platform-policy", "namespace": "default", "creationTimestamp": "2026-06-22T20:00:00Z"},
                    "reason": "PolicyViolation",
                    "message": "Pod kube-system/kube-proxy-abc: [host-path] fail; HostPath volumes are forbidden at /spec/volumes/0/hostPath/",
                    "involvedObject": {"kind": "ClusterPolicy", "namespace": "default", "name": "disallow-host-path"},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "web-bad", "namespace": "cnsec-bad"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{"name": "web", "image": "nginx", "volumeMounts": [{"name": "host-etc", "mountPath": "/etc"}]}],
                                "volumes": [{"name": "host-etc", "hostPath": {"path": "/etc"}}],
                            }
                        }
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "business-policy", "namespace": "default", "creationTimestamp": "2026-06-22T20:01:00Z"},
                    "reason": "PolicyViolation",
                    "message": "Deployment cnsec-bad/web-bad: [autogen-host-path] fail; HostPath volumes are forbidden at /spec/template/spec/volumes/0/hostPath/",
                    "involvedObject": {"kind": "ClusterPolicy", "namespace": "default", "name": "disallow-host-path"},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-policy-events") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        audit = by_rule["CN-PER-004-audit-persistence-event"]
        self.assertEqual("FAIL", audit.status)
        observed = audit.evidence[0].observed
        self.assertEqual(1, len(observed["risks"]))
        self.assertEqual("cnsec-bad", observed["risks"][0]["namespace"])
        self.assertEqual("2026-06-22T20:01:00Z", observed["risks"][0]["time"])
        self.assertEqual("Deployment/cnsec-bad/web-bad", observed["risks"][0]["target_asset"])
        self.assertTrue(observed["risks"][0]["volume_refs"])
        self.assertEqual(1, observed["platform_review_count"])
        self.assertEqual("kube-system", observed["platform_review"][0]["namespace"])
        ledger = by_rule["CN-PER-004-incident-ledger"]
        self.assertEqual("PASS", ledger.status)
        self.assertEqual(["cnsec-bad"], ledger.evidence[0].observed["affected_namespaces"])
        self.assertEqual(["Deployment/cnsec-bad/web-bad"], ledger.evidence[0].observed["affected_targets"])
        incident = ledger.evidence[0].observed["incidents"][0]
        self.assertEqual("2026-06-22T20:01:00Z", incident["time"])
        self.assertEqual("Deployment/cnsec-bad/web-bad", incident["target_asset"])
        self.assertTrue(incident["volume_refs"])

    def test_persistence_runtime_reviews_platform_hostpath_without_business_fail(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {"name": "falco", "namespace": "falco"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{"name": "falco", "image": "falcosecurity/falco:0.44.1", "volumeMounts": [{"name": "host-proc", "mountPath": "/host/proc"}]}],
                                "volumes": [{"name": "host-proc", "hostPath": {"path": "/proc"}}],
                            }
                        }
                    },
                }
            ]
        )
        findings = [finding for finding in run_rules(index, "persistence-runtime-platform-hostpath") if finding.checkpoint_id == "CN-39"]
        by_rule = {finding.rule_id: finding for finding in findings}
        mount = by_rule["CN-PER-004-risky-volume-mount"]
        self.assertEqual("PASS", mount.status)
        self.assertEqual([], mount.evidence[0].observed["risks"])
        self.assertEqual(1, mount.evidence[0].observed["platform_review_count"])
        self.assertEqual("DaemonSet/falco/falco", mount.evidence[0].observed["platform_review"][0]["asset"])

    def test_authlog_parser_and_node_ip_extraction(self) -> None:
        events = parse_auth_log_text(
            "2026-06-22T02:41:01Z k8s-worker-1 sshd[2101]: Failed password for invalid user admin from 10.20.0.99 port 49152 ssh2\n",
            "unit-authlog",
        )
        self.assertEqual(1, len(events))
        self.assertEqual("AuthLogEvent", events[0]["kind"])
        self.assertEqual("10.20.0.99", events[0]["remote_ip"])
        nodes = node_internal_ips(
            [
                {
                    "kind": "Node",
                    "metadata": {"name": "k8s-worker-1"},
                    "status": {"addresses": [{"type": "InternalIP", "address": "10.20.0.21"}]},
                }
            ]
        )
        self.assertEqual({"k8s-worker-1": "10.20.0.21"}, nodes)

    def test_authlog_source_counts_as_identity_audit_source(self) -> None:
        index = load_manifest_path("fixtures/k8s-good/cnsec-good.yaml")
        index.objects.append(
            {
                "apiVersion": "fixtures.cnsec/v1",
                "kind": "AuthLogSource",
                "metadata": {"name": "k8s-worker-1-authlog"},
                "source": "authlog",
                "line_count": 20,
                "failed_password_count": 0,
            }
        )
        findings = run_rules(index, "authlog-source")
        source_finding = [finding for finding in findings if finding.rule_id == "CN-IAM-003-falco-or-authlog"][0]
        self.assertEqual("PASS", source_finding.status)
        self.assertEqual(1, source_finding.evidence[0].observed["auth_sources"])

    def test_identity_hardening_detects_exec_abnormal_login_and_keeps_identity_incident_ledger(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuditLogEvent",
                    "metadata": {"name": "pod-exec-1", "namespace": "cnsec-bad"},
                    "verb": "create",
                    "user": {"username": "alice@example.test"},
                    "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "cnsec-bad", "name": "debug-shell"},
                    "requestURI": "/api/v1/namespaces/cnsec-bad/pods/debug-shell/exec",
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuthLogEvent",
                    "metadata": {"name": "ssh-success-1"},
                    "node": "worker-1",
                    "remote_ip": "198.51.100.24",
                    "user": "root",
                    "event_type": "ssh_accepted_password",
                    "raw": "Accepted password for root from 198.51.100.24 port 54422 ssh2",
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "identity-runtime-events") if finding.checkpoint_id == "CN-30"]

        exec_finding = next(finding for finding in findings if "exec" in finding.rule_id)
        self.assertEqual("FAIL", exec_finding.status)
        exec_observed = json.dumps(exec_finding.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("debug-shell", exec_observed)
        self.assertIn("alice@example.test", exec_observed)

        abnormal_login = next(finding for finding in findings if "login" in finding.rule_id)
        self.assertEqual("FAIL", abnormal_login.status)
        login_observed = json.dumps(abnormal_login.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("198.51.100.24", login_observed)
        self.assertIn("root", login_observed)

        ledger = next(finding for finding in findings if "ledger" in finding.rule_id)
        self.assertEqual("PASS", ledger.status)
        ledger_observed = json.dumps(ledger.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("exec", ledger_observed)
        self.assertIn("login", ledger_observed)

    def test_authentication_mechanisms_deduplicates_pods_and_uses_sa_automount_context(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-partial", "labels": {"purpose": "cnsec-demo"}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-uncapped", "labels": {"purpose": "cnsec-demo"}}},
                {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "locked", "namespace": "cnsec-good"}, "automountServiceAccountToken": False},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"serviceAccountName": "locked", "containers": [{"name": "web", "image": "nginx"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"automountServiceAccountToken": True, "containers": [{"name": "web", "image": "nginx"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
                    "spec": {"template": {"spec": {"containers": [{"name": "proxy", "image": "proxy"}]}}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "bad-web-abc", "namespace": "cnsec-bad", "ownerReferences": [{"kind": "ReplicaSet", "name": "bad-web-rs"}]},
                    "spec": {"automountServiceAccountToken": True, "containers": [{"name": "web", "image": "nginx"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "debug-shell", "namespace": "cnsec-bad"},
                    "spec": {"containers": [{"name": "debug", "image": "busybox"}]},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "auth-context") if finding.checkpoint_id == "CN-28" and finding.rule_id == "CN-IAM-001-sa-token-automount"]
        by_asset = {finding.asset.key: finding for finding in findings if finding.asset}
        self.assertEqual("PASS", by_asset["Deployment/cnsec-good/good-web"].status)
        self.assertFalse(by_asset["Deployment/cnsec-good/good-web"].evidence[0].observed["effective_automount"])
        self.assertEqual("WARN", by_asset["Deployment/cnsec-bad/bad-web"].status)
        self.assertEqual("NOT_APPLICABLE", by_asset["DaemonSet/kube-system/kube-proxy"].status)
        self.assertEqual("WARN", by_asset["Pod/cnsec-bad/debug-shell"].status)
        self.assertNotIn("Pod/cnsec-bad/bad-web-abc", by_asset)
        self.assertEqual(
            ["DaemonSet/kube-system/kube-proxy", "Deployment/cnsec-bad/bad-web", "Deployment/cnsec-good/good-web", "Pod/cnsec-bad/debug-shell"],
            sorted(by_asset),
        )

    def test_authentication_mechanisms_downgrades_known_public_discovery_bindings(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "system:public-info-viewer"}, "subjects": [{"kind": "Group", "name": "system:unauthenticated"}], "roleRef": {"kind": "ClusterRole", "name": "system:public-info-viewer", "apiGroup": "rbac.authorization.k8s.io"}},
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "kubeadm:bootstrap-signer-clusterinfo", "namespace": "kube-public"}, "subjects": [{"kind": "Group", "name": "system:unauthenticated"}], "roleRef": {"kind": "Role", "name": "kubeadm:bootstrap-signer-clusterinfo", "apiGroup": "rbac.authorization.k8s.io"}},
            ]
        )
        finding = [finding for finding in run_rules(index, "anon-public-review") if finding.rule_id == "CN-IAM-001-anonymous-binding"][0]
        self.assertEqual("NOT_APPLICABLE", finding.status)
        self.assertEqual([], finding.evidence[0].observed["dangerous_bindings"])
        self.assertEqual(2, len(finding.evidence[0].observed["public_discovery_review"]))

    def test_authentication_mechanisms_surface_oidc_external_auth_and_apiserver_tls_evidence(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--oidc-issuer-url=https://accounts.example.test",
                        "--oidc-client-id=kubernetes",
                        "--authentication-config=/etc/kubernetes/authn.yaml",
                        "--client-ca-file=/etc/kubernetes/pki/ca.crt",
                        "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt",
                        "--tls-private-key-file=/etc/kubernetes/pki/apiserver.key",
                    ],
                },
                {
                    "apiVersion": "apiserver.config.k8s.io/v1beta1",
                    "kind": "AuthenticationConfiguration",
                    "metadata": {"name": "cluster-authn"},
                    "jwt": [{"issuer": {"url": "https://accounts.example.test", "audiences": ["kubernetes"]}}],
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "authn-evidence") if finding.checkpoint_id == "CN-28"]

        oidc = next(finding for finding in findings if "oidc" in finding.rule_id or "external" in finding.rule_id)
        self.assertEqual("PASS", oidc.status)
        oidc_observed = json.dumps(oidc.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("accounts.example.test", oidc_observed)
        self.assertTrue("authenticationconfiguration" in oidc_observed or "authn.yaml" in oidc_observed)

        apiserver_tls = next(
            finding
            for finding in findings
            if finding.rule_id != "CN-IAM-001-mtls-strict" and "tls" in finding.rule_id and "apiserver" in finding.rule_id
        )
        self.assertEqual("PASS", apiserver_tls.status)
        tls_observed = json.dumps(apiserver_tls.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("client-ca-file", tls_observed)
        self.assertIn("tls-cert-file", tls_observed)
        self.assertIn("tls-private-key-file", tls_observed)

    def test_rbac_matrix_separates_business_and_system_dangerous_grants(self) -> None:
        index = load_manifest_path("fixtures")
        matrix = build_rbac_matrix(index)
        self.assertGreaterEqual(matrix["summary"]["business_dangerous_row_count"], 1)
        self.assertTrue(any(row["subject"] == "Group:system:authenticated" for row in matrix["business_dangerous_rows"]))
        self.assertTrue(all(not row["system_managed"] for row in matrix["business_dangerous_rows"]))
        findings = run_rules(index, "rbac-context")
        by_rule = {}
        for finding in findings:
            by_rule.setdefault(finding.rule_id, []).append(finding)
        dangerous = by_rule["CN-IAM-002-dangerous-rbac"]
        self.assertTrue(any(finding.status == "FAIL" and finding.asset and finding.asset.name == "dangerous-app-rolebinding" for finding in dangerous))
        self.assertIn(by_rule["CN-IAM-002-temporary-grant-expiry"][0].status, {"WARN", "PASS"})
        self.assertTrue(all("system:aggregate-to-edit" not in (finding.title or "") for finding in dangerous))

    def test_dynamic_access_control_reports_permission_matrix_resource_coverage(self) -> None:
        complete_index = ResourceIndex(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "audit-reader"},
                    "rules": [{"apiGroups": ["", "networking.k8s.io"], "resources": ["pods", "services", "configmaps", "secrets", "ingresses", "namespaces"], "verbs": ["get", "list"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "audit-reader-binding"},
                    "subjects": [{"kind": "ServiceAccount", "name": "auditor", "namespace": "cnsec-good"}],
                    "roleRef": {"kind": "ClusterRole", "name": "audit-reader", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        matrix = build_rbac_matrix(complete_index)
        coverage = matrix["required_resource_coverage"]
        self.assertEqual([], coverage["missing_resources"])
        self.assertEqual(100.0, coverage["coverage_percent"])
        self.assertIn("ServiceAccount:cnsec-good/auditor", coverage["resources"]["pods"]["subjects_sample"])
        complete_by_rule = {finding.rule_id: finding for finding in run_rules(complete_index, "matrix-complete") if finding.checkpoint_id == "CN-29"}
        self.assertEqual("PASS", complete_by_rule["CN-IAM-002-permission-matrix-coverage"].status)
        self.assertEqual("PASS", complete_by_rule["CN-IAM-002-permission-queryability"].status)
        query_sample = complete_by_rule["CN-IAM-002-permission-queryability"].evidence[0].observed["subject_index_sample"][0]
        self.assertEqual("ServiceAccount:cnsec-good/auditor", query_sample["subject"])
        self.assertIn("pods", query_sample["resources"])

        partial_index = ResourceIndex(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "debug", "namespace": "cnsec-bad"},
                    "rules": [{"apiGroups": [""], "resources": ["pods/exec", "pods/attach", "pods/portforward", "secrets"], "verbs": ["get", "list", "create"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-binding", "namespace": "cnsec-bad"},
                    "subjects": [{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        partial_by_rule = {finding.rule_id: finding for finding in run_rules(partial_index, "matrix-partial") if finding.checkpoint_id == "CN-29"}
        coverage_finding = partial_by_rule["CN-IAM-002-permission-matrix-coverage"]
        self.assertEqual("WARN", coverage_finding.status)
        self.assertEqual(["services", "configmaps", "ingresses", "namespaces"], coverage_finding.evidence[0].observed["missing_resources"])
        self.assertEqual("PASS", partial_by_rule["CN-IAM-002-permission-queryability"].status)
        resource_sample = partial_by_rule["CN-IAM-002-permission-queryability"].evidence[0].observed["resource_index_sample"]
        self.assertTrue(any(row["resource"] == "pods/exec" and "Group:system:authenticated" in row["subjects"] for row in resource_sample))
        dangerous = partial_by_rule["CN-IAM-002-dangerous-rbac"]
        self.assertIn("pods attach", dangerous.evidence[0].observed["danger_reasons"])
        self.assertIn("pods portforward", dangerous.evidence[0].observed["danger_reasons"])

    def test_dynamic_access_control_expands_clusterrole_aggregation(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "tenant-edit"},
                    "aggregationRule": {
                        "clusterRoleSelectors": [
                            {
                                "matchLabels": {"cnsec.io/aggregate-to-tenant-edit": "true"},
                                "matchExpressions": [{"key": "cnsec.io/tier", "operator": "In", "values": ["business"]}],
                            }
                        ]
                    },
                    "rules": [],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "tenant-secret-reader", "labels": {"cnsec.io/aggregate-to-tenant-edit": "true", "cnsec.io/tier": "business"}},
                    "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "tenant-nonmatching-secret-reader", "labels": {"cnsec.io/aggregate-to-tenant-edit": "true", "cnsec.io/tier": "platform"}},
                    "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "tenant-edit-binding"},
                    "subjects": [{"kind": "Group", "name": "developers"}],
                    "roleRef": {"kind": "ClusterRole", "name": "tenant-edit", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        matrix = build_rbac_matrix(index)
        self.assertEqual(1, matrix["summary"]["aggregated_cluster_role_count"])
        self.assertEqual(1, matrix["summary"]["aggregated_rule_row_count"])
        row = matrix["business_dangerous_rows"][0]
        self.assertEqual("ClusterRole/tenant-edit", f"{row['role_kind']}/{row['role_name']}")
        self.assertEqual("tenant-secret-reader", row["aggregation_source_role"])
        self.assertIn("secret read/list/watch", row["danger_reasons"])

        findings = [finding for finding in run_rules(index, "aggregated-rbac") if finding.rule_id == "CN-IAM-002-dangerous-rbac"]
        self.assertEqual("FAIL", findings[0].status)
        self.assertEqual("tenant-secret-reader", findings[0].evidence[0].observed["aggregation_source_role"])

    def test_dynamic_access_control_validates_temporary_grant_expiry(self) -> None:
        base_role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "debug", "namespace": "cnsec-bad"},
            "rules": [{"apiGroups": [""], "resources": ["pods/exec", "secrets"], "verbs": ["get", "list", "create"]}],
        }
        valid_index = ResourceIndex(
            [
                base_role,
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-valid", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "2999-01-01T00:00:00Z"}},
                    "subjects": [{"kind": "User", "name": "alice@example.test"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        valid_expiry = [finding for finding in run_rules(valid_index, "valid-expiry") if finding.rule_id == "CN-IAM-002-temporary-grant-expiry"][0]
        self.assertEqual("PASS", valid_expiry.status)

        invalid_index = ResourceIndex(
            [
                base_role,
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-expired", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "2000-01-01T00:00:00Z"}},
                    "subjects": [{"kind": "User", "name": "bob@example.test"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-invalid", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "soon"}},
                    "subjects": [{"kind": "User", "name": "carol@example.test"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        matrix = build_rbac_matrix(invalid_index)
        marker_statuses = {row["binding_name"]: row["expiry_marker"]["status"] for row in matrix["expiry_missing_rows"]}
        self.assertEqual("expired", marker_statuses["debug-expired"])
        self.assertEqual("invalid", marker_statuses["debug-invalid"])
        invalid_expiry = [finding for finding in run_rules(invalid_index, "invalid-expiry") if finding.rule_id == "CN-IAM-002-temporary-grant-expiry"][0]
        self.assertEqual("WARN", invalid_expiry.status)
        observed_statuses = {row["binding"].rsplit("/", 1)[-1]: row["expiry_marker"]["status"] for row in invalid_expiry.evidence[0].observed}
        self.assertEqual("expired", observed_statuses["debug-expired"])
        self.assertEqual("invalid", observed_statuses["debug-invalid"])

        role_only_index = ResourceIndex(
            [
                {
                    **base_role,
                    "metadata": {"name": "debug", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "2999-01-01T00:00:00Z"}},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-role-only-expiry", "namespace": "cnsec-bad"},
                    "subjects": [{"kind": "User", "name": "dave@example.test"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        role_only_matrix = build_rbac_matrix(role_only_index)
        self.assertEqual([], role_only_matrix["expiry_missing_rows"])
        role_only_row = role_only_matrix["business_dangerous_rows"][0]
        self.assertEqual("missing", role_only_row["expiry_marker"]["status"])
        self.assertEqual("valid", role_only_row["role_expiry_marker"]["status"])
        self.assertEqual("role", role_only_row["effective_expiry_marker"]["source"])
        role_only_expiry = [finding for finding in run_rules(role_only_index, "role-only-expiry") if finding.rule_id == "CN-IAM-002-temporary-grant-expiry"][0]
        self.assertEqual("PASS", role_only_expiry.status)

        cluster_role_only_index = ResourceIndex(
            [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "cluster-debug", "annotations": {"cnsec.io/expires-at": "2999-01-01T00:00:00Z"}},
                    "rules": [{"apiGroups": [""], "resources": ["pods/exec", "secrets"], "verbs": ["get", "list", "create"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "cluster-debug-role-only-expiry"},
                    "subjects": [{"kind": "User", "name": "cluster-debug@example.test"}],
                    "roleRef": {"kind": "ClusterRole", "name": "cluster-debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        cluster_role_only_matrix = build_rbac_matrix(cluster_role_only_index)
        self.assertEqual([], cluster_role_only_matrix["expiry_missing_rows"])
        cluster_role_only_row = cluster_role_only_matrix["business_dangerous_rows"][0]
        self.assertEqual("valid", cluster_role_only_row["role_expiry_marker"]["status"])
        self.assertEqual("role", cluster_role_only_row["effective_expiry_marker"]["source"])

        binding_override_index = ResourceIndex(
            [
                {
                    **base_role,
                    "metadata": {"name": "debug", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "2999-01-01T00:00:00Z"}},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-binding-expired", "namespace": "cnsec-bad", "annotations": {"cnsec.io/expires-at": "2000-01-01T00:00:00Z"}},
                    "subjects": [{"kind": "User", "name": "erin@example.test"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        binding_override_matrix = build_rbac_matrix(binding_override_index)
        binding_override_row = binding_override_matrix["expiry_missing_rows"][0]
        self.assertEqual("expired", binding_override_row["effective_expiry_marker"]["status"])
        self.assertEqual("binding", binding_override_row["effective_expiry_marker"]["source"])
        binding_override_expiry = [finding for finding in run_rules(binding_override_index, "binding-override-expiry") if finding.rule_id == "CN-IAM-002-temporary-grant-expiry"][0]
        self.assertEqual("WARN", binding_override_expiry.status)

    def test_dynamic_access_control_validates_context_policy_content(self) -> None:
        context_index = ResourceIndex(
            [
                {
                    "apiVersion": "kyverno.io/v1",
                    "kind": "ClusterPolicy",
                    "metadata": {"name": "require-env-label"},
                    "spec": {
                        "rules": [
                            {
                                "name": "require-env-label",
                                "match": {"any": [{"resources": {"kinds": ["Pod"], "namespaceSelector": {"matchLabels": {"env": "prod"}}}}]},
                                "validate": {"message": "env label required", "pattern": {"metadata": {"labels": {"env": "?*"}}}},
                            }
                        ]
                    },
                }
            ]
        )
        context_by_rule = {finding.rule_id: finding for finding in run_rules(context_index, "context-policy") if finding.checkpoint_id == "CN-29"}
        context_finding = context_by_rule["CN-IAM-002-context-policy"]
        self.assertEqual("PASS", context_finding.status)
        self.assertEqual(1, context_finding.evidence[0].observed["context_policy_count"])
        self.assertIn("label", context_finding.evidence[0].observed["context_policy_sample"][0]["signals"])
        self.assertIn("namespace", context_finding.evidence[0].observed["context_policy_sample"][0]["signals"])
        self.assertEqual(["subject"], context_finding.evidence[0].observed["missing_required_contexts"])
        self.assertEqual(1, context_finding.evidence[0].observed["signal_coverage"]["env"])
        self.assertEqual(1, context_finding.evidence[0].observed["signal_coverage"]["label"])

        subject_index = ResourceIndex(
            [
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": "tenant-subject-policy"},
                    "spec": {
                        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
                        "matchConditions": [
                            {"name": "tenant-env", "expression": "object.metadata.labels['tenant'] == 'blue' && object.metadata.labels['env'] == 'prod'"},
                            {"name": "trusted-subject", "expression": "request.userInfo.groups.exists(g, g == 'platform-admins')"},
                        ],
                        "validations": [{"expression": "object.metadata.namespace == request.namespace"}],
                    },
                }
                ,
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicyBinding",
                    "metadata": {"name": "tenant-subject-policy-binding"},
                    "spec": {"policyName": "tenant-subject-policy", "validationActions": ["Audit"]},
                },
            ]
        )
        subject_by_rule = {finding.rule_id: finding for finding in run_rules(subject_index, "subject-context-policy") if finding.checkpoint_id == "CN-29"}
        subject_finding = subject_by_rule["CN-IAM-002-context-policy"]
        self.assertEqual("PASS", subject_finding.status)
        subject_signals = set(subject_finding.evidence[0].observed["context_policy_sample"][0]["signals"])
        self.assertTrue({"env", "label", "namespace", "subject"} <= subject_signals)
        self.assertEqual([], subject_finding.evidence[0].observed["missing_required_contexts"])
        self.assertTrue(subject_finding.evidence[0].observed["context_policy_sample"][0]["binding_assets"])

        unbound_vap_index = ResourceIndex(
            [
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": "tenant-subject-policy"},
                    "spec": {
                        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
                        "matchConditions": [
                            {"name": "tenant-env", "expression": "object.metadata.labels['tenant'] == 'blue' && object.metadata.labels['env'] == 'prod'"},
                            {"name": "trusted-subject", "expression": "request.userInfo.groups.exists(g, g == 'platform-admins')"},
                        ],
                        "validations": [{"expression": "object.metadata.namespace == request.namespace"}],
                    },
                }
            ]
        )
        unbound_by_rule = {finding.rule_id: finding for finding in run_rules(unbound_vap_index, "subject-context-policy-unbound") if finding.checkpoint_id == "CN-29"}
        unbound_finding = unbound_by_rule["CN-IAM-002-context-policy"]
        self.assertEqual("WARN", unbound_finding.status)
        self.assertEqual(0, unbound_finding.evidence[0].observed["context_policy_count"])
        self.assertEqual(1, len(unbound_finding.evidence[0].observed["unbound_validating_policies"]))

        generic_policy_index = ResourceIndex(
            [
                {
                    "apiVersion": "kyverno.io/v1",
                    "kind": "ClusterPolicy",
                    "metadata": {"name": "generic-policy"},
                    "spec": {"rules": [{"name": "audit", "validate": {"message": "generic", "pattern": {"spec": {"restartPolicy": "Always"}}}}]},
                }
            ]
        )
        generic_by_rule = {finding.rule_id: finding for finding in run_rules(generic_policy_index, "generic-policy") if finding.checkpoint_id == "CN-29"}
        generic_finding = generic_by_rule["CN-IAM-002-context-policy"]
        self.assertEqual("WARN", generic_finding.status)
        self.assertEqual(0, generic_finding.evidence[0].observed["context_policy_count"])
        self.assertEqual(["env", "label", "namespace", "subject"], generic_finding.evidence[0].observed["missing_required_contexts"])

    def test_scaling_security_distinguishes_platform_namespace_and_workload_inheritance(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system", "labels": {}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad-web"}}, "spec": {"containers": [{"name": "web", "image": "nginx"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "dns", "namespace": "kube-system"},
                    "spec": {"template": {"metadata": {"labels": {"k8s-app": "dns"}}, "spec": {"containers": [{"name": "dns", "image": "coredns"}]}}},
                },
            ]
        )
        findings = run_rules(index, "scaling-security-context")
        psa = [finding for finding in findings if finding.rule_id == "CN-ELAS-002-psa-labels"]
        by_namespace = {finding.asset.name: finding for finding in psa if finding.asset}
        self.assertEqual("NOT_APPLICABLE", by_namespace["kube-system"].status)
        self.assertEqual("PASS", by_namespace["cnsec-good"].status)
        self.assertEqual("FAIL", by_namespace["cnsec-bad"].status)
        inheritance = [finding for finding in findings if finding.rule_id == "CN-ELAS-002-workload-policy-inheritance"][0]
        self.assertEqual("FAIL", inheritance.status)
        self.assertTrue(any(row["namespace"] == "cnsec-bad" for row in inheritance.evidence[0].observed["unprotected_workload_namespaces"]))
        self.assertTrue(any(row["namespace"] == "kube-system" for row in inheritance.evidence[0].observed["platform_review_namespaces"]))

    def test_scaling_security_checks_rollout_and_hpa_template_inheritance(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "kyverno.io/v1",
                    "kind": "ClusterPolicy",
                    "metadata": {"name": "restricted-pods"},
                    "spec": {"rules": [{"name": "restricted", "validate": {"pattern": {"spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"securityContext": {"allowPrivilegeEscalation": False}}]}}}}]},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {
                        "replicas": 2,
                        "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 1}},
                        "template": {
                            "metadata": {"labels": {"app": "good-web"}},
                            "spec": {
                                "securityContext": {"runAsNonRoot": True, "runAsUser": 101},
                                "containers": [
                                    {
                                        "name": "web",
                                        "image": "nginx",
                                        "resources": {"requests": {"cpu": "100m"}, "limits": {"cpu": "500m"}},
                                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                    }
                                ],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {
                        "replicas": 1,
                        "strategy": {"type": "Recreate"},
                        "template": {"metadata": {"labels": {"app": "bad-web"}}, "spec": {"containers": [{"name": "web", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": True}}]}},
                    },
                },
                {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": {"name": "good-hpa", "namespace": "cnsec-good"}, "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "good-web"}, "minReplicas": 2, "maxReplicas": 5}},
                {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": {"name": "bad-hpa", "namespace": "cnsec-bad"}, "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "bad-web"}, "minReplicas": 1, "maxReplicas": 100}},
                {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "metadata": {"name": "missing-target-hpa", "namespace": "cnsec-bad"}, "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "missing"}, "minReplicas": 1, "maxReplicas": 3}},
            ]
        )
        findings = [finding for finding in run_rules(index, "scaling-rollout") if finding.checkpoint_id == "CN-24"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-002-rollout-strategy", "cnsec-good", "good-web")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-002-rollout-strategy", "cnsec-bad", "bad-web")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-002-hpa-template-inheritance", "cnsec-good", "good-hpa")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-002-hpa-template-inheritance", "cnsec-bad", "bad-hpa")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-002-hpa-template-inheritance", "cnsec-bad", "missing-target-hpa")].status)

    def test_scaling_security_scores_admission_policy_control_coverage(self) -> None:
        full_index = ResourceIndex(
            [
                {
                    "apiVersion": "kyverno.io/v1",
                    "kind": "ClusterPolicy",
                    "metadata": {"name": "restricted-pod-security"},
                    "spec": {
                        "rules": [
                            {
                                "name": "restricted",
                                "validate": {
                                    "podSecurity": {
                                        "level": "restricted",
                                        "version": "latest",
                                    }
                                },
                            }
                        ]
                    },
                }
            ]
        )
        full_finding = [finding for finding in run_rules(full_index, "full-policy") if finding.rule_id == "CN-ELAS-002-admission-policy-present"][0]
        self.assertEqual("PASS", full_finding.status)
        self.assertEqual([], full_finding.evidence[0].observed["missing_required_controls"])
        self.assertIn("seccomp_profile", full_finding.evidence[0].observed["covered_controls"])
        self.assertIn("read_only_root_filesystem", full_finding.evidence[0].observed["missing_recommended_controls"])

        partial_index = ResourceIndex(
            [
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": "deny-privilege-escalation"},
                    "spec": {
                        "validations": [
                            {
                                "expression": "object.spec.containers.all(c, has(c.securityContext) && c.securityContext.allowPrivilegeEscalation == false)",
                                "message": "allowPrivilegeEscalation must be false",
                            }
                        ]
                    },
                }
            ]
        )
        partial_finding = [finding for finding in run_rules(partial_index, "partial-policy") if finding.rule_id == "CN-ELAS-002-admission-policy-present"][0]
        self.assertEqual("WARN", partial_finding.status)
        observed = partial_finding.evidence[0].observed
        self.assertIn("disallow_privilege_escalation", observed["covered_controls"])
        self.assertIn("run_as_non_root", observed["missing_controls"])

        expression_index = ResourceIndex(
            [
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": "pod-baseline-vap"},
                    "spec": {
                        "validations": [
                            {"expression": "object.spec.securityContext.runAsNonRoot == true"},
                            {"expression": "object.spec.containers.all(c, c.securityContext.allowPrivilegeEscalation == false)"},
                            {"expression": "object.spec.containers.all(c, c.securityContext.privileged == false)"},
                            {"expression": "object.spec.containers.all(c, c.securityContext.capabilities.drop.exists(x, x == 'ALL'))"},
                            {"expression": "object.spec.securityContext.seccompProfile.type in ['RuntimeDefault', 'Localhost']"},
                        ]
                    },
                }
            ]
        )
        expression_finding = [finding for finding in run_rules(expression_index, "expression-policy") if finding.rule_id == "CN-ELAS-002-admission-policy-present"][0]
        expression_observed = expression_finding.evidence[0].observed
        self.assertEqual("PASS", expression_finding.status)
        self.assertEqual([], expression_observed["missing_required_controls"])
        self.assertIn("reasons", expression_observed["security_policy_details"][0])

    def test_resource_policy_governance_validates_quota_limitrange_and_priorityclass(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-partial"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "trivy-system"}},
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "complete", "namespace": "cnsec-good"},
                    "spec": {"hard": {"pods": "10", "requests.cpu": "2", "requests.memory": "4Gi", "limits.cpu": "4", "limits.memory": "8Gi"}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "LimitRange",
                    "metadata": {"name": "defaults", "namespace": "cnsec-good"},
                    "spec": {"limits": [{"type": "Container", "default": {"cpu": "500m", "memory": "512Mi"}, "defaultRequest": {"cpu": "100m", "memory": "128Mi"}}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "partial", "namespace": "cnsec-partial"},
                    "spec": {"hard": {"pods": "5", "requests.cpu": "1"}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "LimitRange",
                    "metadata": {"name": "partial", "namespace": "cnsec-partial"},
                    "spec": {"limits": [{"type": "Container", "defaultRequest": {"cpu": "100m"}}]},
                },
                {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass", "metadata": {"name": "business-critical"}, "value": 1000, "globalDefault": False},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"priorityClassName": "business-critical", "containers": [{"name": "web", "image": "nginx"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "partial-web", "namespace": "cnsec-partial"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx"}]}}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "resource-policy") if finding.checkpoint_id == "CN-25"]
        by_title = {finding.title: finding for finding in findings}
        self.assertEqual("PASS", by_title["cnsec-good ResourceQuota 检查"].status)
        self.assertEqual([], by_title["cnsec-good ResourceQuota 检查"].evidence[0].observed["missing"])
        partial_quota = by_title["cnsec-partial ResourceQuota 检查"]
        self.assertEqual("FAIL", partial_quota.status)
        self.assertEqual(["requests.memory", "limits.cpu", "limits.memory"], partial_quota.evidence[0].observed["missing"])
        partial_limit = by_title["cnsec-partial LimitRange 检查"]
        self.assertEqual("FAIL", partial_limit.status)
        self.assertEqual(["default.cpu", "default.memory", "defaultRequest.memory"], sorted(partial_limit.evidence[0].observed["missing"]))
        self.assertEqual("FAIL", by_title["cnsec-bad ResourceQuota 检查"].status)
        self.assertEqual("FAIL", by_title["cnsec-bad LimitRange 检查"].status)
        self.assertEqual("NOT_APPLICABLE", by_title["trivy-system ResourceQuota 检查"].status)
        self.assertEqual("NOT_APPLICABLE", by_title["trivy-system LimitRange 检查"].status)
        priority = [finding for finding in findings if finding.rule_id == "CN-ELAS-003-priorityclass"][0]
        self.assertEqual("FAIL", priority.status)
        self.assertEqual("business-critical", priority.evidence[0].observed["priority_classes"][0]["name"])
        self.assertTrue(any(row["asset"] == "Deployment/cnsec-partial/partial-web" for row in priority.evidence[0].observed["missing_usage"]))

        no_priority_index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-app"}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "app", "namespace": "cnsec-app"},
                    "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "app"}]}}},
                },
            ]
        )
        no_priority = [finding for finding in run_rules(no_priority_index, "no-priority") if finding.rule_id == "CN-ELAS-003-priorityclass"][0]
        self.assertEqual("FAIL", no_priority.status)
        self.assertFalse(no_priority.evidence[0].observed["has_priority_classes"])

    def test_resource_policy_proves_admission_and_daemonset_govern_new_pods_and_nodes(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Node", "metadata": {"name": "worker-1", "labels": {"node-role.kubernetes.io/worker": "true"}}},
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": "pod-and-node-guardrails"},
                    "spec": {
                        "matchConstraints": {
                            "resourceRules": [
                                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods", "nodes"]},
                            ]
                        },
                        "validations": [{"expression": "has(object.metadata.labels)"}],
                    },
                },
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicyBinding",
                    "metadata": {"name": "pod-and-node-guardrails-binding"},
                    "spec": {"policyName": "pod-and-node-guardrails", "validationActions": ["Deny"]},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {"name": "falco", "namespace": "falco"},
                    "spec": {"template": {"spec": {"containers": [{"name": "falco", "image": "falcosecurity/falco:0.44.1"}]}}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "resource-policy-governance") if finding.checkpoint_id == "CN-25"]

        admission = next(finding for finding in findings if "admission" in finding.rule_id)
        self.assertEqual("PASS", admission.status)
        admission_observed = json.dumps(admission.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("pods", admission_observed)
        self.assertIn("nodes", admission_observed)
        self.assertIn("validatingadmissionpolicy", admission_observed)

        daemonset = next(finding for finding in findings if "daemonset" in finding.rule_id and "govern" in json.dumps(finding.evidence[0].observed, ensure_ascii=False).lower())
        self.assertEqual("PASS", daemonset.status)
        daemonset_observed = json.dumps(daemonset.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("worker-1", daemonset_observed)
        self.assertIn("falco", daemonset_observed)

    def test_microservice_resilience_uses_namespace_context_and_quality_checks(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apiregistration.k8s.io/v1",
                    "kind": "APIService",
                    "metadata": {"name": "v1beta1.metrics.k8s.io"},
                    "spec": {"group": "metrics.k8s.io", "service": {"name": "metrics-server", "namespace": "kube-system"}},
                    "status": {"conditions": [{"type": "Available", "status": "True", "reason": "Passed", "message": "all checks passed"}]},
                },
                {
                    "apiVersion": "metrics.k8s.io/v1beta1",
                    "kind": "PodMetrics",
                    "metadata": {"name": "good-web-abc", "namespace": "cnsec-good"},
                    "containers": [{"name": "web", "usage": {"cpu": "10m", "memory": "20Mi"}}],
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "system-addon", "namespace": "kube-system"},
                    "spec": {"template": {"metadata": {"labels": {"app": "system-addon"}}, "spec": {"containers": [{"name": "addon", "image": "addon"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"metadata": {"labels": {"app": "good-web"}}, "spec": {"containers": [{"name": "web", "image": "nginx", "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}}}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad-web"}}, "spec": {"containers": [{"name": "web", "image": "nginx"}]}}},
                },
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "good-web-hpa", "namespace": "cnsec-good"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "good-web"}, "minReplicas": 2, "maxReplicas": 5, "metrics": [{"type": "Resource", "resource": {"name": "cpu"}}]},
                    "status": {
                        "conditions": [
                            {"type": "AbleToScale", "status": "True", "reason": "ReadyForNewScale"},
                            {"type": "ScalingActive", "status": "True", "reason": "ValidMetricFound"},
                            {"type": "ScalingLimited", "status": "True", "reason": "TooFewReplicas"},
                        ],
                        "currentMetrics": [{"type": "Resource", "resource": {"name": "cpu", "current": {"averageUtilization": 1}}}],
                        "currentReplicas": 2,
                        "desiredReplicas": 2,
                    },
                },
                {
                    "apiVersion": "policy/v1",
                    "kind": "PodDisruptionBudget",
                    "metadata": {"name": "good-web-pdb", "namespace": "cnsec-good"},
                    "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "good-web"}}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "resilience-context") if finding.checkpoint_id == "CN-6"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        metrics_api = [finding for finding in findings if finding.rule_id == "CN-ELAS-001-metrics-api"][0]
        self.assertEqual("PASS", metrics_api.status)
        self.assertTrue(metrics_api.evidence[0].observed["api_service_available"])
        hpa_runtime = by_rule_asset[("CN-ELAS-001-hpa-runtime", "cnsec-good", "good-web")]
        self.assertEqual("PASS", hpa_runtime.status)
        self.assertTrue(hpa_runtime.evidence[0].observed["has_current_metrics"])
        self.assertTrue(hpa_runtime.evidence[0].observed["trigger_evidence"])
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-ELAS-001-hpa-present", "kube-system", "system-addon")].status)
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-ELAS-001-resources-present", "kube-system", "system-addon")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-001-pdb-present", "cnsec-bad", "bad-web")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-001-resources-present", "cnsec-bad", "bad-web")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-001-hpa-quality", "cnsec-good", "good-web")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-001-pdb-quality", "cnsec-good", "good-web")].status)
        good_summary = by_rule_asset[("CN-ELAS-001-workload-resilience-score", "cnsec-good", "good-web")]
        self.assertEqual("PASS", good_summary.status)
        self.assertEqual(100.0, good_summary.evidence[0].observed["resilience_score"])
        bad_summary = by_rule_asset[("CN-ELAS-001-workload-resilience-score", "cnsec-bad", "bad-web")]
        self.assertEqual("FAIL", bad_summary.status)
        self.assertIn("pdb_present", bad_summary.evidence[0].observed["missing_controls"])
        self.assertIn("resources_present", bad_summary.evidence[0].observed["missing_controls"])
        system_summary = by_rule_asset[("CN-ELAS-001-workload-resilience-score", "kube-system", "system-addon")]
        self.assertEqual("NOT_APPLICABLE", system_summary.status)
        mesh_finding = [finding for finding in findings if finding.rule_id == "CN-ELAS-001-service-mesh-resilience"][0]
        self.assertEqual("NOT_APPLICABLE", mesh_finding.status)

    def test_microservice_resilience_checks_istio_timeout_retry_and_outlier_detection(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-api", "namespace": "cnsec-good"},
                    "spec": {"template": {"metadata": {"labels": {"app": "good-api"}}, "spec": {"containers": [{"name": "api", "image": "api", "resources": {"requests": {"cpu": "100m"}, "limits": {"cpu": "500m"}}}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-api", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad-api"}}, "spec": {"containers": [{"name": "api", "image": "api"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "worker-no-service", "namespace": "cnsec-good"},
                    "spec": {"template": {"metadata": {"labels": {"app": "worker-no-service"}}, "spec": {"containers": [{"name": "worker", "image": "worker"}]}}},
                },
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "good-api", "namespace": "cnsec-good"}, "spec": {"selector": {"app": "good-api"}, "ports": [{"port": 80}]}},
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "bad-api", "namespace": "cnsec-bad"}, "spec": {"selector": {"app": "bad-api"}, "ports": [{"port": 80}]}},
                {
                    "apiVersion": "security.istio.io/v1beta1",
                    "kind": "PeerAuthentication",
                    "metadata": {"name": "default", "namespace": "istio-system"},
                    "spec": {"mtls": {"mode": "STRICT"}},
                },
                {
                    "apiVersion": "networking.istio.io/v1beta1",
                    "kind": "VirtualService",
                    "metadata": {"name": "good-api", "namespace": "cnsec-good"},
                    "spec": {"hosts": ["good-api.cnsec-good.svc.cluster.local"], "http": [{"timeout": "2s", "retries": {"attempts": 3, "perTryTimeout": "1s"}, "route": [{"destination": {"host": "good-api.cnsec-good.svc.cluster.local"}}]}]},
                },
                {
                    "apiVersion": "networking.istio.io/v1beta1",
                    "kind": "DestinationRule",
                    "metadata": {"name": "good-api", "namespace": "cnsec-good"},
                    "spec": {"host": "good-api.cnsec-good.svc.cluster.local", "trafficPolicy": {"outlierDetection": {"consecutive5xxErrors": 3}}},
                },
                {
                    "apiVersion": "networking.istio.io/v1beta1",
                    "kind": "VirtualService",
                    "metadata": {"name": "bad-api", "namespace": "cnsec-bad"},
                    "spec": {"hosts": ["bad-api"], "http": [{"route": [{"destination": {"host": "bad-api"}}]}]},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "mesh-resilience") if finding.checkpoint_id == "CN-6"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        good_mesh = by_rule_asset[("CN-ELAS-001-service-mesh-resilience", "cnsec-good", "good-api")]
        bad_mesh = by_rule_asset[("CN-ELAS-001-service-mesh-resilience", "cnsec-bad", "bad-api")]
        worker_mesh = by_rule_asset[("CN-ELAS-001-service-mesh-resilience", "cnsec-good", "worker-no-service")]
        self.assertEqual("PASS", good_mesh.status)
        self.assertTrue(good_mesh.evidence[0].observed["has_timeout"])
        self.assertTrue(good_mesh.evidence[0].observed["has_retries"])
        self.assertTrue(good_mesh.evidence[0].observed["has_outlier_detection"])
        self.assertEqual("FAIL", bad_mesh.status)
        self.assertFalse(bad_mesh.evidence[0].observed["has_timeout"])
        self.assertFalse(bad_mesh.evidence[0].observed["has_retries"])
        self.assertFalse(bad_mesh.evidence[0].observed["has_outlier_detection"])
        self.assertEqual("NOT_APPLICABLE", worker_mesh.status)
        self.assertFalse(worker_mesh.evidence[0].observed["service_found"])

    def test_scaling_behavior_detects_scale_audit_and_statefulset_rbac(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "bad-hpa", "namespace": "cnsec-bad"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "bad-web"}, "minReplicas": 1, "maxReplicas": 1000, "metrics": [{"type": "Resource"}]},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "stateful-scale", "namespace": "cnsec-bad"},
                    "rules": [{"apiGroups": ["apps"], "resources": ["statefulsets/scale"], "verbs": ["patch"]}],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ScaleEvent",
                    "metadata": {"name": "manual-scale-1", "namespace": "cnsec-bad", "creationTimestamp": "2026-06-22T10:00:00Z"},
                    "actor": "alice@example.test",
                    "target": {"kind": "Deployment", "namespace": "cnsec-bad", "name": "bad-web"},
                    "current_replicas": 1,
                    "desired_replicas": 80,
                    "message": "manual patch scale to 80 replicas",
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "AuditLogEvent",
                    "metadata": {"name": "manual-scale-2", "namespace": "cnsec-bad", "creationTimestamp": "2026-06-22T10:03:00Z"},
                    "verb": "patch",
                    "user": {"username": "alice@example.test"},
                    "objectRef": {"resource": "deployments", "subresource": "scale", "namespace": "cnsec-bad", "name": "bad-web"},
                    "requestObject": {"spec": {"replicas": 90}},
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ScaleEvent",
                    "metadata": {"name": "manual-scale-3", "namespace": "cnsec-bad", "creationTimestamp": "2026-06-22T10:05:00Z"},
                    "actor": "alice@example.test",
                    "target": {"kind": "Deployment", "namespace": "cnsec-bad", "name": "bad-web"},
                    "current_replicas": 80,
                    "desired_replicas": 90,
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "scale-audit") if finding.checkpoint_id == "CN-26"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("FAIL", by_rule["CN-ELAS-004-hpa-max"].status)
        self.assertEqual("FAIL", by_rule["CN-ELAS-004-scale-rbac"].status)
        self.assertEqual("PASS", by_rule["CN-ELAS-004-scale-event-source"].status)
        self.assertEqual("FAIL", by_rule["CN-ELAS-004-abnormal-scale-events"].status)
        suspicious = by_rule["CN-ELAS-004-abnormal-scale-events"].evidence[0].observed
        self.assertTrue(any("untrusted scale actor" in row.get("reasons", []) for row in suspicious))
        self.assertTrue(any("scale changes >= 3 within 10m" in row.get("reasons", []) for row in suspicious))

    def test_scaling_behavior_ignores_normal_deployment_controller_rollout_events(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "web-good.1", "namespace": "cnsec-good", "creationTimestamp": "2026-06-23T05:36:51Z"},
                    "reason": "ScalingReplicaSet",
                    "message": "Scaled up replica set web-good-59585c8c94 from 0 to 1",
                    "source": {"component": "deployment-controller"},
                    "involvedObject": {"kind": "Deployment", "namespace": "cnsec-good", "name": "web-good"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "web-good.2", "namespace": "cnsec-good", "creationTimestamp": "2026-06-23T05:37:02Z"},
                    "reason": "ScalingReplicaSet",
                    "message": "Scaled down replica set web-good-747cd7d5c5 from 2 to 1",
                    "source": {"component": "deployment-controller"},
                    "involvedObject": {"kind": "Deployment", "namespace": "cnsec-good", "name": "web-good"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "web-good.3", "namespace": "cnsec-good", "creationTimestamp": "2026-06-23T05:37:02Z"},
                    "reason": "ScalingReplicaSet",
                    "message": "Scaled up replica set web-good-59585c8c94 from 1 to 2",
                    "source": {"component": "deployment-controller"},
                    "involvedObject": {"kind": "Deployment", "namespace": "cnsec-good", "name": "web-good"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "web-good.4", "namespace": "cnsec-good", "creationTimestamp": "2026-06-23T05:37:03Z"},
                    "reason": "ScalingReplicaSet",
                    "message": "Scaled down replica set web-good-747cd7d5c5 from 1 to 0",
                    "source": {"component": "deployment-controller"},
                    "involvedObject": {"kind": "Deployment", "namespace": "cnsec-good", "name": "web-good"},
                },
            ]
        )
        by_rule = {finding.rule_id: finding for finding in run_rules(index, "trusted-rollout") if finding.checkpoint_id == "CN-26"}
        self.assertEqual("PASS", by_rule["CN-ELAS-004-scale-event-source"].status)
        self.assertEqual("PASS", by_rule["CN-ELAS-004-abnormal-scale-events"].status)

    def test_scaling_behavior_validates_quota_guardrail_quality_and_hpa_cap(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "good-hpa", "namespace": "cnsec-good"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "good-web"}, "minReplicas": 2, "maxReplicas": 5, "metrics": [{"type": "Resource"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "complete", "namespace": "cnsec-good"},
                    "spec": {"hard": {"pods": "20", "requests.cpu": "2", "requests.memory": "4Gi", "limits.cpu": "4", "limits.memory": "8Gi"}},
                },
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "partial-quota-hpa", "namespace": "cnsec-partial"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "bad-web"}, "minReplicas": 2, "maxReplicas": 10, "metrics": [{"type": "Resource"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "partial", "namespace": "cnsec-partial"},
                    "spec": {"hard": {"pods": "20", "requests.cpu": "2"}},
                },
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "uncapped-high-hpa", "namespace": "cnsec-uncapped"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "bad-web"}, "minReplicas": 2, "maxReplicas": 1000, "metrics": [{"type": "Resource"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "too-large", "namespace": "cnsec-uncapped"},
                    "spec": {"hard": {"pods": "200", "requests.cpu": "20", "requests.memory": "40Gi", "limits.cpu": "40", "limits.memory": "80Gi"}},
                },
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-capped", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "autoscaling/v2",
                    "kind": "HorizontalPodAutoscaler",
                    "metadata": {"name": "capped-high-hpa", "namespace": "cnsec-capped"},
                    "spec": {"scaleTargetRef": {"kind": "Deployment", "name": "capped-web"}, "minReplicas": 2, "maxReplicas": 1000, "metrics": [{"type": "Resource"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "ResourceQuota",
                    "metadata": {"name": "caps-hpa", "namespace": "cnsec-capped"},
                    "spec": {"hard": {"pods": "20", "requests.cpu": "2", "requests.memory": "4Gi", "limits.cpu": "4", "limits.memory": "8Gi"}},
                },
            ]
        )
        guardrails = [
            finding for finding in run_rules(index, "quota-guardrail")
            if finding.rule_id == "CN-ELAS-004-resourcequota-guardrail"
        ]
        by_hpa = {finding.asset.name: finding for finding in guardrails}
        self.assertEqual("PASS", by_hpa["good-hpa"].status)
        self.assertEqual([], by_hpa["good-hpa"].evidence[0].observed["reasons"])
        self.assertEqual("FAIL", by_hpa["partial-quota-hpa"].status)
        self.assertIn("requests.memory", by_hpa["partial-quota-hpa"].evidence[0].observed["quality"]["missing"])
        self.assertEqual("FAIL", by_hpa["uncapped-high-hpa"].status)
        self.assertIn("pods quota does not cap abnormal HPA maxReplicas", by_hpa["uncapped-high-hpa"].evidence[0].observed["reasons"])
        self.assertEqual("PASS", by_hpa["capped-high-hpa"].status)
        self.assertTrue(by_hpa["capped-high-hpa"].evidence[0].observed["pod_quota_caps_high_hpa"])

    def test_lifecycle_governance_enforces_business_cleanup_and_pvc_retention_evidence(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "default"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "other-business"}},
                {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "good-job", "namespace": "cnsec-good"}, "spec": {"ttlSecondsAfterFinished": 300}},
                {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "bad-job", "namespace": "cnsec-bad"}, "spec": {"template": {"spec": {"containers": [{"name": "job", "image": "busybox"}]}}}},
                {
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "metadata": {"name": "bad-cron", "namespace": "cnsec-bad"},
                    "spec": {"successfulJobsHistoryLimit": 10, "failedJobsHistoryLimit": 10, "concurrencyPolicy": "Allow"},
                },
                {
                    "apiVersion": "batch/v1",
                    "kind": "CronJob",
                    "metadata": {"name": "default-cron", "namespace": "default"},
                    "spec": {"concurrencyPolicy": "Allow"},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "uses-data", "namespace": "cnsec-good", "ownerReferences": [{"kind": "Deployment", "name": "web"}]},
                    "spec": {"volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "used-data"}}], "containers": [{"name": "web", "image": "nginx"}]},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "db", "namespace": "cnsec-good"},
                    "spec": {
                        "replicas": 3,
                        "volumeClaimTemplates": [{"metadata": {"name": "data"}}],
                        "template": {"spec": {"containers": [{"name": "db", "image": "postgres"}]}},
                    },
                },
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "used-data", "namespace": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "used-data", "namespace": "other-business"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data-db-0", "namespace": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data-db-1", "namespace": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "data-db-2", "namespace": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "snap-data", "namespace": "cnsec-good"}},
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1",
                    "kind": "VolumeSnapshot",
                    "metadata": {"name": "snap-data-daily", "namespace": "cnsec-good"},
                    "spec": {"source": {"persistentVolumeClaimName": "snap-data"}},
                },
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "owned-data", "namespace": "cnsec-good", "ownerReferences": [{"kind": "StatefulSet", "name": "db"}]}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "orphan-data", "namespace": "cnsec-bad"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "default-orphan", "namespace": "default"}},
                {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "finished", "namespace": "cnsec-bad", "ownerReferences": [{"kind": "Job", "name": "bad-job"}]}, "status": {"phase": "Succeeded"}},
                {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "debug", "namespace": "default"}, "status": {"phase": "Running"}},
            ]
        )
        findings = [finding for finding in run_rules(index, "lifecycle") if finding.checkpoint_id == "CN-27"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-job-ttl", "cnsec-good", "good-job")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-005-job-ttl", "cnsec-bad", "bad-job")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-005-cronjob-retention", "cnsec-bad", "bad-cron")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-ELAS-005-cronjob-retention", "default", "default-cron")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "used-data")].status)
        self.assertTrue(by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "used-data")].evidence[0].observed["referenced"])
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-005-orphan-pvc", "other-business", "used-data")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "data-db-0")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "data-db-1")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "data-db-2")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "snap-data")].status)
        self.assertTrue(by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "snap-data")].evidence[0].observed["backup_evidence"])
        self.assertEqual("PASS", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-good", "owned-data")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-005-orphan-pvc", "cnsec-bad", "orphan-data")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-ELAS-005-orphan-pvc", "default", "default-orphan")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-ELAS-005-pod-owner-lifecycle", "cnsec-bad", "finished")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-ELAS-005-pod-owner-lifecycle", "default", "debug")].status)

    def test_scaling_behavior_classifies_platform_bound_clusterroles_as_system_review(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "calico-kube-controllers"},
                    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get", "list", "watch", "patch", "update"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "calico-kube-controllers"},
                    "subjects": [{"kind": "ServiceAccount", "name": "calico-kube-controllers", "namespace": "kube-system"}],
                    "roleRef": {"kind": "ClusterRole", "name": "calico-kube-controllers", "apiGroup": "rbac.authorization.k8s.io"},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "tenant-scale-admin"},
                    "rules": [{"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["patch", "update"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "tenant-scale-admin"},
                    "subjects": [{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}],
                    "roleRef": {"kind": "ClusterRole", "name": "tenant-scale-admin", "apiGroup": "rbac.authorization.k8s.io"},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "metrics-scale-reader"},
                    "rules": [{"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get", "patch"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "metrics-scale-reader"},
                    "subjects": [{"kind": "ServiceAccount", "name": "metrics-server", "namespace": "kube-system"}],
                    "roleRef": {"kind": "ClusterRole", "name": "metrics-scale-reader", "apiGroup": "rbac.authorization.k8s.io"},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": "kube-system-human-scale"},
                    "rules": [{"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["patch"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": "kube-system-human-scale"},
                    "subjects": [{"kind": "User", "name": "ops@example.test"}],
                    "roleRef": {"kind": "ClusterRole", "name": "kube-system-human-scale", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        finding = [finding for finding in run_rules(index, "scale-rbac-binding-context") if finding.rule_id == "CN-ELAS-004-scale-rbac"][0]
        observed = finding.evidence[0].observed
        self.assertTrue(any(row["role"] == "ClusterRole/_cluster/calico-kube-controllers" for row in observed["system_scale_review"]))
        self.assertTrue(any(row["role"] == "ClusterRole/_cluster/metrics-scale-reader" for row in observed["system_scale_review"]))
        self.assertTrue(any(row["role"] == "ClusterRole/_cluster/tenant-scale-admin" for row in observed["business_scale_risks"]))
        self.assertTrue(any(row["role"] == "ClusterRole/_cluster/kube-system-human-scale" for row in observed["business_scale_risks"]))
        self.assertFalse(any(row["role"] == "ClusterRole/_cluster/calico-kube-controllers" for row in observed["business_scale_risks"]))

    def test_container_immutability_context_hash_and_orphan_secret(self) -> None:
        good_template = {"metadata": {"labels": {"app": "good"}}, "spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "web", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}]}}
        import hashlib
        import json

        baseline = hashlib.sha256(json.dumps(good_template["spec"], sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good", "annotations": {"cnsec.io/spec-hash": baseline}},
                    "spec": {"template": good_template},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad"}}, "spec": {"containers": [{"name": "web", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": True}}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "metadata": {"name": "kube-proxy", "namespace": "kube-system"},
                    "spec": {"template": {"metadata": {"labels": {"k8s-app": "kube-proxy"}}, "spec": {"containers": [{"name": "proxy", "image": "kube-proxy"}]}}},
                },
                {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "kube-root-ca.crt", "namespace": "cnsec-good"}, "data": {"ca.crt": "demo"}},
                {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "no-ttl", "namespace": "cnsec-bad"}, "spec": {"template": {"spec": {"containers": [{"name": "job", "image": "busybox"}]}}}},
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "unused-secret", "namespace": "cnsec-bad"}, "type": "Opaque", "data": {"password": "czNjcjN0"}},
            ]
        )
        secret = index.by_kind("Secret")[0]
        self.assertNotIn("data", secret)
        self.assertEqual(["password"], secret["data_keys"])
        findings = run_rules(index, "immutability-context")
        relevant = [finding for finding in findings if finding.checkpoint_id == "CN-23"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in relevant}
        self.assertEqual("PASS", by_rule_asset[("CN-IMM-002-spec-hash-baseline", "cnsec-good", "good-web")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-IMM-002-rootfs-readonly", "cnsec-good", "good-web")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-IMM-002-run-as-non-root", "cnsec-bad", "bad-web")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-IMM-002-rootfs-readonly", "cnsec-bad", "bad-web")].status)
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-IMM-002-run-as-non-root", "kube-system", "kube-proxy")].status)
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-IMM-002-rootfs-readonly", "kube-system", "kube-proxy")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-IMM-002-job-ttl", "cnsec-bad", "no-ttl")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-IMM-002-orphan-secret", "cnsec-bad", "unused-secret")].status)
        self.assertNotIn(("CN-IMM-002-orphan-configmap", "cnsec-good", "kube-root-ca.crt"), by_rule_asset)

    def test_immutable_deployment_marks_platform_digest_and_rootfs_as_not_applicable(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "metrics-server", "namespace": "kube-system"},
                    "spec": {"template": {"spec": {"containers": [{"name": "metrics", "image": "registry.k8s.io/metrics-server:v0.7.1"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:latest"}]}}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "immutable-platform-review") if finding.checkpoint_id == "CN-22"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-IMM-001-image-pinned-digest", "kube-system", "metrics-server")].status)
        self.assertEqual("NOT_APPLICABLE", by_rule_asset[("CN-IMM-001-rootfs-readonly", "kube-system", "metrics-server")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-IMM-001-image-pinned-digest", "cnsec-good", "good-web")].status)

    def test_immutable_deployment_detects_container_ssh_and_exec_rbac(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx@sha256:abc", "securityContext": {"readOnlyRootFilesystem": True}}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:latest", "ports": [{"name": "ssh", "containerPort": 22}], "command": ["/usr/sbin/sshd", "-D"], "securityContext": {"readOnlyRootFilesystem": False}}]}}},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "debug", "namespace": "cnsec-bad"},
                    "rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "debug-binding", "namespace": "cnsec-bad"},
                    "subjects": [{"kind": "Group", "name": "developers"}],
                    "roleRef": {"kind": "Role", "name": "debug", "apiGroup": "rbac.authorization.k8s.io"},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "immutable-ssh-rbac") if finding.checkpoint_id == "CN-22"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        good_ssh = by_rule_asset[("CN-IMM-001-no-ssh-container", "cnsec-good", "good-web")]
        self.assertEqual("PASS", good_ssh.status)
        bad_ssh = by_rule_asset[("CN-IMM-001-no-ssh-container", "cnsec-bad", "bad-web")]
        self.assertEqual("FAIL", bad_ssh.status)
        self.assertTrue(bad_ssh.evidence[0].observed["exposes_ssh_port"])
        self.assertTrue(bad_ssh.evidence[0].observed["runs_sshd"])
        exec_rbac = [finding for finding in findings if finding.rule_id == "CN-IMM-001-exec-rbac"][0]
        self.assertEqual("FAIL", exec_rbac.status)
        self.assertEqual("Group:developers", exec_rbac.evidence[0].observed[0]["subject"])
        self.assertEqual("RoleBinding/cnsec-bad/debug-binding", exec_rbac.evidence[0].observed[0]["binding"])

    def test_container_immutability_detects_historical_spec_hash_drift(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad"}}, "spec": {"containers": [{"name": "web", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}]}}},
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "SpecHashBaseline",
                    "metadata": {"name": "bad-web-previous"},
                    "spec": {
                        "asset": {"kind": "Deployment", "namespace": "cnsec-bad", "name": "bad-web"},
                        "spec_hash": "0" * 64,
                    },
                },
            ]
        )
        finding = [
            finding
            for finding in run_rules(index, "spec-hash-drift")
            if finding.checkpoint_id == "CN-23"
            and finding.rule_id == "CN-IMM-002-spec-hash-baseline"
            and finding.asset
            and finding.asset.name == "bad-web"
        ][0]
        self.assertEqual("FAIL", finding.status)
        self.assertEqual("SpecHashBaseline", finding.evidence[0].observed["baseline_source"]["source"])
        self.assertEqual("0" * 64, finding.evidence[0].observed["baseline"])
        self.assertNotEqual(finding.evidence[0].observed["baseline"], finding.evidence[0].observed["current_hash"])

    def test_container_immutability_reads_asset_spec_hash_baseline(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"metadata": {"labels": {"app": "good"}}, "spec": {"containers": [{"name": "web", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}]}}},
                },
            ]
        )
        workload = index.by_kind("Deployment")[0]
        current_hash = _spec_hash(workload)
        index = ResourceIndex(
            [
                *index.objects,
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "Asset",
                    "metadata": {"name": "good-web-asset"},
                    "asset_kind": "Deployment",
                    "asset_namespace": "cnsec-good",
                    "asset_name": "good-web",
                    "spec_hash": current_hash,
                },
            ]
        )
        finding = [
            finding
            for finding in run_rules(index, "asset-spec-hash")
            if finding.checkpoint_id == "CN-23"
            and finding.rule_id == "CN-IMM-002-spec-hash-baseline"
            and finding.asset
            and finding.asset.name == "good-web"
        ][0]
        self.assertEqual("PASS", finding.status)
        self.assertEqual("Asset", finding.evidence[0].observed["baseline_source"]["source"])
        self.assertEqual(current_hash, finding.evidence[0].observed["baseline"])

    def test_container_immutability_flags_completed_pods_and_old_replicasets_for_cleanup(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "api", "namespace": "cnsec-bad"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "api"}},
                        "template": {
                            "metadata": {"labels": {"app": "api"}},
                            "spec": {"containers": [{"name": "api", "image": "nginx", "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}]},
                        },
                    },
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "metadata": {
                        "name": "api-5f76d4c4b5",
                        "namespace": "cnsec-bad",
                        "annotations": {"deployment.kubernetes.io/revision": "3"},
                        "ownerReferences": [{"kind": "Deployment", "name": "api", "controller": True}],
                    },
                    "spec": {"replicas": 0},
                    "status": {"replicas": 0, "readyReplicas": 0},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "api-finished", "namespace": "cnsec-bad"},
                    "status": {"phase": "Succeeded"},
                    "spec": {"containers": [{"name": "api", "image": "busybox"}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "api-crash", "namespace": "cnsec-bad"},
                    "status": {"phase": "Failed"},
                    "spec": {"containers": [{"name": "api", "image": "busybox"}]},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "immutability-cleanup") if finding.checkpoint_id == "CN-23"]

        completed_assets = {
            finding.asset.key
            for finding in findings
            if finding.asset
            and finding.asset.kind == "Pod"
            and finding.status == "FAIL"
            and finding.evidence
            and isinstance(finding.evidence[0].observed, dict)
            and finding.evidence[0].observed.get("phase") in {"Succeeded", "Failed"}
        }
        self.assertEqual({"Pod/cnsec-bad/api-crash", "Pod/cnsec-bad/api-finished"}, completed_assets)

        stale_rs = next(
            finding
            for finding in findings
            if finding.asset and finding.asset.kind == "ReplicaSet" and finding.asset.name == "api-5f76d4c4b5"
        )
        self.assertEqual("FAIL", stale_rs.status)
        stale_observed = json.dumps(stale_rs.evidence[0].observed, ensure_ascii=False).lower()
        self.assertIn("revision", stale_observed)
        self.assertIn("0", stale_observed)

    def test_container_posture_deduplicates_controller_owned_pods(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "kube-system"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad-web"}}, "spec": {"containers": [{"name": "web", "image": "nginx:latest", "securityContext": {"allowPrivilegeEscalation": True}}]}}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "bad-web-abc", "namespace": "cnsec-bad", "ownerReferences": [{"kind": "ReplicaSet", "name": "bad-web-rs", "controller": True}]},
                    "spec": {"containers": [{"name": "web", "image": "nginx:latest", "securityContext": {"allowPrivilegeEscalation": True}}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "debug-shell", "namespace": "cnsec-bad"},
                    "spec": {"containers": [{"name": "debug", "image": "busybox", "securityContext": {"allowPrivilegeEscalation": True}}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "kube-apiserver-node1", "namespace": "kube-system", "ownerReferences": [{"kind": "Node", "name": "node1"}]},
                    "spec": {"containers": [{"name": "apiserver", "image": "registry.k8s.io/kube-apiserver:v1.30.0"}]},
                },
            ]
        )

        findings = run_rules(index, "posture-dedupe")
        posture_findings = [
            finding
            for finding in findings
            if finding.checkpoint_id in {"CN-22", "CN-23"}
            and finding.rule_id in {"CN-IMM-001-image-pinned-digest", "CN-IMM-002-run-as-non-root"}
        ]
        assets_by_rule = {
            rule_id: {finding.asset.key for finding in posture_findings if finding.rule_id == rule_id and finding.asset}
            for rule_id in {"CN-IMM-001-image-pinned-digest", "CN-IMM-002-run-as-non-root"}
        }

        expected_assets = {
            "Deployment/cnsec-bad/bad-web",
            "Pod/cnsec-bad/debug-shell",
            "Pod/kube-system/kube-apiserver-node1",
        }
        self.assertEqual(expected_assets, assets_by_rule["CN-IMM-001-image-pinned-digest"])
        self.assertEqual(expected_assets, assets_by_rule["CN-IMM-002-run-as-non-root"])
        self.assertNotIn("Pod/cnsec-bad/bad-web-abc", assets_by_rule["CN-IMM-001-image-pinned-digest"])
        self.assertNotIn("Pod/cnsec-bad/bad-web-abc", assets_by_rule["CN-IMM-002-run-as-non-root"])

    def test_stateful_data_security_covers_tls_service_and_csi_evidence(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-bad", "labels": {"purpose": "cnsec-demo"}}},
                {
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": "encrypted-sc"},
                    "parameters": {"encrypted": "true", "kmsKeyId": "demo-key"},
                    "volumeBindingMode": "WaitForFirstConsumer",
                },
                {
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": "plain-sc"},
                    "parameters": {},
                },
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "good-data", "namespace": "cnsec-good"}, "spec": {"storageClassName": "encrypted-sc"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "bad-data", "namespace": "cnsec-bad"}, "spec": {"storageClassName": "plain-sc"}},
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db-tls", "namespace": "cnsec-good"}, "type": "kubernetes.io/tls", "data": {"tls.crt": "x", "tls.key": "y"}},
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1",
                    "kind": "VolumeSnapshot",
                    "metadata": {"name": "good-data-snapshot", "namespace": "cnsec-good"},
                    "spec": {"source": {"persistentVolumeClaimName": "good-data"}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "db-good", "namespace": "cnsec-good"},
                    "spec": {
                        "serviceName": "db-good",
                        "selector": {"matchLabels": {"app": "db-good"}},
                        "template": {
                            "metadata": {"labels": {"app": "db-good"}},
                            "spec": {
                                "volumes": [
                                    {"name": "tls", "secret": {"secretName": "db-tls"}},
                                    {"name": "external-secrets", "csi": {"driver": "secrets-store.csi.k8s.io", "volumeAttributes": {"secretProviderClass": "db-good"}}},
                                    {"name": "data", "persistentVolumeClaim": {"claimName": "good-data"}},
                                ],
                                "containers": [{"name": "db", "image": "postgres", "env": [{"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-tls", "key": "password"}}}]}],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "db-bad", "namespace": "cnsec-bad"},
                    "spec": {
                        "serviceName": "db-bad",
                        "selector": {"matchLabels": {"app": "db-bad"}},
                        "template": {
                            "metadata": {"labels": {"app": "db-bad"}},
                            "spec": {
                                "hostNetwork": True,
                                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "bad-data"}}],
                                "containers": [{"name": "db", "image": "postgres", "ports": [{"containerPort": 5432, "hostPort": 30432}], "env": [{"name": "POSTGRES_PASSWORD", "value": "plain"}]}],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "db-no-service", "namespace": "cnsec-good"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "db-no-service"}},
                        "template": {
                            "metadata": {"labels": {"app": "db-no-service"}},
                            "spec": {"containers": [{"name": "db", "image": "postgres"}]},
                        },
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "postgres-debug", "namespace": "cnsec-bad", "labels": {"app": "postgres-debug"}},
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "postgres", "image": "postgres:16", "ports": [{"containerPort": 5432, "hostPort": 31432}]}],
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "orders-store", "namespace": "cnsec-bad", "annotations": {"cnsec.io/data-role": "database"}},
                    "spec": {"containers": [{"name": "store", "image": "registry.example.test/business/orders-store:v1", "ports": [{"containerPort": 9000, "hostPort": 31900}]}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "db-bad-0", "namespace": "cnsec-bad", "labels": {"app": "db-bad"}, "ownerReferences": [{"kind": "StatefulSet", "name": "db-bad", "controller": True}]},
                    "spec": {"hostNetwork": True, "containers": [{"name": "postgres", "image": "postgres:16", "ports": [{"containerPort": 5432, "hostPort": 32432}]}]},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "db-data-debug-mounter", "namespace": "cnsec-bad"},
                    "spec": {
                        "containers": [{"name": "debug", "image": "busybox:latest"}],
                        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "bad-data"}}],
                    },
                },
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "db-good", "namespace": "cnsec-good"}, "spec": {"type": "ClusterIP", "selector": {"app": "db-good"}, "ports": [{"port": 5432}]}},
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "db-bad", "namespace": "cnsec-bad"}, "spec": {"type": "NodePort", "selector": {"app": "db-bad"}, "ports": [{"port": 5432, "nodePort": 30432}]}},
                {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "db-good-deny", "namespace": "cnsec-good"}, "spec": {"podSelector": {}}},
                {"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": {"name": "db-good-backup", "namespace": "cnsec-good"}},
            ]
        )
        findings = run_rules(index, "stateful-data")
        cn37 = [finding for finding in findings if finding.checkpoint_id == "CN-37"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in cn37}
        good_np = by_rule_asset[("CN-PER-003-stateful-networkpolicy", "cnsec-good", "db-good")]
        self.assertEqual("PASS", good_np.status)
        self.assertTrue(good_np.evidence[0].observed["policies"][0]["matches_statefulset"])
        self.assertTrue(good_np.evidence[0].observed["policies"][0]["default_deny"])
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-database-service-exposure", "cnsec-good", "db-good")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-database-service-exposure", "cnsec-bad", "db-bad")].status)
        no_service = by_rule_asset[("CN-PER-003-database-service-exposure", "cnsec-good", "db-no-service")]
        self.assertEqual("WARN", no_service.status)
        self.assertFalse(no_service.evidence[0].observed["service_found"])
        self.assertEqual("no matching Service evidence", no_service.evidence[0].observed["reason"])
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-pod-network-exposure", "cnsec-good", "db-good")].status)
        host_exposure = by_rule_asset[("CN-PER-003-pod-network-exposure", "cnsec-bad", "db-bad")]
        self.assertEqual("FAIL", host_exposure.status)
        self.assertTrue(host_exposure.evidence[0].observed["hostNetwork"])
        self.assertEqual(30432, host_exposure.evidence[0].observed["hostPorts"][0]["hostPort"])
        pod_exposure = by_rule_asset[("CN-PER-003-pod-network-exposure", "cnsec-bad", "postgres-debug")]
        self.assertEqual("FAIL", pod_exposure.status)
        self.assertEqual(31432, pod_exposure.evidence[0].observed["hostPorts"][0]["hostPort"])
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-stateful-networkpolicy", "cnsec-bad", "postgres-debug")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-secret-reference", "cnsec-bad", "postgres-debug")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-tls-or-mtls", "cnsec-bad", "postgres-debug")].status)
        annotated_pod_exposure = by_rule_asset[("CN-PER-003-pod-network-exposure", "cnsec-bad", "orders-store")]
        self.assertEqual("FAIL", annotated_pod_exposure.status)
        self.assertEqual(31900, annotated_pod_exposure.evidence[0].observed["hostPorts"][0]["hostPort"])
        self.assertNotIn(("CN-PER-003-pod-network-exposure", "cnsec-bad", "db-bad-0"), by_rule_asset)
        self.assertFalse(any(finding.asset and finding.asset.name == "db-data-debug-mounter" for finding in cn37))
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-tls-or-mtls", "cnsec-good", "db-good")].status)
        bad_tls = by_rule_asset[("CN-PER-003-tls-or-mtls", "cnsec-bad", "db-bad")]
        self.assertEqual("FAIL", bad_tls.status)
        self.assertEqual("demo-risk", bad_tls.evidence[0].observed["tier"])
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-kms-or-csi-secret-store", "cnsec-good", "db-good")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-kms-or-csi-secret-store", "cnsec-bad", "db-bad")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-secret-reference", "cnsec-bad", "db-bad")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-backup-or-snapshot", "cnsec-bad", "db-bad")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-pvc-data-protection", "cnsec-good", "good-data")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-pvc-data-protection", "cnsec-bad", "bad-data")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-pvc-encryption-evidence", "cnsec-bad", "db-bad")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-pvc-namespace-isolation", "cnsec-good", "good-data")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-003-pvc-namespace-isolation", "cnsec-bad", "bad-data")].status)
        inventory = next(finding for finding in cn37 if finding.rule_id == "CN-PER-003-data-protection-inventory")
        self.assertEqual("PASS", inventory.status)
        self.assertEqual(5, inventory.evidence[0].observed["workload_count"])
        self.assertEqual(2, inventory.evidence[0].observed["pvc_count"])
        self.assertIn("FAIL", inventory.evidence[0].observed["control_status_count"])
        self.assertNotIn("Pod/cnsec-bad/db-data-debug-mounter", [row["asset"] for row in inventory.evidence[0].observed["workloads"]])

    def test_stateful_backup_requires_bound_workload_evidence(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-data"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "orders-data", "namespace": "cnsec-data"}, "spec": {"storageClassName": "plain-sc"}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "orders-db", "namespace": "cnsec-data"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "orders-db"}},
                        "template": {
                            "metadata": {"labels": {"app": "orders-db"}},
                            "spec": {
                                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "orders-data"}}],
                                "containers": [{"name": "postgres", "image": "postgres:16"}],
                            },
                        },
                    },
                },
                {"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": {"name": "unbound-backup", "namespace": "velero"}, "spec": {}},
                {
                    "apiVersion": "velero.io/v1",
                    "kind": "Backup",
                    "metadata": {"name": "orders-bound-backup", "namespace": "velero"},
                    "spec": {
                        "includedNamespaces": ["cnsec-data"],
                        "includedResources": ["statefulsets", "persistentvolumeclaims"],
                    },
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "stateful-bound-backup") if finding.checkpoint_id == "CN-37"]
        backup = next(finding for finding in findings if finding.rule_id == "CN-PER-003-backup-or-snapshot")
        self.assertEqual("PASS", backup.status)
        self.assertEqual(["Backup/velero/orders-bound-backup"], backup.evidence[0].observed["backup_evidence"])

    def test_stateful_data_security_covers_database_deployment_and_deduplicates_replica_pod(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-good"}},
                {
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": "encrypted-sc"},
                    "parameters": {"encrypted": "true", "kmsKeyId": "demo-key"},
                },
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "orders-data", "namespace": "cnsec-good"}, "spec": {"storageClassName": "encrypted-sc"}},
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "orders-tls", "namespace": "cnsec-good"}, "type": "kubernetes.io/tls", "data": {"tls.crt": "x", "tls.key": "y"}},
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1",
                    "kind": "VolumeSnapshot",
                    "metadata": {"name": "orders-data-snapshot", "namespace": "cnsec-good"},
                    "spec": {"source": {"persistentVolumeClaimName": "orders-data"}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "orders-db", "namespace": "cnsec-good", "annotations": {"cnsec.io/data-role": "database"}},
                    "spec": {
                        "selector": {"matchLabels": {"app": "orders-db"}},
                        "template": {
                            "metadata": {"labels": {"app": "orders-db"}},
                            "spec": {
                                "volumes": [
                                    {"name": "tls", "secret": {"secretName": "orders-tls"}},
                                    {"name": "ext-secrets", "csi": {"driver": "secrets-store.csi.k8s.io", "volumeAttributes": {"secretProviderClass": "orders-db"}}},
                                    {"name": "data", "persistentVolumeClaim": {"claimName": "orders-data"}},
                                ],
                                "containers": [{"name": "db", "image": "postgres:16", "env": [{"name": "POSTGRES_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "orders-tls", "key": "password"}}}]}],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "orders-db-abc", "namespace": "cnsec-good", "ownerReferences": [{"kind": "ReplicaSet", "name": "orders-db-rs", "controller": True}], "labels": {"app": "orders-db"}},
                    "spec": {
                        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "orders-data"}}],
                        "containers": [{"name": "db", "image": "postgres:16"}],
                    },
                },
                {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "orders-db", "namespace": "cnsec-good"}, "spec": {"type": "ClusterIP", "selector": {"app": "orders-db"}, "ports": [{"port": 5432}]}},
                {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "orders-db-deny", "namespace": "cnsec-good"}, "spec": {"podSelector": {"matchLabels": {"app": "orders-db"}}, "policyTypes": ["Ingress"]}},
                {"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": {"name": "orders-db-backup", "namespace": "velero"}, "spec": {"includedNamespaces": ["cnsec-good"], "includedResources": ["deployments", "persistentvolumeclaims"], "labelSelector": {"matchLabels": {"app": "orders-db"}}}},
            ]
        )
        findings = [finding for finding in run_rules(index, "deployment-stateful-data") if finding.checkpoint_id == "CN-37"]
        by_rule_asset = {(finding.rule_id, finding.asset.namespace if finding.asset else None, finding.asset.name if finding.asset else None): finding for finding in findings}
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-stateful-networkpolicy", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-database-service-exposure", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-secret-reference", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-tls-or-mtls", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-pvc-encryption-evidence", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-kms-or-csi-secret-store", "cnsec-good", "orders-db")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-003-backup-or-snapshot", "cnsec-good", "orders-db")].status)
        self.assertNotIn(("CN-PER-003-secret-reference", "cnsec-good", "orders-db-abc"), by_rule_asset)
        inventory = next(finding for finding in findings if finding.rule_id == "CN-PER-003-data-protection-inventory")
        assets = [row["asset"] for row in inventory.evidence[0].observed["workloads"]]
        self.assertIn("Deployment/cnsec-good/orders-db", assets)
        self.assertNotIn("Pod/cnsec-good/orders-db-abc", assets)

    def test_cloud_native_adapter_inventory_includes_security_spec_summary(self) -> None:
        with TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "objects.yaml"
            manifest.write_text(
                """
apiVersion: v1
kind: Service
metadata:
  name: postgres-bad
  namespace: cnsec-bad
spec:
  type: NodePort
  selector:
    app: postgres-bad
  ports:
  - name: postgres
    port: 5432
    targetPort: 5432
    nodePort: 30432
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: db-data
  namespace: cnsec-bad
spec:
  storageClassName: insecure-local
  accessModes:
  - ReadWriteOnce
""",
                encoding="utf-8",
            )
            result = CloudNativeAdapter().evaluate(AssessmentRequest(task_id="inventory-summary", manifest=str(manifest)))
        rows = {(row["kind"], row["namespace"], row["name"]): row for row in result.raw_summary["resource_inventory"]}
        service_summary = rows[("Service", "cnsec-bad", "postgres-bad")]["spec_summary"]
        pvc_summary = rows[("PersistentVolumeClaim", "cnsec-bad", "db-data")]["spec_summary"]
        self.assertEqual("NodePort", service_summary["type"])
        self.assertEqual(30432, service_summary["ports"][0]["nodePort"])
        self.assertEqual("insecure-local", pvc_summary["storageClassName"])
        self.assertEqual(["ReadWriteOnce"], pvc_summary["accessModes"])

    def test_stateful_networkpolicy_must_select_statefulset_pods(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "cnsec-data"}},
                {
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": "orders-db", "namespace": "cnsec-data"},
                    "spec": {
                        "selector": {"matchLabels": {"app": "orders-db"}},
                        "template": {
                            "metadata": {"labels": {"app": "orders-db"}},
                            "spec": {"containers": [{"name": "postgres", "image": "postgres:16"}]},
                        },
                    },
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "web-only", "namespace": "cnsec-data"},
                    "spec": {"podSelector": {"matchLabels": {"app": "web"}}, "policyTypes": ["Ingress"], "ingress": []},
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "allow-all-db", "namespace": "cnsec-data"},
                    "spec": {"podSelector": {"matchLabels": {"app": "orders-db"}}, "policyTypes": ["Ingress"], "ingress": [{}]},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "stateful-netpol-selector") if finding.checkpoint_id == "CN-37"]
        by_rule = {finding.rule_id: finding for finding in findings}
        networkpolicy = by_rule["CN-PER-003-stateful-networkpolicy"]
        self.assertEqual("FAIL", networkpolicy.status)
        self.assertEqual("business", networkpolicy.evidence[0].observed["tier"])
        self.assertFalse(networkpolicy.evidence[0].observed["policies"][0]["matches_statefulset"])
        self.assertTrue(networkpolicy.evidence[0].observed["policies"][1]["matches_subject"])
        self.assertFalse(networkpolicy.evidence[0].observed["policies"][1]["restricts_ingress"])
        self.assertEqual("no restricted ingress NetworkPolicy selects this workload", networkpolicy.evidence[0].observed["reason"])

    def test_pv_security_covers_reclaim_access_and_snapshot_evidence(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": "encrypted-sc"},
                    "provisioner": "csi.example.test",
                    "parameters": {"encrypted": "true", "kmsKeyId": "demo-key"},
                    "volumeBindingMode": "WaitForFirstConsumer",
                    "reclaimPolicy": "Retain",
                    "allowVolumeExpansion": True,
                },
                {
                    "apiVersion": "storage.k8s.io/v1",
                    "kind": "StorageClass",
                    "metadata": {"name": "plain-sc"},
                    "provisioner": "kubernetes.io/no-provisioner",
                    "parameters": {},
                    "volumeBindingMode": "Immediate",
                    "reclaimPolicy": "Delete",
                },
                {"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass", "metadata": {"name": "encrypted-snap"}, "driver": "csi.example.test"},
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolume",
                    "metadata": {"name": "good-pv"},
                    "spec": {"storageClassName": "encrypted-sc", "persistentVolumeReclaimPolicy": "Retain", "accessModes": ["ReadWriteOnce"], "csi": {"driver": "csi.example.test", "volumeHandle": "vol-1"}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolume",
                    "metadata": {"name": "bad-pv"},
                    "spec": {"storageClassName": "plain-sc", "persistentVolumeReclaimPolicy": "Delete", "accessModes": ["ReadWriteMany"], "hostPath": {"path": "/tmp/data"}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolume",
                    "metadata": {"name": "compensated-local-pv"},
                    "spec": {
                        "storageClassName": "encrypted-sc",
                        "persistentVolumeReclaimPolicy": "Retain",
                        "accessModes": ["ReadWriteOnce"],
                        "hostPath": {"path": "/tmp/compensated"},
                        "claimRef": {"namespace": "cnsec-good", "name": "good-data"},
                    },
                },
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "good-data", "namespace": "cnsec-good"}, "spec": {"storageClassName": "encrypted-sc", "accessModes": ["ReadWriteOnce"]}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "bad-data", "namespace": "cnsec-bad"}, "spec": {"storageClassName": "plain-sc", "accessModes": ["ReadWriteMany"]}},
                {
                    "apiVersion": "snapshot.storage.k8s.io/v1",
                    "kind": "VolumeSnapshot",
                    "metadata": {"name": "good-data-snapshot", "namespace": "cnsec-good"},
                    "spec": {"source": {"persistentVolumeClaimName": "good-data"}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "pv-security") if finding.checkpoint_id == "CN-36"]
        by_rule_asset = {(finding.rule_id, finding.asset.name if finding.asset else None): finding for finding in findings}
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-storageclass-encryption", "encrypted-sc")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-PER-002-storageclass-encryption", "plain-sc")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-storageclass-reclaim-policy", "encrypted-sc")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-PER-002-storageclass-reclaim-policy", "plain-sc")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-snapshot-backup-evidence", "encrypted-sc")].status)
        self.assertEqual("FAIL", by_rule_asset[("CN-PER-002-hostpath-local-pv", "bad-pv")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-hostpath-local-pv", "compensated-local-pv")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-PER-002-pv-access-mode", "bad-pv")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-pvc-storage-encryption", "good-data")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-PER-002-pvc-storage-encryption", "bad-data")].status)
        self.assertEqual("PASS", by_rule_asset[("CN-PER-002-pvc-backup-evidence", "good-data")].status)
        self.assertEqual("WARN", by_rule_asset[("CN-PER-002-pvc-backup-evidence", "bad-data")].status)

    def test_registry_security_covers_endpoint_pull_secret_audit_and_vuln_evidence(self) -> None:
        index = ResourceIndex(
            [
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "registry-good-pull", "namespace": "cnsec-good"}, "type": "kubernetes.io/dockerconfigjson", "data": {".dockerconfigjson": "redacted"}},
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "registry-sa-pull", "namespace": "cnsec-good"}, "type": "kubernetes.io/dockerconfigjson", "data": {".dockerconfigjson": "redacted"}},
                {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "registry-opaque", "namespace": "cnsec-bad"}, "type": "Opaque", "data": {"token": "redacted"}},
                {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "puller", "namespace": "cnsec-good"}, "imagePullSecrets": [{"name": "registry-sa-pull"}]},
                {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "opaque-puller", "namespace": "cnsec-bad"}, "imagePullSecrets": [{"name": "registry-opaque"}]},
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "good-web", "namespace": "cnsec-good"},
                    "spec": {
                        "template": {
                            "metadata": {"labels": {"app": "good-web"}},
                            "spec": {
                                "imagePullSecrets": [{"name": "registry-good-pull"}],
                                "containers": [{"name": "web", "image": "registry.good.example/team/web@sha256:abc"}],
                            },
                        }
                    },
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "sa-private-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"serviceAccountName": "puller", "containers": [{"name": "web", "image": "registry.sa.example/team/web:v1"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "bad-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "bad-web"}}, "spec": {"containers": [{"name": "web", "image": "10.20.0.1:5000/insecure/nginx:latest"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "private-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"metadata": {"labels": {"app": "private-web"}}, "spec": {"containers": [{"name": "web", "image": "registry.company.example/team/web:v1"}]}}},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "opaque-secret-web", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"serviceAccountName": "opaque-puller", "containers": [{"name": "web", "image": "registry.opaque.example/team/web:v1"}]}}},
                },
                {"apiVersion": "fixtures.cnsec/v1", "kind": "RegistryEndpoint", "metadata": {"name": "registry-good"}, "url": "https://registry.good.example", "tls_enabled": True, "anonymous_pull": False, "robot_account": "robot$pull", "robot_account_scope": "project:team:pull", "audit_enabled": True},
                {"apiVersion": "fixtures.cnsec/v1", "kind": "RegistryEndpoint", "metadata": {"name": "registry-bad"}, "url": "http://10.20.0.1:5000", "tls_enabled": False, "anonymous_pull": True, "robot_account": None, "robot_account_scope": "admin", "audit_enabled": False},
                {"apiVersion": "fixtures.cnsec/v1", "kind": "RegistryEndpoint", "metadata": {"name": "registry-weak"}, "url": "https://registry.weak.example", "tls_enabled": True, "anonymous_pull": False, "robot_account": "robot$ci", "robot_account_scope": "project:team:push,pull", "audit_enabled": True},
                {"apiVersion": "fixtures.cnsec/v1", "kind": "RegistryAuditEvent", "metadata": {"name": "anon-pull"}, "registry": "10.20.0.1:5000", "repository": "insecure/nginx", "action": "pull", "actor": "anonymous", "result": "success"},
                {"apiVersion": "fixtures.cnsec/v1", "kind": "RegistryAuditEvent", "metadata": {"name": "delete-tag"}, "registry": "10.20.0.1:5000", "repository": "insecure/nginx", "action": "delete_tag", "actor": "admin", "result": "success"},
                {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport", "metadata": {"name": "bad-web-nginx", "namespace": "cnsec-bad"}, "report": {"summary": {"criticalCount": 1, "highCount": 2}}},
                {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "VulnerabilityReport", "metadata": {"name": "coredns", "namespace": "kube-system"}, "report": {"summary": {"criticalCount": 3, "highCount": 1}}},
                {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "SecretReport", "metadata": {"name": "bad-web-secrets", "namespace": "cnsec-bad"}, "report": {"summary": {"secretCount": 1}}},
                {"apiVersion": "aquasecurity.github.io/v1alpha1", "kind": "SecretReport", "metadata": {"name": "falco-secrets", "namespace": "falco"}, "report": {"summary": {"secretCount": 1}}},
            ]
        )
        findings = [finding for finding in run_rules(index, "registry-security") if finding.checkpoint_id == "CN-38"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("FAIL", by_rule["CN-REG-001-security-posture"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-insecure-registry"].status)
        self.assertEqual("WARN", by_rule["CN-REG-001-latest-tag"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-pull-secret"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-registry-endpoint"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-registry-audit"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-trivy-reports"].status)
        self.assertEqual("FAIL", by_rule["CN-REG-001-secret-leak-reports"].status)
        self.assertEqual("PASS", by_rule["CN-REG-001-registry-inventory"].status)
        self.assertTrue(any(row["asset"] == "Deployment/cnsec-bad/bad-web" for row in by_rule["CN-REG-001-pull-secret"].evidence[0].observed))
        self.assertTrue(any(row["asset"] == "Deployment/cnsec-bad/private-web" for row in by_rule["CN-REG-001-pull-secret"].evidence[0].observed))
        self.assertFalse(any(row["asset"] == "Deployment/cnsec-good/sa-private-web" for row in by_rule["CN-REG-001-pull-secret"].evidence[0].observed))
        opaque_secret_risk = [row for row in by_rule["CN-REG-001-pull-secret"].evidence[0].observed if row["asset"] == "Deployment/cnsec-bad/opaque-secret-web"][0]
        self.assertEqual(["registry-opaque"], opaque_secret_risk["pull_secrets"])
        self.assertEqual(["registry-opaque"], opaque_secret_risk["pull_secret_sources"]["service_account"])
        endpoint_risks = by_rule["CN-REG-001-registry-endpoint"].evidence[0].observed["risks"]
        self.assertTrue(any(row["asset"] == "RegistryEndpoint/_cluster/registry-weak" and "robot account scope includes write/admin/delete privileges" in row["risks"] for row in endpoint_risks))
        self.assertTrue(any("anonymous pull event" in row["risks"] for row in by_rule["CN-REG-001-registry-audit"].evidence[0].observed["risks"]))
        inventory = by_rule["CN-REG-001-registry-inventory"].evidence[0].observed
        self.assertTrue(any(row["registry"] == "10.20.0.1:5000" and row["image_count"] >= 1 for row in inventory))
        self.assertTrue(any(row["asset"] == "SecretReport/cnsec-bad/bad-web-secrets" and row["secrets"] == 1 for row in by_rule["CN-REG-001-secret-leak-reports"].evidence[0].observed["risks"]))
        self.assertFalse(any(row["asset"] == "VulnerabilityReport/kube-system/coredns" for row in by_rule["CN-REG-001-trivy-reports"].evidence[0].observed["risks"]))
        self.assertTrue(any(row["asset"] == "VulnerabilityReport/kube-system/coredns" for row in by_rule["CN-REG-001-trivy-reports"].evidence[0].observed["platform_review"]))
        self.assertFalse(any(row["asset"] == "SecretReport/falco/falco-secrets" for row in by_rule["CN-REG-001-secret-leak-reports"].evidence[0].observed["risks"]))
        self.assertTrue(any(row["asset"] == "SecretReport/falco/falco-secrets" for row in by_rule["CN-REG-001-secret-leak-reports"].evidence[0].observed["platform_review"]))
        posture = by_rule["CN-REG-001-security-posture"].evidence[0].observed
        self.assertEqual("FAIL", posture["status"])
        self.assertGreaterEqual(posture["hard_risk_count"], 1)
        self.assertEqual(5, posture["image_inventory"]["registry_count"])
        self.assertEqual(3, posture["endpoint_evidence"]["endpoint_count"])
        self.assertEqual(1, posture["scan_evidence"]["business_vulnerability_risk_count"])
        self.assertEqual(1, posture["scan_evidence"]["platform_vulnerability_review_count"])
        self.assertEqual(1, posture["scan_evidence"]["business_secret_risk_count"])
        self.assertEqual(1, posture["scan_evidence"]["platform_secret_review_count"])

    def test_registry_security_uses_limited_evidence_without_registry_adapter(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "public-web", "namespace": "cnsec-good"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]}}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "pulled-nginx", "namespace": "cnsec-good"},
                    "reason": "Pulled",
                    "message": "Successfully pulled image nginx:1.27",
                    "involvedObject": {"kind": "Pod", "namespace": "cnsec-good", "name": "public-web-abc"},
                },
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "VulnerabilityReport",
                    "metadata": {"name": "public-web-nginx", "namespace": "cnsec-good"},
                    "report": {"summary": {"criticalCount": 0, "highCount": 0}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "registry-limited-evidence") if finding.checkpoint_id == "CN-38"]
        by_rule = {finding.rule_id: finding for finding in findings}
        endpoint = by_rule["CN-REG-001-registry-endpoint"]
        audit = by_rule["CN-REG-001-registry-audit"]
        self.assertEqual("WARN", endpoint.status)
        self.assertEqual("WARN", by_rule["CN-REG-001-security-posture"].status)
        self.assertEqual("inferred", by_rule["CN-REG-001-security-posture"].evidence[0].observed["endpoint_evidence"]["mode"])
        self.assertEqual("WARN", by_rule["CN-REG-001-security-posture"].evidence[0].observed["status"])
        self.assertTrue(by_rule["CN-REG-001-security-posture"].evidence[0].observed["limited_evidence"])
        self.assertEqual("inferred", endpoint.evidence[0].observed["evidence_mode"])
        self.assertEqual("limited_inference", endpoint.evidence[0].observed["evidence_level"])
        self.assertTrue(endpoint.evidence[0].observed["limitations"])
        self.assertTrue(endpoint.evidence[0].observed["inferred_registries"])
        self.assertEqual("WARN", audit.status)
        self.assertEqual("kubernetes_events_limited", audit.evidence[0].observed["evidence_mode"])
        self.assertEqual("limited_kubernetes_event_stream", audit.evidence[0].observed["evidence_level"])
        self.assertTrue(audit.evidence[0].observed["limitations"])
        self.assertTrue(audit.evidence[0].observed["kubernetes_pull_events"])
        self.assertFalse(audit.evidence[0].observed["kubernetes_pull_risks"])
        self.assertEqual("UNKNOWN", by_rule["CN-REG-001-secret-leak-reports"].status)

    def test_registry_security_respects_tls_endpoint_on_port_5000_and_exposed_secret_report(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "secure-port-pull", "namespace": "cnsec-good"},
                    "type": "kubernetes.io/dockerconfigjson",
                    "data": {".dockerconfigjson": "redacted"},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "secure-port-registry", "namespace": "cnsec-good"},
                    "spec": {
                        "template": {
                            "spec": {
                                "imagePullSecrets": [{"name": "secure-port-pull"}],
                                "containers": [{"name": "web", "image": "registry.secure.example:5000/team/web:v1"}],
                            }
                        }
                    },
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "RegistryEndpoint",
                    "metadata": {"name": "secure-port-registry"},
                    "url": "https://registry.secure.example:5000",
                    "tls_enabled": True,
                    "anonymous_pull": False,
                    "robot_account": "robot$pull",
                    "robot_account_scope": "project:team:pull",
                    "audit_enabled": True,
                },
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "ExposedSecretReport",
                    "metadata": {"name": "secure-port-registry-secrets", "namespace": "cnsec-good"},
                    "report": {"summary": {"criticalCount": 0, "highCount": 0, "secretCount": 0}},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "registry-secure-port") if finding.checkpoint_id == "CN-38"]
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("PASS", by_rule["CN-REG-001-security-posture"].status)
        self.assertEqual("PASS", by_rule["CN-REG-001-insecure-registry"].status)
        self.assertEqual("PASS", by_rule["CN-REG-001-registry-endpoint"].status)
        self.assertEqual("PASS", by_rule["CN-REG-001-secret-leak-reports"].status)

    def test_registry_security_flags_kubernetes_image_pull_failures(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "pull-fail", "namespace": "cnsec-bad"},
                    "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "registry.example.test/team/web:latest"}]}}},
                },
                {
                    "apiVersion": "v1",
                    "kind": "Event",
                    "metadata": {"name": "pull-fail-event", "namespace": "cnsec-bad"},
                    "reason": "Failed",
                    "message": 'Failed to pull image "registry.example.test/team/web:latest": pull access denied',
                    "involvedObject": {"kind": "Pod", "namespace": "cnsec-bad", "name": "pull-fail-abc"},
                },
            ]
        )
        findings = [finding for finding in run_rules(index, "registry-pull-failure") if finding.checkpoint_id == "CN-38"]
        by_rule = {finding.rule_id: finding for finding in findings}
        audit = by_rule["CN-REG-001-registry-audit"]
        self.assertEqual("FAIL", audit.status)
        self.assertEqual("kubernetes_events_limited", audit.evidence[0].observed["evidence_mode"])
        self.assertTrue(audit.evidence[0].observed["kubernetes_pull_risks"])
        self.assertIn("image pull failure", audit.evidence[0].observed["kubernetes_pull_risks"][0]["risk_reasons"])
        self.assertIn("failed mutable-tag pull", audit.evidence[0].observed["kubernetes_pull_risks"][0]["risk_reasons"])
        self.assertEqual("registry.example.test/team/web:latest", audit.evidence[0].observed["kubernetes_pull_risks"][0]["image"])
        self.assertEqual("registry.example.test", audit.evidence[0].observed["kubernetes_pull_risks"][0]["registry"])
        self.assertEqual(1, by_rule["CN-REG-001-security-posture"].evidence[0].observed["audit_evidence"]["risk_count"])

    def test_control_plane_manifest_flags_drive_etcd_security_findings(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--etcd-servers=https://127.0.0.1:2379",
                        "--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt",
                        "--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt",
                        "--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key",
                    ],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-etcd", "labels": {"component": "etcd"}},
                    "component": "etcd",
                    "path": "/etc/kubernetes/manifests/etcd.yaml",
                    "command": [
                        "etcd",
                        "--client-cert-auth=true",
                        "--peer-client-cert-auth=true",
                        "--listen-client-urls=https://127.0.0.1:2379",
                        "--listen-peer-urls=https://10.20.0.11:2380",
                        "--cert-file=/etc/kubernetes/pki/etcd/server.crt",
                        "--key-file=/etc/kubernetes/pki/etcd/server.key",
                        "--peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
                        "--peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
                        "--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                        "--peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                    ],
                },
            ]
        )
        findings = run_rules(index, "control-plane-flags")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("PASS", by_rule["CN-PER-001-control-plane-source"].status)
        self.assertEqual("apiserver and etcd static pod manifests collected", by_rule["CN-PER-001-control-plane-source"].evidence[0].observed["reason"])
        self.assertEqual("PASS", by_rule["CN-PER-001-etcd-tls"].status)
        self.assertEqual("PASS", by_rule["CN-PER-001-apiserver-etcd-client-cert"].status)
        self.assertEqual("FAIL", by_rule["CN-PER-001-secret-encryption"].status)
        self.assertEqual(
            "static pod manifest is available and lacks --encryption-provider-config",
            by_rule["CN-PER-001-secret-encryption"].evidence[0].observed["reason"],
        )
        self.assertTrue(by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["checks"]["peer_client_cert_auth"])
        self.assertTrue(by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["checks"]["peer_cert_file"])
        self.assertEqual("true", by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["flags"]["peer-client-cert-auth"])

    def test_control_plane_encryption_provider_config_passes_secret_encryption(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
                    ],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "EncryptionProviderConfig",
                    "metadata": {"name": "cp-encryption-config"},
                    "path": "/etc/kubernetes/encryption-config.yaml",
                    "resources": [
                        {
                            "resources": ["secrets"],
                            "provider_names": ["aescbc", "identity"],
                        }
                    ],
                    "config": {"kind": "EncryptionConfiguration"},
                },
            ]
        )
        findings = run_rules(index, "control-plane-encryption")
        by_rule = {finding.rule_id: finding for finding in findings}
        secret_encryption = by_rule["CN-PER-001-secret-encryption"]
        self.assertEqual("PASS", secret_encryption.status)
        self.assertEqual(
            "/etc/kubernetes/encryption-config.yaml",
            secret_encryption.evidence[0].observed["encryption_provider_config"],
        )
        self.assertEqual(["ControlPlaneManifest"], secret_encryption.evidence[0].observed["apiserver_source_kinds"])
        self.assertEqual("cp-kube-apiserver", secret_encryption.evidence[0].observed["apiserver_sources"][0]["name"])

    def test_control_plane_encryption_provider_config_without_file_content_is_unknown(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
                    ],
                }
            ]
        )
        findings = run_rules(index, "control-plane-encryption-missing-content")
        by_rule = {finding.rule_id: finding for finding in findings}
        secret_encryption = by_rule["CN-PER-001-secret-encryption"]
        self.assertEqual("UNKNOWN", secret_encryption.status)
        self.assertEqual(
            "encryption provider config flag present but file content was not collected",
            secret_encryption.evidence[0].observed["reason"],
        )
        self.assertIsNone(secret_encryption.evidence[0].observed["config_validation"])

    def test_control_plane_encryption_provider_config_validates_content(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
                    ],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "EncryptionProviderConfig",
                    "metadata": {"name": "cp-encryption-config"},
                    "path": "/etc/kubernetes/encryption-config.yaml",
                    "resources": [
                        {
                            "resources": ["secrets"],
                            "provider_names": ["aescbc", "identity"],
                        }
                    ],
                    "config": {"kind": "EncryptionConfiguration"},
                },
            ]
        )
        findings = run_rules(index, "control-plane-encryption-content")
        by_rule = {finding.rule_id: finding for finding in findings}
        secret_encryption = by_rule["CN-PER-001-secret-encryption"]
        self.assertEqual("PASS", secret_encryption.status)
        self.assertTrue(secret_encryption.evidence[0].observed["config_validation"]["covers_secrets"])
        self.assertIn("aescbc", secret_encryption.evidence[0].observed["config_validation"]["provider_names"])

        invalid_index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
                    ],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "EncryptionProviderConfig",
                    "metadata": {"name": "cp-encryption-config"},
                    "path": "/etc/kubernetes/encryption-config.yaml",
                    "resources": [
                        {
                            "resources": ["secrets"],
                            "provider_names": ["identity", "aescbc"],
                        }
                    ],
                    "config": {"kind": "EncryptionConfiguration"},
                },
            ]
        )
        invalid_findings = run_rules(invalid_index, "control-plane-encryption-invalid-content")
        invalid_by_rule = {finding.rule_id: finding for finding in invalid_findings}
        self.assertEqual("FAIL", invalid_by_rule["CN-PER-001-secret-encryption"].status)
        self.assertEqual(
            "encryption provider config collected but identity is the first provider for secrets",
            invalid_by_rule["CN-PER-001-secret-encryption"].evidence[0].observed["reason"],
        )
        self.assertTrue(invalid_by_rule["CN-PER-001-secret-encryption"].evidence[0].observed["config_validation"]["first_provider_identity"])

    def test_partial_control_plane_static_source_warns(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-etcd", "labels": {"component": "etcd"}},
                    "component": "etcd",
                    "path": "/etc/kubernetes/manifests/etcd.yaml",
                    "command": ["etcd", "--client-cert-auth=true"],
                }
            ]
        )
        findings = run_rules(index, "control-plane-partial-source")
        by_rule = {finding.rule_id: finding for finding in findings}
        source = by_rule["CN-PER-001-control-plane-source"]
        self.assertEqual("WARN", source.status)
        self.assertFalse(source.evidence[0].observed["apiserver_static_manifest"])
        self.assertTrue(source.evidence[0].observed["etcd_static_manifest"])
        self.assertEqual("UNKNOWN", by_rule["CN-PER-001-secret-encryption"].status)

    def test_pod_only_control_plane_evidence_warns_instead_of_failing_tls_checks(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "kube-apiserver-node1", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "kube-apiserver",
                                "image": "registry.k8s.io/kube-apiserver:v1.30.0",
                                "command": ["kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"],
                            }
                        ]
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "etcd-node1", "namespace": "kube-system", "labels": {"component": "etcd"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "etcd",
                                "image": "registry.k8s.io/etcd:latest",
                                "command": ["etcd", "--listen-client-urls=https://127.0.0.1:2379"],
                            }
                        ]
                    },
                },
            ]
        )
        findings = run_rules(index, "control-plane-pod-partial-tls")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("WARN", by_rule["CN-PER-001-etcd-tls"].status)
        self.assertEqual("WARN", by_rule["CN-PER-001-apiserver-etcd-client-cert"].status)
        self.assertEqual(
            "partial control-plane evidence lacks complete etcd TLS flags",
            by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["reason"],
        )
        self.assertEqual(
            "partial control-plane evidence lacks complete apiserver->etcd TLS flags",
            by_rule["CN-PER-001-apiserver-etcd-client-cert"].evidence[0].observed["reason"],
        )

    def test_static_control_plane_manifest_requires_etcd_cert_and_peer_key_files(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-etcd", "labels": {"component": "etcd"}},
                    "component": "etcd",
                    "path": "/etc/kubernetes/manifests/etcd.yaml",
                    "command": [
                        "etcd",
                        "--client-cert-auth=true",
                        "--peer-client-cert-auth=true",
                        "--listen-client-urls=https://127.0.0.1:2379",
                        "--listen-peer-urls=https://10.20.0.11:2380",
                        "--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                        "--peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                    ],
                }
            ]
        )
        findings = run_rules(index, "control-plane-static-missing-etcd-cert-files")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("FAIL", by_rule["CN-PER-001-etcd-tls"].status)
        self.assertFalse(by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["checks"]["cert_file"])
        self.assertFalse(by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["checks"]["peer_key_file"])

    def test_control_plane_tls_rejects_mixed_http_and_https_endpoints(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-kube-apiserver", "labels": {"component": "kube-apiserver"}},
                    "component": "kube-apiserver",
                    "path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
                    "command": [
                        "kube-apiserver",
                        "--etcd-servers=https://127.0.0.1:2379,http://10.20.0.11:2379",
                        "--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt",
                        "--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt",
                        "--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key",
                    ],
                },
                {
                    "apiVersion": "fixtures.cnsec/v1",
                    "kind": "ControlPlaneManifest",
                    "metadata": {"name": "cp-etcd", "labels": {"component": "etcd"}},
                    "component": "etcd",
                    "path": "/etc/kubernetes/manifests/etcd.yaml",
                    "command": [
                        "etcd",
                        "--client-cert-auth=true",
                        "--peer-client-cert-auth=true",
                        "--listen-client-urls=https://127.0.0.1:2379,http://10.20.0.11:2379",
                        "--listen-peer-urls=https://10.20.0.11:2380",
                        "--cert-file=/etc/kubernetes/pki/etcd/server.crt",
                        "--key-file=/etc/kubernetes/pki/etcd/server.key",
                        "--peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
                        "--peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
                        "--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                        "--peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
                    ],
                },
            ]
        )
        findings = run_rules(index, "control-plane-mixed-http-https")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("FAIL", by_rule["CN-PER-001-apiserver-etcd-client-cert"].status)
        self.assertEqual("FAIL", by_rule["CN-PER-001-etcd-tls"].status)
        self.assertFalse(by_rule["CN-PER-001-apiserver-etcd-client-cert"].evidence[0].observed["checks"]["etcd_servers_https"])
        self.assertFalse(by_rule["CN-PER-001-etcd-tls"].evidence[0].observed["checks"]["client_urls_https"])

    def test_pod_control_plane_source_warns_for_missing_secret_encryption_flag(self) -> None:
        index = ResourceIndex(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "kube-apiserver-node1", "namespace": "kube-system", "labels": {"component": "kube-apiserver"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "kube-apiserver",
                                "image": "registry.k8s.io/kube-apiserver:v1.30.0",
                                "command": ["kube-apiserver", "--etcd-servers=https://127.0.0.1:2379"],
                            }
                        ]
                    },
                }
            ]
        )
        findings = run_rules(index, "control-plane-pod-source")
        by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual("WARN", by_rule["CN-PER-001-control-plane-source"].status)
        secret_encryption = by_rule["CN-PER-001-secret-encryption"]
        self.assertEqual("WARN", secret_encryption.status)
        self.assertEqual(["Pod"], secret_encryption.evidence[0].observed["apiserver_source_kinds"])
        self.assertEqual("apiserver evidence is partial and lacks --encryption-provider-config", secret_encryption.evidence[0].observed["reason"])

    def test_missing_control_plane_evidence_leaves_secret_encryption_unknown(self) -> None:
        findings = run_rules(ResourceIndex([]), "control-plane-missing")
        by_rule = {finding.rule_id: finding for finding in findings}
        secret_encryption = by_rule["CN-PER-001-secret-encryption"]
        self.assertEqual("UNKNOWN", secret_encryption.status)
        self.assertEqual("no apiserver command evidence collected", secret_encryption.evidence[0].observed["reason"])

    def test_report_scores_all_checkpoints(self) -> None:
        index = load_manifest_path("ops/cnsec-lab/manifests")
        findings = run_rules(index, "test-task")
        report = build_report("test-task", findings, CLOUD_NATIVE_CHECKPOINTS)
        self.assertEqual(len(CLOUD_NATIVE_CHECKPOINTS), len(report.checkpoint_scores))
        self.assertIn("overall_score", report.summary)
        self.assertIn("remediation_priority", report.summary)
        self.assertTrue(report.summary["remediation_priority"])
        self.assertTrue({"priority", "risk_score", "remediation"} <= set(report.summary["remediation_priority"][0]))

    def test_each_checkpoint_has_multiple_rule_findings(self) -> None:
        index = load_manifest_path("ops/cnsec-lab/manifests")
        findings = run_rules(index, "test-task")
        counts = {checkpoint.id: 0 for checkpoint in CLOUD_NATIVE_CHECKPOINTS}
        for finding in findings:
            counts[finding.checkpoint_id] += 1
        too_sparse = {checkpoint_id: count for checkpoint_id, count in counts.items() if count < 2}
        self.assertEqual({}, too_sparse)

    def test_fixtures_cover_every_cloud_native_checkpoint_with_fail(self) -> None:
        request = AssessmentRequest(
            task_id="fixture-fail-coverage",
            profile="all_tools_demo",
            manifest="fixtures",
        )
        result = AssessmentOrchestrator().run(request)
        fail_by_checkpoint = {checkpoint.id: 0 for checkpoint in CLOUD_NATIVE_CHECKPOINTS}
        for finding in result.findings:
            if finding.checkpoint_id in fail_by_checkpoint and finding.status == "FAIL":
                fail_by_checkpoint[finding.checkpoint_id] += 1
        missing = {checkpoint_id: count for checkpoint_id, count in fail_by_checkpoint.items() if count == 0}
        self.assertEqual({}, missing)

    def test_data_quality_distinguishes_schema_errors_from_collection_warnings(self) -> None:
        finding = _finding(
            "quality-test",
            "CN-6",
            "CN-ELAS-001-test",
            "quality fixture",
            "PASS",
            "info",
            AssetRef(kind="Pod", name="demo"),
            Evidence("ok"),
            "none",
        )
        adapter = AdapterResult(
            "cloud_native",
            [],
            {"collected_at": "2026-06-22T00:00:00+00:00"},
            [
                "volumesnapshots.snapshot.storage.k8s.io: the server does not have a resource type",
                "failed to parse bad.yaml: boom",
            ],
        )
        quality = data_quality_summary([adapter], [finding])
        self.assertEqual(1, quality.schema_error_count)
        self.assertEqual(2, quality.collection_warning_count)
        self.assertEqual(0, quality.missing_timestamp_count)

    def test_data_quality_tracks_missing_freshness_and_final_int5_findings(self) -> None:
        finding = _finding(
            "quality-test",
            "CN-6",
            "CN-ELAS-001-test",
            "quality fixture",
            "UNKNOWN",
            "info",
            AssetRef(kind="Pod", name="demo"),
            Evidence("unknown"),
            "none",
        )
        adapter = AdapterResult("cloud_native", [], {}, [])
        quality = data_quality_summary([adapter], [finding])
        self.assertEqual(0.0, quality.freshness)
        self.assertEqual(1, quality.missing_timestamp_count)

        result = AssessmentOrchestrator().run(AssessmentRequest(task_id="quality-final", profile="all_tools_demo", manifest="ops/cnsec-lab/manifests"))
        int5 = [finding for finding in result.findings if finding.checkpoint_id == "INT-5"]
        self.assertEqual(6, len(int5))
        by_rule = {finding.rule_id: finding for finding in int5}
        self.assertEqual("PASS", by_rule["INT-DATA-005-completeness"].status)
        self.assertEqual(100.0, result.report.summary["data_quality"]["completeness"])
        self.assertIn("collected_at", result.adapter_results[0].raw_summary)

    def test_all_tools_orchestrator_covers_assessment_checkpoints(self) -> None:
        request = AssessmentRequest(
            task_id="test-all-tools",
            profile="all_tools_demo",
            manifest="ops/cnsec-lab/manifests",
        )
        result = AssessmentOrchestrator().run(request)
        self.assertEqual(
            ["cloud_native", "cloud_api_stub", "smart_cloud_stub", "registry_stub"],
            [adapter_result.tool_id for adapter_result in result.adapter_results],
        )
        self.assertEqual(len(ASSESSMENT_CHECKPOINTS), len(result.report.checkpoint_scores))
        covered = {finding.checkpoint_id for finding in result.findings}
        self.assertEqual({checkpoint.id for checkpoint in ASSESSMENT_CHECKPOINTS}, covered)
        self.assertIn("data_quality", result.report.summary)
        self.assertTrue({checkpoint.id for checkpoint in VISUALIZATION_CHECKPOINTS} <= covered)
        by_rule = {finding.rule_id: finding for finding in result.findings}
        self.assertEqual("cloud_api_stub", by_rule["INT-API-001-stub-adapter"].tool_id)
        self.assertEqual("smart_cloud_stub", by_rule["INT-SMART-001-stub-adapter"].tool_id)
        self.assertEqual("registry_stub", by_rule["INT-FRAME-001-registry-adapter-stub"].tool_id)
        self.assertEqual("platform", by_rule["VIZ-OVR-001-overview"].tool_id)
        self.assertGreaterEqual(sum(1 for finding in result.findings if finding.tool_id == "cloud_api_stub"), 3)
        self.assertGreaterEqual(sum(1 for finding in result.findings if finding.tool_id == "smart_cloud_stub"), 3)
        self.assertGreaterEqual(sum(1 for finding in result.findings if finding.tool_id == "registry_stub"), 1)
        for checkpoint_id in {"INT-8", "INT-10"}:
            statuses = {finding.status for finding in result.findings if finding.checkpoint_id == checkpoint_id}
            self.assertNotIn("FAIL", statuses)
            self.assertNotIn("UNKNOWN", statuses)
            self.assertIn("WARN", statuses)
        raw_by_tool = {adapter_result.tool_id: adapter_result.raw_summary for adapter_result in result.adapter_results}
        self.assertIn("target_parameters", raw_by_tool["cloud_api_stub"])
        self.assertIn("capabilities", raw_by_tool["smart_cloud_stub"])
        self.assertIn("capabilities", raw_by_tool["registry_stub"])
        self.assertTrue(raw_by_tool["cloud_api_stub"]["stub_mode"])
        self.assertTrue(raw_by_tool["smart_cloud_stub"]["stub_mode"])
        self.assertTrue(raw_by_tool["registry_stub"]["stub_mode"])
        self.assertEqual("Finding[]", raw_by_tool["cloud_api_stub"]["integration_contract"]["output"])
        self.assertEqual("Finding[]", raw_by_tool["smart_cloud_stub"]["integration_contract"]["output"])
        self.assertIn("Finding[]", raw_by_tool["registry_stub"]["integration_contract"]["output"])
        summary_by_tool = {item["tool_id"]: item for item in result.report.summary["tool_summary"]}
        self.assertTrue(summary_by_tool["cloud_api_stub"]["stub_mode"])
        self.assertTrue(summary_by_tool["smart_cloud_stub"]["stub_mode"])
        self.assertTrue(summary_by_tool["registry_stub"]["stub_mode"])
        self.assertEqual("stub", summary_by_tool["cloud_api_stub"]["status"])
        self.assertEqual("stub", summary_by_tool["smart_cloud_stub"]["status"])
        self.assertEqual("stub", summary_by_tool["registry_stub"]["status"])
        self.assertEqual(result.report.summary["tool_summary"], result.report.summary["tools"])
        cn6_by_rule = {}
        for finding in result.findings:
            if finding.checkpoint_id == "CN-6":
                cn6_by_rule.setdefault(finding.rule_id, []).append(finding)
        self.assertIn("CN-ELAS-001-metrics-api", cn6_by_rule)
        self.assertIn("CN-ELAS-001-hpa-runtime", cn6_by_rule)
        self.assertIn("CN-ELAS-001-workload-resilience-score", cn6_by_rule)
        metrics_finding = cn6_by_rule["CN-ELAS-001-metrics-api"][0]
        self.assertEqual("PASS", metrics_finding.status)
        self.assertTrue(metrics_finding.evidence[0].observed["api_service_available"])
        runtime_by_asset = {finding.asset.key: finding for finding in cn6_by_rule["CN-ELAS-001-hpa-runtime"] if finding.asset}
        self.assertEqual("PASS", runtime_by_asset["Deployment/cnsec-good/web-good"].status)
        self.assertTrue(runtime_by_asset["Deployment/cnsec-good/web-good"].evidence[0].observed["has_current_metrics"])
        self.assertEqual("WARN", runtime_by_asset["Deployment/cnsec-bad/web-bad"].status)
        self.assertFalse(runtime_by_asset["Deployment/cnsec-bad/web-bad"].evidence[0].observed["scalingActive"]["status"] == "True")
        summary_by_asset = {finding.asset.key: finding for finding in cn6_by_rule["CN-ELAS-001-workload-resilience-score"] if finding.asset}
        self.assertEqual(100.0, summary_by_asset["Deployment/cnsec-good/web-good"].evidence[0].observed["resilience_score"])
        self.assertIn("resources_present", summary_by_asset["Deployment/cnsec-bad/web-bad"].evidence[0].observed["missing_controls"])

    def test_sqlite_store_persists_assessment_result(self) -> None:
        request = AssessmentRequest(
            task_id="test-store",
            profile="all_tools_demo",
            manifest="ops/cnsec-lab/manifests",
        )
        second_request = AssessmentRequest(
            task_id="test-store-second",
            profile="all_tools_demo",
            manifest="ops/cnsec-lab/manifests",
        )
        result = AssessmentOrchestrator().run(request)
        second_result = AssessmentOrchestrator().run(second_request)
        with TemporaryDirectory() as temp_dir:
            store = AssessmentStore(f"{temp_dir}/assessment.sqlite3")
            store.save_result(result)
            store.save_result(second_result)
            self.assertEqual(len(ASSESSMENT_CHECKPOINTS), len(store.list_checkpoints()))
            self.assertIsNotNone(store.get_report("test-store"))
            self.assertIsNotNone(store.get_report("test-store-second"))
            self.assertEqual(len(result.findings), len(store.list_findings("test-store")))
            self.assertEqual(len(second_result.findings), len(store.list_findings("test-store-second")))

    def test_checkpoint_metadata_defaults_survive_store_reopen(self) -> None:
        with TemporaryDirectory() as temp_dir:
            db_path = f"{temp_dir}/assessment.sqlite3"
            store = AssessmentStore(db_path)
            checkpoint = store.get_checkpoint("CN-29")
            self.assertTrue(checkpoint["enabled"])
            self.assertEqual("all", checkpoint["applicability"]["scope"])
            self.assertEqual({checkpoint["rule_group"]: True}, checkpoint["rule_enabled"])

            patched = store.patch_checkpoint(
                "CN-29",
                {
                    "enabled": False,
                    "applicability": {"scope": "demo-only"},
                    "rule_enabled": {"CN-IAM-002": False},
                },
            )
            self.assertFalse(patched["enabled"])

            reopened = AssessmentStore(db_path)
            checkpoint = reopened.get_checkpoint("CN-29")
            self.assertFalse(checkpoint["enabled"])
            self.assertEqual("demo-only", checkpoint["applicability"]["scope"])
            self.assertFalse(checkpoint["rule_enabled"]["CN-IAM-002"])

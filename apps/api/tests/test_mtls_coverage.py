import unittest

from cloudnative_security.mtls_coverage import analyze_mtls_coverage, effective_mtls_mode


class MtlsCoverageTests(unittest.TestCase):
    def test_workload_policy_overrides_namespace_and_port_inherits(self):
        policies = [
            {"metadata": {"name": "mesh", "namespace": "istio-system"}, "spec": {"mtls": {"mode": "STRICT"}}},
            {"metadata": {"name": "namespace", "namespace": "prod"}, "spec": {"mtls": {"mode": "PERMISSIVE"}}},
            {"metadata": {"name": "workload", "namespace": "prod"}, "spec": {"selector": {"matchLabels": {"app": "payments"}}, "mtls": {"mode": "STRICT", "portLevelMtls": {"8080": {"mode": "PERMISSIVE"}}}}},
        ]
        workload = {"metadata": {"name": "payments", "namespace": "prod", "labels": {"app": "payments"}}}
        result = analyze_mtls_coverage(policies, [workload])
        self.assertEqual("STRICT", result.status)
        self.assertEqual("PERMISSIVE", effective_mtls_mode(policies, "prod", {"app": "payments"}, 8080))

    def test_unmatched_workload_is_unknown(self):
        result = analyze_mtls_coverage([], [{"metadata": {"name": "a", "namespace": "prod"}}])
        self.assertEqual("UNKNOWN", result.status)
        self.assertEqual("UNKNOWN", result.workloads[0].mode)


if __name__ == "__main__":
    unittest.main()

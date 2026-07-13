from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


class DeliveryAssetsTest(unittest.TestCase):
    def test_pve_lab_delivery_assets_exist(self) -> None:
        root = Path("deploy/pve-lab")
        readme = root / "README.md"
        env_example = root / "lab.env.example"
        wrapper = root / "run-stage.sh"
        self.assertTrue(readme.is_file())
        self.assertTrue(env_example.is_file())
        self.assertTrue(wrapper.is_file())

        readme_text = readme.read_text()
        for expected in ["template", "vms", "node", "init", "addons", "workloads", "assess", "Snapshot Policy"]:
            self.assertIn(expected, readme_text)

        env_text = env_example.read_text()
        for expected in ["CP1_ID=111", "W1_ID=102", "W2_ID=103", "PVE_LAB_GW=10.20.0.1"]:
            self.assertIn(expected, env_text)

        result = subprocess.run(["bash", "-n", str(wrapper)], check=False, capture_output=True, text=True)
        self.assertEqual("", result.stderr)
        self.assertEqual(0, result.returncode)

    def test_demo_fixtures_and_one_command_entries_exist(self) -> None:
        expected_files = [
            Path("fixtures/k8s-good/cnsec-good.yaml"),
            Path("fixtures/k8s-bad/cnsec-bad.yaml"),
            Path("fixtures/logs/falco_events.jsonl"),
            Path("fixtures/logs/authlog_ssh_bruteforce.log"),
            Path("docker-compose.yml"),
            Path("deploy/kind-demo/run-kind-demo.sh"),
        ]
        for path in expected_files:
            self.assertTrue(path.is_file(), str(path))
        result = subprocess.run(["bash", "-n", "deploy/kind-demo/run-kind-demo.sh"], check=False, capture_output=True, text=True)
        self.assertEqual("", result.stderr)
        self.assertEqual(0, result.returncode)

    def test_dashboard_drilldown_controls_exist(self) -> None:
        index = Path("apps/web/static/index.html").read_text()
        app = Path("apps/web/static/app.js").read_text()
        styles = Path("apps/web/static/styles.css").read_text()
        self.assertIn("findingDetail", index)
        for expected in ["copyRemediationBtn", "relatedFindings", "related-finding", "asset-card"]:
            self.assertIn(expected, app)
        for expected in [".related-findings", ".related-finding", ".asset-card", ".detail-head"]:
            self.assertIn(expected, styles)


if __name__ == "__main__":
    unittest.main()

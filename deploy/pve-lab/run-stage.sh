#!/usr/bin/env bash
set -euo pipefail

STAGE="${1:-}"
PVE_SSH="${PVE_SSH:-cloudnative-env}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/root/cnsec-lab}"
PYTHON_BIN="${PYTHON_BIN:-$REPO_ROOT/.venv/bin/python}"

usage() {
  cat <<'EOF'
Usage: deploy/pve-lab/run-stage.sh <stage>

Stages:
  sync       Copy lab scripts, manifests, and lab.env.example to the PVE host.
  template   Create or reuse the Ubuntu cloud-init template.
  vms        Clone/start the three Kubernetes VMs.
  node       Install node prerequisites on every VM.
  init       Run kubeadm init/join and fetch kubeconfig.
  addons     Install metrics-server, Kyverno, Trivy Operator, and Falco.
  workloads  Apply cnsec-good and cnsec-bad manifests.
  assess     Run the local Python assessment against the PVE lab.

Environment:
  PVE_SSH=cloudnative-env
  REMOTE_ROOT=/root/cnsec-lab
EOF
}

require_stage() {
  if [ -z "$STAGE" ] || [ "$STAGE" = "-h" ] || [ "$STAGE" = "--help" ]; then
    usage
    exit 0
  fi
}

sync_lab() {
  ssh "$PVE_SSH" "mkdir -p '$REMOTE_ROOT/scripts' '$REMOTE_ROOT/manifests'"
  scp "$REPO_ROOT"/ops/cnsec-lab/scripts/*.sh "$PVE_SSH:$REMOTE_ROOT/scripts/"
  scp "$REPO_ROOT"/ops/cnsec-lab/manifests/*.yaml "$PVE_SSH:$REMOTE_ROOT/manifests/"
  scp "$REPO_ROOT"/deploy/pve-lab/lab.env.example "$PVE_SSH:$REMOTE_ROOT/lab.env.example"
  ssh "$PVE_SSH" "test -f '$REMOTE_ROOT/lab.env' || cp '$REMOTE_ROOT/lab.env.example' '$REMOTE_ROOT/lab.env'"
}

run_pve_script() {
  local script="$1"
  ssh "$PVE_SSH" "bash '$REMOTE_ROOT/scripts/$script'"
}

run_node_script() {
  ssh "$PVE_SSH" "source '$REMOTE_ROOT/lab.env'; for ip in \"\$CP1_IP\" \"\$W1_IP\" \"\$W2_IP\"; do scp -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new '$REMOTE_ROOT/scripts/10-k8s-node-common.sh' agent@\"\$ip\":/tmp/10-k8s-node-common.sh; ssh -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new agent@\"\$ip\" 'bash /tmp/10-k8s-node-common.sh'; done"
}

run_addons() {
  ssh "$PVE_SSH" "source '$REMOTE_ROOT/lab.env'; ssh -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new agent@\"\$CP1_IP\" 'mkdir -p /tmp/cnsec-lab/manifests'; scp -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new '$REMOTE_ROOT/scripts/12-k8s-install-addons.sh' agent@\"\$CP1_IP\":/tmp/12-k8s-install-addons.sh; scp -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new '$REMOTE_ROOT/manifests/metrics-server.yaml' agent@\"\$CP1_IP\":/tmp/cnsec-lab/manifests/metrics-server.yaml; ssh -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new agent@\"\$CP1_IP\" 'LAB_MANIFEST_DIR=/tmp/cnsec-lab/manifests bash /tmp/12-k8s-install-addons.sh'"
}

run_workloads() {
  ssh "$PVE_SSH" "source '$REMOTE_ROOT/lab.env'; ssh -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new agent@\"\$CP1_IP\" 'kubectl delete namespace cnsec-bad --ignore-not-found --wait=true --timeout=180s || true; kubectl -n cnsec-good delete pod orders-db --ignore-not-found --wait=true --timeout=180s || true'; for file in cnsec-good.yaml; do scp -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new '$REMOTE_ROOT/manifests/'\"\$file\" agent@\"\$CP1_IP\":/tmp/\"\$file\"; ssh -i \"\${SSH_KEY_PATH:-/root/.ssh/agent_lab}\" -o StrictHostKeyChecking=accept-new agent@\"\$CP1_IP\" \"kubectl apply -f /tmp/\"\$file\"\"; done"
}

run_assess() {
  if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN=python3
  fi
  PYTHONPATH=apps/api "$PYTHON_BIN" -m cloudnative_security.cli \
    --pve-ssh "$PVE_SSH" \
    --profile all_tools_demo \
    --task-id pve-all-tools \
    --extra-manifest artifacts/pve-lab/logs/falco_events.jsonl \
    --extra-manifest artifacts/pve-lab/logs/registry_evidence.yaml \
    --output artifacts/reports/all-tools-pve.json \
    --markdown-output artifacts/reports/all-tools-pve.md \
    --html-output artifacts/reports/all-tools-pve.html \
    --sqlite artifacts/assessment.sqlite3
}

require_stage
case "$STAGE" in
  sync) sync_lab ;;
  template) sync_lab; run_pve_script 02-create-ubuntu-template.sh ;;
  vms) sync_lab; run_pve_script 03-create-k8s-vms.sh ;;
  node) sync_lab; run_node_script ;;
  init) sync_lab; run_pve_script 11-k8s-init-control-plane.sh ;;
  addons) sync_lab; run_addons ;;
  workloads) sync_lab; run_workloads ;;
  assess) run_assess ;;
  *) usage; exit 2 ;;
esac

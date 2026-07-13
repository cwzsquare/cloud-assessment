#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-cnsec-demo}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v kind >/dev/null 2>&1; then
  echo "ERROR: kind is required. Install kind first: https://kind.sigs.k8s.io/" >&2
  exit 20
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl is required." >&2
  exit 21
fi

if ! kind get clusters | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME"
fi

kubectl --context "kind-$CLUSTER_NAME" apply -f "$REPO_ROOT/fixtures/k8s-good"
kubectl --context "kind-$CLUSTER_NAME" apply -f "$REPO_ROOT/fixtures/k8s-bad"
kubectl --context "kind-$CLUSTER_NAME" get nodes -o wide
kubectl --context "kind-$CLUSTER_NAME" get pods -A

PYTHONPATH="$REPO_ROOT/apps/api" python3 -m cloudnative_security.cli \
  --kubeconfig "${KUBECONFIG:-$HOME/.kube/config}" \
  --profile all_tools_demo \
  --task-id kind-all-tools \
  --output "$REPO_ROOT/artifacts/reports/all-tools-kind.json" \
  --markdown-output "$REPO_ROOT/artifacts/reports/all-tools-kind.md" \
  --html-output "$REPO_ROOT/artifacts/reports/all-tools-kind.html" \
  --sqlite "$REPO_ROOT/artifacts/assessment.sqlite3"

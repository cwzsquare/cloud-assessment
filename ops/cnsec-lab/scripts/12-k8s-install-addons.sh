#!/usr/bin/env bash
set -euo pipefail

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

MANIFEST_DIR="${LAB_MANIFEST_DIR:-/root/cnsec-lab/manifests}"

if [ -f "${MANIFEST_DIR}/metrics-server.yaml" ]; then
  kubectl apply -f "${MANIFEST_DIR}/metrics-server.yaml"
else
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
  kubectl -n kube-system patch deployment metrics-server --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' || true
fi
kubectl -n kube-system rollout status deployment/metrics-server --timeout=180s || true

helm repo add kyverno https://kyverno.github.io/kyverno/ || true
helm repo add aqua https://aquasecurity.github.io/helm-charts/ || true
helm repo add falcosecurity https://falcosecurity.github.io/charts || true
helm repo update

helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait
helm upgrade --install kyverno-policies kyverno/kyverno-policies -n kyverno --wait \
  --set validationFailureAction=Audit || true

helm upgrade --install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace --wait \
  --set trivy.ignoreUnfixed=true || true

helm upgrade --install falco falcosecurity/falco -n falco --create-namespace --wait \
  --set tty=true || true

kubectl get pods -A -o wide

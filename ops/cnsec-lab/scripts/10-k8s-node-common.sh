#!/usr/bin/env bash
set -euo pipefail

K8S_MINOR="${K8S_MINOR:-v1.36}"

sudo swapoff -a
sudo sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab

cat <<'EOF' | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter

cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gpg apt-transport-https jq chrony containerd qemu-guest-agent
sudo systemctl enable --now qemu-guest-agent

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo sed -i 's/^disabled_plugins = \["cri"\]/disabled_plugins = []/' /etc/containerd/config.toml || true
if [ -n "${K8S_IMAGE_REPOSITORY:-}" ]; then
  sudo sed -i "s#sandbox = '.*'#sandbox = '${K8S_IMAGE_REPOSITORY}/pause:3.10.2'#" /etc/containerd/config.toml || true
fi
sudo systemctl enable --now containerd
sudo systemctl restart containerd

sudo mkdir -p /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /
EOF
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kubelet kubeadm kubectl
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y cri-tools || true
sudo apt-mark hold kubelet kubeadm kubectl
sudo systemctl enable kubelet

sudo crictl info >/tmp/crictl-info.json || true
kubeadm version
kubelet --version

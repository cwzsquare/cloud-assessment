#!/usr/bin/env bash
set -euo pipefail

source /root/cnsec-lab/lab.env

SSH_KEY_PATH="${SSH_KEY_PATH:-/root/.ssh/agent_lab}"
SSH_OPTS=(-i "$SSH_KEY_PATH" -o StrictHostKeyChecking=accept-new)
KUBEADM_IMAGE_REPOSITORY_ARG=""
if [ -n "${K8S_IMAGE_REPOSITORY:-}" ]; then
  KUBEADM_IMAGE_REPOSITORY_ARG="--image-repository=${K8S_IMAGE_REPOSITORY}"
fi

for node in \
  "$CP1_IP $CP1_NAME" \
  "$W1_IP $W1_NAME" \
  "$W2_IP $W2_NAME"; do
  ip="${node%% *}"
  name="${node##* }"
  ssh "${SSH_OPTS[@]}" agent@"$ip" "sudo hostnamectl set-hostname $name"
done

for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  ssh "${SSH_OPTS[@]}" agent@"$ip" "cat <<EOF | sudo tee -a /etc/hosts
${CP1_IP} ${CP1_NAME}
${W1_IP} ${W1_NAME}
${W2_IP} ${W2_NAME}
EOF"
done

ssh "${SSH_OPTS[@]}" agent@"$CP1_IP" "sudo kubeadm init \
  --apiserver-advertise-address=${CP1_IP} \
  --control-plane-endpoint=${CP1_IP} \
  --pod-network-cidr=${POD_CIDR} \
  --service-cidr=${SERVICE_CIDR} \
  --kubernetes-version=${K8S_VERSION} \
  ${KUBEADM_IMAGE_REPOSITORY_ARG} \
  --upload-certs"

ssh "${SSH_OPTS[@]}" agent@"$CP1_IP" 'mkdir -p $HOME/.kube && sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config && sudo chown $(id -u):$(id -g) $HOME/.kube/config'
scp -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=accept-new agent@"$CP1_IP":/home/agent/.kube/config /root/cnsec-lab/kubeconfig

JOIN_CMD=$(ssh "${SSH_OPTS[@]}" agent@"$CP1_IP" 'sudo kubeadm token create --print-join-command')
printf 'sudo %s\n' "$JOIN_CMD" >/root/cnsec-lab/join-command.sh
chmod +x /root/cnsec-lab/join-command.sh

for ip in "$W1_IP" "$W2_IP"; do
  ssh "${SSH_OPTS[@]}" agent@"$ip" "sudo ${JOIN_CMD}"
done

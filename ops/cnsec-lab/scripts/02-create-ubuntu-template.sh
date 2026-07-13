#!/usr/bin/env bash
set -euo pipefail

source /root/cnsec-lab/lab.env

VM_CPU_TYPE="${VM_CPU_TYPE:-host}"
VM_NIC_MODEL="${VM_NIC_MODEL:-e1000}"
ROOT_DISK_SLOT="${ROOT_DISK_SLOT:-ide0}"
CLOUDINIT_SLOT="${CLOUDINIT_SLOT:-ide2}"
IMAGE_NAME="${IMAGE_NAME:-noble-server-cloudimg-amd64.img}"
IMAGE_PATH="/var/lib/vz/template/iso/${IMAGE_NAME}"

attach_root_disk() {
  case "$ROOT_DISK_SLOT" in
    ide0|sata0|scsi0|virtio0)
      qm set "$UBUNTU_TEMPLATE_ID" --"${ROOT_DISK_SLOT}" "${PVE_STORAGE}:vm-${UBUNTU_TEMPLATE_ID}-disk-0"
      ;;
    *)
      echo "ERROR: unsupported ROOT_DISK_SLOT=$ROOT_DISK_SLOT" >&2
      exit 1
      ;;
  esac
}

if [ ! -s "${SSH_PUBKEY_PATH}" ]; then
  echo "ERROR: missing SSH public key: ${SSH_PUBKEY_PATH}" >&2
  exit 20
fi

if [ ! -s "${IMAGE_PATH}" ]; then
  wget -O "${IMAGE_PATH}" "${UBUNTU_CLOUD_IMAGE}"
fi

if qm status "${UBUNTU_TEMPLATE_ID}" >/dev/null 2>&1; then
  echo "Template VM ${UBUNTU_TEMPLATE_ID} already exists, skip."
  exit 0
fi

qm create "${UBUNTU_TEMPLATE_ID}" \
  --name ubuntu-2404-k8s-template \
  --memory 2048 \
  --cores 2 \
  --cpu "${VM_CPU_TYPE}" \
  --net0 "${VM_NIC_MODEL}",bridge="${PVE_LAB_BRIDGE}" \
  --ostype l26 \
  --serial0 socket \
  --vga serial0

qm importdisk "${UBUNTU_TEMPLATE_ID}" "${IMAGE_PATH}" "${PVE_STORAGE}"
attach_root_disk
qm set "${UBUNTU_TEMPLATE_ID}" --"${CLOUDINIT_SLOT}" "${PVE_STORAGE}:cloudinit"
qm set "${UBUNTU_TEMPLATE_ID}" --boot order="${ROOT_DISK_SLOT}"
qm set "${UBUNTU_TEMPLATE_ID}" --ciuser agent --sshkeys "${SSH_PUBKEY_PATH}"
qm set "${UBUNTU_TEMPLATE_ID}" --ipconfig0 ip=dhcp
qm resize "${UBUNTU_TEMPLATE_ID}" "${ROOT_DISK_SLOT}" +18G
qm template "${UBUNTU_TEMPLATE_ID}"

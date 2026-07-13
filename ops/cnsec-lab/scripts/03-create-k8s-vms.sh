#!/usr/bin/env bash
set -euo pipefail

source /root/cnsec-lab/lab.env

VM_CPU_TYPE="${VM_CPU_TYPE:-host}"
VM_NIC_MODEL="${VM_NIC_MODEL:-e1000}"
ROOT_DISK_SLOT="${ROOT_DISK_SLOT:-ide0}"
TARGET_VMS="${TARGET_VMS:-all}"

create_vm() {
  local id="$1" name="$2" ip="$3" cores="$4" mem="$5" disk_add="$6"

  if qm status "$id" >/dev/null 2>&1; then
    echo "VM $id $name exists, skip clone."
  else
    qm clone "$UBUNTU_TEMPLATE_ID" "$id" --name "$name" --full 1 --storage "$PVE_STORAGE"
    qm set "$id" \
      --cpu "$VM_CPU_TYPE" \
      --cores "$cores" \
      --memory "$mem" \
      --net0 "${VM_NIC_MODEL}",bridge="${PVE_LAB_BRIDGE}" \
      --ipconfig0 ip="${ip}/24",gw="${PVE_LAB_GW}" \
      --nameserver "1.1.1.1" \
      --searchdomain "cnsec.lab" \
      --ciuser agent \
      --sshkeys "$SSH_PUBKEY_PATH" \
      --agent enabled=1
    qm resize "$id" "$ROOT_DISK_SLOT" "+${disk_add}G" || true
  fi

  if qm status "$id" | grep -q "status: running"; then
    echo "VM $id $name already running."
  else
    qm start "$id"
  fi
  qm status "$id" | grep -q "status: running"
}

if [ "$TARGET_VMS" = "all" ] || [ "$TARGET_VMS" = "cp1" ]; then
  create_vm "$CP1_ID" "$CP1_NAME" "$CP1_IP" 4 8192 60
fi
if [ "$TARGET_VMS" = "all" ] || [ "$TARGET_VMS" = "w1" ]; then
  create_vm "$W1_ID"  "$W1_NAME"  "$W1_IP"  4 8192 60
fi
if [ "$TARGET_VMS" = "all" ] || [ "$TARGET_VMS" = "w2" ]; then
  create_vm "$W2_ID"  "$W2_NAME"  "$W2_IP"  4 8192 60
fi

cat >/root/cnsec-lab/inventory.json <<EOF
{
  "pve_node": "${PVE_NODE}",
  "network": {"bridge": "${PVE_LAB_BRIDGE}", "cidr": "${PVE_LAB_CIDR}", "gateway": "${PVE_LAB_GW}"},
  "vms": [
    {"id": ${CP1_ID}, "name": "${CP1_NAME}", "ip": "${CP1_IP}", "role": "control-plane"},
    {"id": ${W1_ID}, "name": "${W1_NAME}", "ip": "${W1_IP}", "role": "worker"},
    {"id": ${W2_ID}, "name": "${W2_NAME}", "ip": "${W2_IP}", "role": "worker"}
  ]
}
EOF

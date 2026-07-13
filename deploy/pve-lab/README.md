# PVE Kubernetes Lab Delivery Guide

This directory is the delivery entry point for recreating the PVE nested
Kubernetes assessment lab required by the prototype DoD. It intentionally reuses
the maintained scripts under `ops/cnsec-lab/` so the executable lab logic has a
single source of truth.

## Topology

Default lab values match the current demo environment:

| VMID | Name | IP | Role |
|---:|---|---|---|
| 111 | `k8s-cp-1` | `10.20.0.11` | control plane |
| 102 | `k8s-worker-1` | `10.20.0.12` | worker |
| 103 | `k8s-worker-2` | `10.20.0.13` | worker |
| 9000 | `ubuntu-2404-k8s-template` | DHCP | template |

The PVE host is reached through the local SSH alias `cloudnative-env`. The lab
network is `10.20.0.0/24`, with PVE acting as gateway at `10.20.0.1`.

## Files

- `lab.env.example`: variables copied to `/root/cnsec-lab/lab.env` on PVE.
- `run-stage.sh`: local wrapper for syncing scripts and running each stage.
- `ops/cnsec-lab/scripts/*.sh`: the PVE and node bootstrap scripts.
- `ops/cnsec-lab/manifests/*.yaml`: `cnsec-good`, `cnsec-bad`, and metrics-server manifests.

## Usage

Review and sync the lab variables:

```bash
deploy/pve-lab/run-stage.sh sync
ssh cloudnative-env 'cp /root/cnsec-lab/lab.env.example /root/cnsec-lab/lab.env'
ssh cloudnative-env 'vi /root/cnsec-lab/lab.env'
```

Run the stages in order:

```bash
deploy/pve-lab/run-stage.sh template
deploy/pve-lab/run-stage.sh vms
deploy/pve-lab/run-stage.sh node
deploy/pve-lab/run-stage.sh init
deploy/pve-lab/run-stage.sh addons
deploy/pve-lab/run-stage.sh workloads
deploy/pve-lab/run-stage.sh assess
```

The final `assess` stage writes:

- `artifacts/reports/all-tools-pve.json`
- `artifacts/reports/all-tools-pve.md`
- `artifacts/reports/all-tools-pve.html`
- `artifacts/assessment.sqlite3`

## Validation

PVE inventory and snapshot hygiene:

```bash
ssh cloudnative-env 'qm list; for id in 111 102 103; do echo VMID:$id; qm listsnapshot $id; done'
```

Kubernetes health:

```bash
ssh cloudnative-env 'source /root/cnsec-lab/lab.env; ssh -i ${SSH_KEY_PATH:-/root/.ssh/agent_lab} agent@$CP1_IP "kubectl get nodes -o wide && kubectl get pods -A"'
```

Assessment smoke:

```bash
python3 - <<'PY'
import json
r=json.load(open("artifacts/reports/all-tools-pve.json"))["report"]
print(r["summary"]["overall_score"], r["summary"]["checkpoint_total"], r["summary"]["finding_total"])
assert r["summary"]["checkpoint_total"] == 38
PY
```

## Snapshot Policy

Before destructive lab changes, create a PVE snapshot for the three active K8s
VMs. After the new state is verified, keep only the latest complete K8s snapshot
and remove intermediate snapshots:

```bash
SNAP="demo-ready-$(date +%Y%m%d%H%M)"
ssh cloudnative-env "for id in 111 102 103; do qm snapshot \$id $SNAP --description 'Verified demo-ready K8s state'; done"
```

List and delete obsolete snapshots explicitly:

```bash
ssh cloudnative-env 'for id in 111 102 103; do qm listsnapshot $id; done'
ssh cloudnative-env 'qm delsnapshot 111 OLD_SNAPSHOT_NAME'
```

Do not delete the latest verified snapshot until a replacement has been created
and the assessment report has been regenerated successfully.

## Cleanup

Destroy only known lab VMs. Keep template `9000` unless a full rebuild is
required.

```bash
ssh cloudnative-env 'for id in 111 102 103; do qm stop $id || true; qm destroy $id --purge || true; done'
```

Old experimental VMs such as `195`-`199` should not exist in the final demo
inventory. Check with `qm list` before and after cleanup.

## Limitations

- The scripts target an isolated demo PVE host, not production PVE.
- Secret data is not collected by the assessment prototype.
- Cloud API and smart cloud checks are adapter stubs; they validate integration,
  scoring, UI, and reporting flow, but not real provider APIs.
- Registry and audit-log depth depends on optional credentials and log sources.

# Agent Progress

Updated: 2026-06-30T03:33Z

## Current state

- PVE host: `cloudnative-env`
- Current retained VM snapshot set:
  - `111/102/103 -> ready-recovered-202606300333`
  - `9000 -> current`
- PVE WG egress:
  - interface: `cnsec-lab`
  - endpoint: `192.168.168.24:51820`
  - NAT rule count: `1` for `10.20.0.0/24 -> cnsec-lab`
  - verified egress IP from both PVE and VM `10.20.0.11`: `104.28.211.190`
- Cluster health:
  - nodes `k8s-cp-1`, `k8s-worker-1`, `k8s-worker-2` all `Ready`
  - core DaemonSets `falco`, `calico-node`, `kube-proxy` all `Ready`
  - post-reboot `trivy-system` scan jobs are reinitializing; operator is `Running`

## Latest repair

- Recovered the PVE lab after the LVM thin pool `pve/data` hit `100%` and all three K8s VMs entered `qmpstatus: io-error`.
- Expanded `/dev/pve/data` with the remaining VG free space, bringing the thin pool back from `100%` to a writable state.
- Power-cycled VMs `111`, `102`, and `103` after storage recovery; all returned to `qmpstatus: running`, ICMP reachability, and SSH access as user `agent`.
- Re-validated the Kubernetes control plane on `10.20.0.11` with `KUBECONFIG=/etc/kubernetes/admin.conf`:
  - nodes `k8s-cp-1`, `k8s-worker-1`, `k8s-worker-2` all `Ready`
  - static control-plane pods `kube-apiserver`, `etcd`, `kube-controller-manager`, `kube-scheduler` all `Running`
  - `kubelet` and `containerd` both `active`
- Refreshed the retained full-cluster snapshot set to the recovered state:
  - created `111/102/103 -> ready-recovered-202606300333`
  - deleted old retained set `ready-cn23-30-202606230653`
- Thin-pool usage dropped to about `71.66%` after replacing the stale snapshot set.
- Re-validated WG egress after recovery:
  - PVE `curl --interface cnsec-lab -4 https://api.ipify.org` => `104.28.211.190`
  - VM `10.20.0.11` `curl -4 https://api.ipify.org` => `104.28.211.190`
- Fixed post-recovery PVE collection regression:
  - root cause was nested SSH host key drift after VM restart/snapshot restore
  - `collect_pve_kubectl`, `collect_pve_control_plane_manifests`, and `collect_pve_auth_logs` now use relaxed known_hosts handling for demo-lab nested SSH hops
  - regenerated live baseline report as `pve-good-live-20260630b`

## This round

- Implemented the remaining tender-intent rule gaps for:
  - `CN-23`: completed/failed Pod cleanup, stale ReplicaSet cleanup
  - `CN-25`: Pod/Node admission governance proof, DaemonSet node auto-governance proof
  - `CN-28`: OIDC/external auth evidence, apiserver TLS evidence
  - `CN-30`: identity incident ledger, pod exec audit detection, abnormal login detection
- Updated auth log parsing to recognize successful SSH login lines in addition to failed-password events.
- Added focused unit tests in `apps/api/tests/test_rules.py` for the new `CN-23/CN-25/CN-28/CN-30` behaviors.
- Re-ran targeted regression:
  - new gap-closing tests: `4/4 OK`
  - broader `CN-23/CN-25/CN-28/CN-30` regression slice: `10/10 OK`
  - `python -m compileall -q apps/api/cloudnative_security apps/api/tests`: OK
- Updated `ops/cnsec-lab/manifests/cnsec-good.yaml`:
  - set `Deployment/cnsec-good/web-good.spec.revisionHistoryLimit: 1`
- Took pre-change PVE VM snapshot set:
  - `111/102/103 -> pre-cn23-rs-cleanup-20260623064715`
- Applied the updated `cnsec-good.yaml` to the live cluster and cleaned `web-good` historical zero-replica ReplicaSets.
- Re-ran live assessment after cleanup:
  - `CN-23`: all `PASS/NOT_APPLICABLE`
  - `CN-25`: all `PASS/NOT_APPLICABLE`
  - `CN-28`: all `PASS/NOT_APPLICABLE`
  - `CN-30`: all `PASS`
  - `CN-35`..`CN-39`: all `PASS`
- Replaced retained full-cluster snapshot set after verification:
  - created `111/102/103 -> ready-cn23-30-202606230653`
  - deleted old retained set `pre-cn24-cn25-cn26-cn28-202606230558`
  - deleted temporary pre-change set `pre-cn23-rs-cleanup-20260623064715`
  - thin-pool `pve/data` usage after cleanup: about `73.65%`
- Re-ran `gpt-5.4` subagent scoring:
  - immutable/elastic domain `CN-22`..`CN-27`: `PASS overall`
  - identity/access domain `CN-28`..`CN-30`: `PASS overall`
  - persistence domain `CN-35`..`CN-39`: `PASS overall`

- Enabled Kubernetes secret encryption at rest on control-plane VM `111`:
  - created `/etc/kubernetes/encryption-config.yaml`
  - inserted `--encryption-provider-config=/etc/kubernetes/encryption-config.yaml` into `/etc/kubernetes/manifests/kube-apiserver.yaml`
  - waited for `kube-apiserver` restart and cluster recovery
- Re-ran PVE assessment report
- Created new cluster snapshot set `demo-ready-cn35-202606230415`
- Deleted previous snapshot set `demo-ready-cn37-202606221959`
- Switched/confirmed PVE WireGuard upstream endpoint to `192.168.168.24:51820`
- Verified PVE host egress via `curl --interface cnsec-lab https://api.ipify.org`
- Verified VM `10.20.0.11` default route still points to `10.20.0.1` and exits through the same WG egress IP
- Re-checked CN-35 implementation with targeted unit tests:
  - `test_control_plane_manifest_flags_drive_etcd_security_findings`
  - `test_control_plane_encryption_provider_config_passes_secret_encryption`
  - `test_control_plane_encryption_provider_config_without_file_content_is_unknown`
  - `test_control_plane_encryption_provider_config_validates_content`
  - `test_control_plane_tls_rejects_mixed_http_and_https_endpoints`
  - result: `5/5 OK`
- Re-ran `gpt-5.4` subagent review for `CN-35`:
  - final score: `9/10`
  - verdict: passes tender intent
  - remaining gap is test-strengthening level only (for example `listen-peer-urls` mixed-protocol explicit test), not a blocker
- Improved `CN-38` registry security implementation:
  - `CN-REG-001-security-posture` no longer auto-`PASS` on any evidence; it now returns `FAIL/WARN/PASS/UNKNOWN` based on hard risks, limited evidence, and warning-level drift signals
  - fixed image registry parsing so single-segment images like `nginx:1.27` resolve to `docker.io` instead of being misclassified as private registries
  - separated endpoint URL normalization from image-ref parsing with `_registry_endpoint_key`, restoring correct matching between `RegistryEndpoint` evidence and image inventory
  - strengthened positive/negative tests so risky sample -> `FAIL`, limited evidence -> `WARN`, explicit clean secure registry -> `PASS`
- Re-checked targeted regression after CN-38 changes:
  - `CN-29/CN-35/CN-38` focused unit suite: `9/9 OK`
  - `python3 -m compileall -q apps/api/cloudnative_security apps/api/tests`: OK
- Re-ran `gpt-5.4` subagent review for `CN-38`:
  - updated score: `8.5/10`
  - verdict: passes tender intent
  - remaining gaps are evidence-strength depth issues (limited inferred TLS, pull-secret proof depth, broader registry anomaly modeling), not immediate rule-correctness blockers
- Hardened live cluster and implementation for `CN-29`:
  - created and applied `ops/cnsec-lab/manifests/cnsec-access-context-policy.yaml`
  - added `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` for `namespace/label/env/subject` context control
  - removed live `cnsec-bad/dangerous-app-rolebinding` and `dangerous-app-role`
  - added collector support for `validatingadmissionpolicies.admissionregistration.k8s.io` and `validatingadmissionpolicybindings.admissionregistration.k8s.io`
  - added RBAC matrix query API filters in `server.py` / `storage.py`
  - added RBAC matrix UI query controls in `apps/web/static/index.html` and `app.js`
  - tightened `CN-29` context policy logic so `ValidatingAdmissionPolicy` must have a binding to count as effective evidence
- Re-ran targeted regression after CN-29 changes:
  - CN-29 rule/API subset: OK
  - `node --check apps/web/static/app.js`: OK
  - `python3 -m compileall -q apps/api/cloudnative_security apps/api/tests`: OK
- Re-ran live PVE report after CN-29 changes:
  - `CN-29`: `91.67 PASS`
  - only remaining live warning under `CN-29` is `CN-IAM-002-system-rbac-review`
- Re-ran `gpt-5.4` subagent review for `CN-29`:
  - updated score: `9/10`
  - verdict: passes tender intent
  - remaining gap is governance-level whitelist/basis review for system controller high privileges, not business-side blocker
- Replaced cluster snapshot set after CN-29 hardening:
  - created `demo-ready-cn29-202606230456`
  - deleted `demo-ready-cn35-202606230415`
  - deleted temporary pre-change set `pre-cn29-20260623044731`
  - thin-pool `pve/data` data usage after cleanup: about `58.72%`
- Improved `CN-37` implementation coverage:
  - added database-like `Deployment` / `Job` / `CronJob` controller coverage to `CN-37`
  - controller-owned Pods (`ReplicaSet` / `Job` / `CronJob` / `StatefulSet`) are now deduplicated from standalone database Pod scoring
  - added targeted unit test covering database `Deployment` and deduplication
  - synchronized `apps/api/cloudnative_security/checkpoints.py` evidence sources with the new controller coverage surface
- Re-ran `gpt-5.4` subagent review for `CN-37` after controller-coverage fix:
  - updated score: `6.5/10`
  - verdict: still fails tender intent
  - remaining blocker is live evidence path: current PVE lab still only demonstrates an intentionally insecure stateful workload (`postgres-bad`) and does not yet include a compliant/pass-path stateful workload

## Latest key scores

From `artifacts/reports/all-tools-pve.json`:

- `CN-23`: `100.0 PASS`
- `CN-25`: `100.0 PASS`
- `CN-28`: `100.0 PASS`
- `CN-29`: `100.0 PASS`
- `CN-30`: `100.0 PASS`
- `CN-35`: `100.0 PASS`
- `CN-36`: `100.0 PASS`
- `CN-37`: `100.0 PASS`
- `CN-38`: `100.0 PASS`
- `CN-39`: `100.0 PASS`
- `CN-6`: `57.84 FAIL`

## Known blockers

- `gpt-5.3-codex` subagent scoring is still externally blocked:
  - provider returns `502 Bad Gateway: unknown provider for model gpt-5.3-codex`
- This does not block code or environment work, but it blocks the user-requested per-item scoring step on that exact model.
- Current scoring workflow should use `gpt-5.4` instead.

## Latest validation

- Re-validated PVE WireGuard runtime after user requested endpoint switch check:
  - running peer endpoint is still `192.168.168.24:51820`
  - latest handshake present during check
  - config file `/etc/wireguard/cnsec-lab.conf` matches runtime endpoint
  - NAT rule still single-entry: `-A POSTROUTING -s 10.20.0.0/24 -o cnsec-lab -j MASQUERADE`
  - PVE `curl --interface cnsec-lab https://api.ipify.org` => `104.28.211.190`
  - VM `10.20.0.11` default route remains `via 10.20.0.1`, public egress IP => `104.28.211.190`
- Re-validated again at `2026-06-23T05:47Z` after explicit retry request:
  - runtime `wg show cnsec-lab` still reports peer endpoint `192.168.168.24:51820`
  - latest handshake during check was about `1 minute`
  - PVE direct egress with `curl --interface cnsec-lab -4 https://api.ipify.org` still returns `104.28.211.190`
  - route to the WireGuard peer itself is still underlay traffic on `vmbr0` via `192.168.1.1`
  - conclusion: tunnel egress is working, but peer reachability still depends on the `192.168.1.x` underlay unless the peer endpoint is changed to a publicly reachable address or another non-`192.168.1.x` path
- Re-validated once more at `2026-06-23T06:27Z` after endpoint retry request:
  - runtime and `/etc/wireguard/cnsec-lab.conf` both still use `Endpoint = 192.168.168.24:51820`
  - latest handshake during check was about `2 minutes`
  - NAT rule remains `-A POSTROUTING -s 10.20.0.0/24 -o cnsec-lab -j MASQUERADE`
  - PVE `curl --interface cnsec-lab -4 https://api.ipify.org` => `104.28.211.190`
  - VM `10.20.0.11` default route remains `via 10.20.0.1`, and `curl -4 https://api.ipify.org` from the VM also => `104.28.211.190`
  - underlay route to the WG peer is still `192.168.168.24 via 192.168.1.1 dev vmbr0`, so the tunnel works but its peer transport still depends on the `192.168.1.x` uplink path

## PVE resource notes

- Host memory available during this round: about `4.8 GiB`
- Root filesystem free: about `50 GiB`
- LVM thin pool `pve/data` data usage after current snapshot set: about `58.72%`
- Thin-pool warning seen during snapshot creation: continue keeping only one retained full-cluster snapshot set

## Recommended next targets

1. If continuing beyond the current stop condition, return to non-target residuals such as `CN-6` and optional hardening like image digest pinning.
2. Keep only the single retained cluster snapshot set `ready-cn23-30-202606230653` unless another live change requires a fresh pre-change snapshot cycle.

# 云原生安全评估项目交接说明（Agent 版）

更新时间：2026-07-13  
工作区：`/root/cloud-assessment`  
项目状态：原型主链路可运行；当前工作区不是历史 Git 工作树，本次整理会建立初始仓库提交。

## 1. 仓库

- Web：<https://gitlab.suitmyself.top/cwzsquare/cloud-assessment>
- SSH：`git@gitlab.suitmyself.top:cwzsquare/cloud-assessment.git`
- 默认分支：`main`
- 认证：本机 `/root/.ssh/id_ed25519`；不要把私钥、kubeconfig 或任何 token 放入仓库。

仓库只保存代码、部署脚本、样例清单、可复核报告和说明文档。以下内容明确排除：

- `artifacts/assessment.sqlite3`：包含原始采集快照和评估数据；
- `artifacts/pve-lab/kubeconfig`：包含集群证书和 client key；
- `.venv/`、缓存、`__pycache__`、靶场运行日志和生成型临时文件。

## 2. 项目做什么

系统实现一条完整的云原生安全评估链路：

```text
Manifest / Kubernetes API / PVE 控制面 / 日志
        -> 采集与脱敏归一化
        -> CloudNativeAdapter + 规则集合
        -> Finding / Evidence / Checkpoint 评分
        -> SQLite 持久化
        -> JSON / Markdown / HTML 报告
        -> API 查询与静态 Web 仪表盘
```

本期重点做实的是云原生安全评估；云上 API、智算云和 Registry 适配器保留统一接口及 stub/mock 结果，用来验证集成、评分、报告和页面链路，不代表真实云厂商检测已经完成。

## 3. 代码地图

| 路径 | Agent 应先看什么 |
|---|---|
| `apps/api/cloudnative_security/collector.py` | Manifest、kubectl、PVE 嵌套 SSH、控制面 static pod、加密配置、auth.log/Falco 采集与脱敏。 |
| `apps/api/cloudnative_security/adapters.py` | `CloudNativeAdapter`、云 API/智算云/Registry stub 和适配器注册表。 |
| `apps/api/cloudnative_security/rules.py` | 主要规则实现；重点覆盖 CN-6、CN-22~30、CN-35~39，以及镜像、RBAC、弹性、持久化和运行时事件判定。 |
| `apps/api/cloudnative_security/rbac_matrix.py` | 主体—角色—资源—动作矩阵、危险权限、系统权限区分、临时授权过期标记。 |
| `apps/api/cloudnative_security/orchestrator.py` | 多适配器编排、Finding 归一化、数据质量、集成和可视化衍生 Finding。 |
| `apps/api/cloudnative_security/scoring.py` | 状态到分数、检查点/域/总分、UNKNOWN 与严重度门禁。 |
| `apps/api/cloudnative_security/report_renderer.py` | Markdown/HTML 报告，以及摘要、重点风险、整改优先级。 |
| `apps/api/cloudnative_security/storage.py` | SQLite 表、评估任务、原始快照、Finding、报告和进度事件。 |
| `apps/api/cloudnative_security/server.py` | HTTP API；目标、评估、Finding、RBAC matrix、报告和检查点权重接口。 |
| `apps/web/static/` | 无构建步骤的静态仪表盘；`app.js` 负责查询、筛选和 drill-down。 |
| `ops/cnsec-lab/manifests/` | `cnsec-good`/`cnsec-bad`、准入策略和 metrics-server 样例。 |
| `ops/cnsec-lab/scripts/` | PVE 模板、VM、Kubernetes 初始化、插件、工作负载和评估脚本。 |
| `deploy/pve-lab/` | 靶场交付入口、变量样例和分阶段 wrapper。 |
| `fixtures/` | 离线正反样例及 Falco/auth.log 事件。 |
| `artifacts/reports/` | 已生成的 JSON、Markdown、HTML 报告和验收截图。 |

## 4. 已实现能力

### 不可变部署与弹性安全

覆盖工作负载不可变性、镜像 digest/版本追踪、容器 SSH/exec 暴露、历史 ReplicaSet/完成或失败 Pod 清理、HPA/PDB、资源 requests/limits、扩缩容审计、ResourceQuota/LimitRange、准入治理和生命周期清理。当前主要规则范围为 CN-6、CN-22~CN-27。

### 动态访问控制与身份安全

覆盖匿名主体、ServiceAccount token 自动挂载、OIDC/external auth、API Server TLS、RBAC 权限矩阵、危险 `*`/Secret/exec/bind/escalate/impersonate 授权、系统组件权限复核、临时授权过期、上下文准入策略、SSH 暴破、异常登录、Pod exec 审计和身份事件台账。当前主要规则范围为 CN-28~CN-30。

### 持久化与数据安全

覆盖 etcd/API Server TLS、Secret 静态加密、PV/PVC/StorageClass 回收与加密、VolumeSnapshot/Velero 等备份证据、有状态应用网络/TLS/凭据/卷保护、Registry endpoint/pull secret/审计/漏洞信号、Falco/Kubernetes audit/PVC 异常事件。当前主要规则范围为 CN-35~CN-39。

### 集成、评分和交付

统一 `Target`、`AssessmentTask`、`AssetRef`、`Evidence`、`Finding`、`Checkpoint`、`Report` 数据模型；支持 Manifest 离线扫描、集群 API 扫描和 PVE 靶场扫描；报告输出 JSON/Markdown/HTML；API 提供任务进度、Finding、原始快照、RBAC 查询和检查点权重调整；Web 页面提供总览、筛选和详情下钻。

## 5. 当前报告基线

### 聚合演示报告

`artifacts/reports/all-tools-pve.json`（生成于 2026-06-23）是多工具聚合演示基线：

- 总分 `98.74`，结论“符合”；
- 38 个检查点，381 条 Finding，证据覆盖率 `100%`；
- 云原生域：不可变/弹性 `97.43`，身份 `100`，持久化 `100`；
- `cloud_native` 为真实 ready 适配器；云 API、智算云、Registry 为 stub；`platform` 为内部衍生结果；
- 主要残留：`orders-db` 缺 HPA/PDB、两个业务镜像未固定 digest，以及 stub 适配器的 mock 风险提示。

### 较新的正向靶场 live 报告

`artifacts/reports/pve-good-live-20260630b.json`（生成于 2026-06-30）应视为更接近当前靶场的基线，但它不是“全绿”报告：

- 总分 `97.32`，结论为存在多个 high 风险失败项；
- 381 条 Finding，`FAIL=6`、`WARN=10`、`UNKNOWN=4`；
- 高风险残留包括异常登录（CN-30）、业务 `hostPath` PV（CN-36）、有状态应用备份/快照证据（CN-37）；
- 中风险残留包括 `orders-db` 的 HPA/PDB、业务镜像 digest；
- 该文件与早期 `all-tools-pve` 的结果不能混用，agent 修改规则或样例后应重新生成报告再判断。

可直接查看：

- `artifacts/reports/pve-good-live-20260630b.md`
- `artifacts/reports/all-tools-pve.md`
- `artifacts/reports/all-tools-pve.html`
- `artifacts/reports/all-tools-pve-acceptance.png`

## 6. 当前验证状态

2026-07-13 在本工作区执行：

```bash
PYTHONPATH=apps/api python3 -m unittest discover -s apps/api/tests -v
```

结果：79 个测试中 76 个通过、3 个失败。失败项是当前代码基线的已知问题：

1. `test_checkpoint_rule_switch_and_applicability_filter_report_findings`：测试期待 CN-37 为 PASS，实际为 FAIL；
2. `test_all_tools_orchestrator_covers_assessment_checkpoints`：测试期待 `Deployment/cnsec-good/web-good` 的运行时结果为 PASS，实际为 UNKNOWN；
3. `test_bad_lab_manifests_produce_actionable_findings`：当前 bad fixture 未产生预期的 CN-29 FAIL。

另外通过：

```bash
PYTHONPATH=apps/api python3 -m compileall -q apps/api/cloudnative_security apps/api/tests
node --check apps/web/static/app.js
```

Agent 接手后应先复现这 3 个失败，再决定是修规则、补 fixture 证据还是更新测试预期；不要直接把报告分数当成单元测试通过证明。

## 7. 靶场服务器与当前 live 拓扑

### 连接入口

- 本机 SSH alias：`cloudnative-env`
- 跳板机：`192.168.204.12:11451`，用户 `root`
- PVE 地址：`192.168.1.173`，用户 `root`
- 本机密钥：`/root/.ssh/id_ed25519`
- 连接命令：`ssh cloudnative-env`

这些值来自本机 `/root/.ssh/config`。不要把 SSH 私钥、PVE 上的 `/root/cnsec-lab/lab.env` 或集群 kubeconfig 提交到仓库。

### 当前靶场事实

以 `artifacts/pve-lab/inventory.json` 和 `artifacts/pve-lab/healthcheck.txt` 为当前可复核证据：

| VMID | 节点 | 当前 IP | 角色 |
|---:|---|---|---|
| 111 | `k8s-cp-1` | `10.20.0.11` | Kubernetes control plane |
| 102 | `k8s-worker-1` | `10.20.0.21` | worker |
| 103 | `k8s-worker-2` | `10.20.0.22` | worker |

- PVE 节点名：`pve-nested-01`；
- 实验网桥：`vmbr1`；网段：`10.20.0.0/24`；网关：`10.20.0.1`；
- Kubernetes：`v1.36.2`；节点系统为 Ubuntu 24.04.4 LTS；
- 当前健康检查中 control plane、两个 worker、etcd、API Server、controller-manager、scheduler、kubelet/containerd 均有运行证据；部分 Trivy 运行态扫描可能受镜像拉取影响。

### 地址冲突提醒

`deploy/pve-lab/README.md` 和 `deploy/pve-lab/lab.env.example` 仍保留旧 worker 默认值 `10.20.0.12/10.20.0.13`，而当前 live inventory/healthcheck 使用 `10.20.0.21/10.20.0.22`。agent 在重建靶场前必须以 PVE 上实际的 `lab.env`、`qm config` 和 `kubectl get nodes -o wide` 为准；不要直接复制旧示例覆盖 live 配置。

### 运行时注意事项

其他工作区会话曾验证：PVE 作为 nested hypervisor 时，L2 guest 的 KVM 加速路径可能早期冻结；同一类测试 VM 在 `kvm=0` 的 TCG 模式下可以进入 userspace 并联网。该结论属于靶场运行约束，不是评估规则实现结论。若 agent 进行靶场重建，应先做最小 VM 启动/网络验证，再运行 kubeadm 和全量评估。

## 8. Agent 接手顺序

1. 先读 `AGENTS.md`、本文件、`README.md`、`apps/api/README.md` 和 `doc/云原生安全评估原型系统工程文档-vibe-coding-v0.2.md`。
2. 先跑离线 fixture 流程和 3 个已知失败测试，确认当前基线。
3. 规则修改优先从 `rules.py` 的对应 helper、`checkpoints.py` 元数据和 `apps/api/tests/test_rules.py` 定向测试入手。
4. 靶场修改前先确认 `cloudnative-env`、当前 IP、Kubernetes 节点状态和是否存在可用快照；不要把旧 worker 地址当成事实。
5. 评估完成后同时检查 JSON、Markdown、HTML 三种报告，并记录输入来源、采集 warning、FAIL/WARN/UNKNOWN 和报告生成时间。
6. 任何包含证书、私钥、kubeconfig、token、原始 SQLite 采集库的文件都不得提交。

## 9. 常用命令

离线扫描：

```bash
PYTHONPATH=apps/api python3 -m cloudnative_security.cli \
  --manifest ops/cnsec-lab/manifests \
  --profile all_tools_demo \
  --task-id local-all-tools \
  --output artifacts/reports/all-tools-local.json \
  --markdown-output artifacts/reports/all-tools-local.md \
  --html-output artifacts/reports/all-tools-local.html \
  --sqlite artifacts/assessment.sqlite3
```

PVE 扫描：

```bash
PYTHONPATH=apps/api python3 -m cloudnative_security.cli \
  --pve-ssh cloudnative-env \
  --profile all_tools_demo \
  --task-id pve-all-tools \
  --output artifacts/reports/all-tools-pve.json \
  --markdown-output artifacts/reports/all-tools-pve.md \
  --html-output artifacts/reports/all-tools-pve.html \
  --sqlite artifacts/assessment.sqlite3
```

启动 API/Web：

```bash
docker compose up
# http://127.0.0.1:18080/
```


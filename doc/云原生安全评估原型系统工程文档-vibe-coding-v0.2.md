# 云原生安全评估原型系统工程文档（Vibe Coding 版）

> 版本：v0.2  
> 输入依据：附件《云原生功能点清单-信工所0608.xlsx》  
> 当前研发重点：**云原生安全评估工具**。云上 API 安全评估工具、智算云安全评估工具在本原型中只做可插拔适配与示例 stub，保证平台集成链路闭环，不做完整检测能力。  
> v0.2 新增：**PVE 嵌套虚拟化 + 多 VM/LXC Kubernetes 靶场环境 + agent SSH 运维指导**。

---

## 1. 原型目标与边界

### 1.1 建设目标

建设一个可演示、可扩展、能覆盖标书检查点的云原生安全评估原型系统，支持对 Kubernetes / 云原生环境进行采集、检查、打分、报告和可视化展示。原型要能完成以下闭环：

1. 注册评估目标：Kubernetes 集群、离线 Manifest 包、镜像仓库配置、可选日志源。
2. 采集资产与配置：集群资源、RBAC、Pod/Workload、HPA/PDB、NetworkPolicy、StorageClass/PV/PVC、Secret/ConfigMap、Service/Ingress、Istio/Gateway 等可选 CRD。
3. 运行检查规则：以标书检查点为一级追踪单元，每个检查点下挂一组可执行规则。
4. 统一输出：所有工具输出转成统一 Finding / Metric / Report 数据模型。
5. 指标赋权与综合判定：按检查点权重形成安全符合度、风险分布、整改优先级。
6. 可视化展示：平台总览、云原生工具详情页、筛选查询、结果 drill-down、报告导出。
7. 集成扩展：云上 API 和智算云工具保留 adapter stub，后续替换为真实插件即可接入。

### 1.2 原型边界

| 范围 | 本期做法 |
|---|---|
| 云原生安全评估工具 | 完整实现“不可变基础设施与弹性安全评估”“动态访问控制与身份安全评估”“容器持久化安全评估”三组检查点。 |
| 云上 API 安全评估工具 | 实现标准 adapter、参数校验、mock findings、详情页占位和统一输出，不实现真实 API 检测。 |
| 智算云安全评估工具 | 实现标准 adapter、参数校验、mock findings、详情页占位和统一输出，不实现真实智算云检测。 |
| 控制面 / etcd 深度配置 | 默认通过 Kubernetes API 可见资源、静态 Pod Manifest 和可选诊断采集器完成；托管集群不可见项标记 UNKNOWN 并给出补充取证建议。 |
| 主动攻击 / 压测 | 原型默认只在 demo namespace 运行可控模拟任务；生产集群默认不做破坏性操作。 |
| 自动整改 | 本期只生成整改建议和示例 YAML，不默认对目标集群执行变更。 |

### 1.3 关键设计原则

- **检查点可追踪**：每个标书检查点都有唯一 `checkpoint_id`，从规则、发现、评分、页面、报告全链路可追溯。
- **证据优先**：每条 FAIL/WARN 必须包含资产定位、原始字段片段、判断原因、整改建议。
- **只读优先**：默认使用只读 Kubernetes RBAC；需要 host/control-plane 权限的深度检查单独作为“增强采集器”。
- **插件化适配**：三类工具遵循统一接口，当前重点只把 CloudNativeAdapter 做实。
- **规则数据分离**：规则元数据用 YAML/JSON 管理，复杂逻辑用 Python handler，便于后续按标书变更快速扩展。
- **适合 vibe coding**：所有任务拆成可独立生成、独立测试的小模块，并提供清晰的数据结构、API 合约、验收标准。

---

## 2. 技术基线与参考标准

本原型的检查规则不只照抄通用基线，而是将标书检查点映射到 Kubernetes 原生能力、云原生安全最佳实践和可执行检测点。建议将以下资料作为规则库的默认参考：

| 资料 | 用途 |
|---|---|
| Kubernetes Pod Security Standards | 作为 Pod 加固、不可变、最小权限检查的基础。重点参考 `restricted` profile。 |
| CIS Kubernetes Benchmark | 作为 kube-apiserver、etcd、kubelet、控制面安全配置的参考基线。 |
| Kubernetes RBAC / RBAC Good Practices | 作为身份认证、最小权限、危险权限识别、权限提升路径分析的依据。 |
| Kubernetes NetworkPolicy | 作为微服务隔离、数据库访问隔离、默认拒绝策略的依据。 |
| Kubernetes HPA / PDB / ResourceQuota / LimitRange | 作为弹性、防止恶意扩容、资源治理和高可用检查的依据。 |
| Kubernetes Encryption at Rest / Secrets | 作为 etcd 加密、Secret 存储风险、KMS 集成建议的依据。 |
| Kubernetes ValidatingAdmissionPolicy、Kyverno、OPA Gatekeeper | 作为安全策略自动化应用、动态访问控制和准入治理的依据。 |
| Istio mTLS / PeerAuthentication | 作为服务网格 mTLS 检测依据。 |
| Falco / Trivy Operator / kube-bench | 作为运行时异常、漏洞/配置扫描、CIS 检查集成的可选实现依据。 |
| OWASP Kubernetes Top 10、NIST SP 800-190 | 作为风险分类、报告说明和整改优先级参考。 |

---

## 3. 推荐技术栈

为降低原型复杂度，建议采用“单体后端 + 插件化扫描 + 前端仪表盘”的结构，先不引入复杂微服务。

| 层 | 建议技术 | 原因 |
|---|---|---|
| 前端 | React + TypeScript + Vite/Next.js + ECharts | 快速搭建筛选、态势、详情、图表。 |
| 后端 API | Python FastAPI + Pydantic | Kubernetes client、规则引擎、报告生成都比较顺手。 |
| 数据库 | SQLite（本地 demo）/ PostgreSQL（投标演示部署） | SQLite 便于一键运行，PostgreSQL 支持 JSONB 和多任务。 |
| 后台任务 | FastAPI BackgroundTasks / APScheduler；后续可替换 Celery/RQ | 原型足够，减少 Redis 依赖。 |
| Kubernetes 采集 | kubernetes Python client + dynamic client | 能发现 CRD，适合 Istio/Kyverno/Gatekeeper/Trivy CRD。 |
| 规则引擎 | YAML rule registry + Python handler | 可读、可扩展、便于检查点追踪。 |
| 报告 | HTML/Markdown 导出；需要时再转 PDF | 原型阶段便于调试。 |
| 部署 | Docker Compose + 可选 Helm chart | 本地演示和集群部署都可覆盖。 |

---

## 4. 总体架构

```text
┌────────────────────────────┐
│ Web UI                     │
│ - 总览仪表盘                │
│ - 云原生工具详情            │
│ - 指标管理/赋权             │
│ - 结果筛选/交互查询         │
└──────────────┬─────────────┘
               │ REST / WebSocket
┌──────────────▼─────────────┐
│ FastAPI Backend            │
│ - Target API               │
│ - Assessment Task API      │
│ - Finding/Metric API       │
│ - Report API               │
│ - Indicator Weight API     │
└──────────────┬─────────────┘
               │
┌──────────────▼─────────────┐
│ Assessment Orchestrator    │
│ - 任务编排                  │
│ - 优先级/资源锁             │
│ - Adapter 调用              │
│ - 状态流转                  │
└──────┬────────┬────────────┘
       │        │
       │        ├──────────────────────────────┐
       │                                       │
┌──────▼────────────────┐        ┌────────────▼─────────────┐
│ CloudNativeAdapter    │        │ API / SmartCloud Stub     │
│ - K8s 资产采集         │        │ - mock findings           │
│ - 规则执行             │        │ - schema-compatible       │
│ - 证据生成             │        │ - 可替换插件              │
└──────┬────────────────┘        └────────────┬─────────────┘
       │                                      │
┌──────▼──────────────────────────────────────▼─────────────┐
│ Normalization Pipeline                                    │
│ raw snapshots -> assets -> findings -> metrics -> reports │
└──────┬────────────────────────────────────────────────────┘
       │
┌──────▼────────────────┐
│ SQLite/PostgreSQL     │
│ - targets             │
│ - tasks               │
│ - raw_snapshots       │
│ - assets              │
│ - checkpoints         │
│ - findings            │
│ - weights             │
│ - reports             │
└───────────────────────┘
```

### 4.1 扫描模式

| 模式 | 用途 | 输入 | 能覆盖的检查 |
|---|---|---|---|
| Manifest 模式 | 无集群权限时演示静态检查 | YAML/tar/helm render 输出 | Pod 安全、RBAC、NetworkPolicy、StorageClass、HPA/PDB、准入策略存在性。 |
| Cluster API 模式 | 推荐默认模式 | kubeconfig 或 in-cluster ServiceAccount | 绝大多数资源配置、RBAC、事件、CRD、Trivy/Kyverno/Gatekeeper 报告。 |
| Control-plane 增强模式 | 自建集群深度评估 | 可选 DaemonSet/Job 读取 control-plane static pod args | kube-apiserver flags、etcd TLS、encryption-provider-config。 |
| Runtime/Event 模式 | 异常监控和 SSH/持久化事件 | Falco webhook、K8s audit log、auth.log 上传 | 运行时写入、exec、SSH 暴破、异常卷访问。 |
| Registry 模式 | 镜像仓库检查 | Harbor/Registry API、pull secret、镜像引用 | 仓库 TLS、匿名访问、审计、镜像漏洞/泄露。 |

---

## 5. 统一数据模型

### 5.1 核心对象

```python
class Target(BaseModel):
    id: str
    name: str
    type: Literal["kubernetes", "manifest_bundle", "registry", "mock"]
    connection_mode: Literal["kubeconfig", "in_cluster", "upload", "stub"]
    labels: dict[str, str] = {}
    created_at: datetime

class AssessmentTask(BaseModel):
    id: str
    target_id: str
    profile: Literal["cloud_native_full", "all_tools_demo"]
    status: Literal["pending", "running", "success", "failed", "cancelled"]
    progress: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None

class AssetRef(BaseModel):
    kind: str
    namespace: str | None = None
    name: str
    uid: str | None = None
    api_version: str | None = None
    labels: dict[str, str] = {}

class Evidence(BaseModel):
    summary: str
    object_ref: AssetRef | None = None
    json_path: str | None = None
    observed: Any | None = None
    expected: Any | None = None
    raw_snippet: dict | list | str | None = None

class Finding(BaseModel):
    id: str
    task_id: str
    tool_id: Literal["cloud_native", "cloud_api_stub", "smart_cloud_stub"]
    checkpoint_id: str
    rule_id: str
    title: str
    status: Literal["PASS", "FAIL", "WARN", "UNKNOWN", "NOT_APPLICABLE"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    score: float
    asset: AssetRef | None
    evidence: list[Evidence]
    remediation: str
    references: list[str] = []
    fingerprint: str
```

### 5.2 标准输出 JSON

```json
{
  "schema_version": "1.0",
  "task_id": "task-20260617-001",
  "target": {
    "id": "target-prod-k8s",
    "name": "prod-k8s",
    "type": "kubernetes"
  },
  "summary": {
    "overall_score": 78.5,
    "conclusion": "基本符合，存在高风险项需整改",
    "by_domain": [
      {"domain": "不可变基础设施与弹性安全评估", "score": 74.0, "failed": 6},
      {"domain": "动态访问控制与身份安全评估", "score": 81.0, "failed": 4},
      {"domain": "容器持久化安全评估", "score": 80.0, "failed": 5}
    ],
    "severity_count": {"critical": 1, "high": 7, "medium": 12, "low": 5}
  },
  "findings": []
}
```

### 5.3 评分规则

| 状态 | 默认得分 | 说明 |
|---|---:|---|
| PASS | 1.0 | 完全符合。 |
| WARN | 0.5 | 有弱项或证据不足但存在部分控制。 |
| FAIL | 0.0 | 明确不符合。 |
| UNKNOWN | 不计入默认分母，单独展示 | 受托管集群权限、日志不可见等限制；报告中必须说明需补充证据。 |
| NOT_APPLICABLE | 不计入分母 | 场景不适用，例如未安装 Istio 时不评价 Istio mTLS，但需提示可选增强。 |

综合分：

```text
checkpoint_score = Σ(rule_score * rule_weight) / Σ(applicable_rule_weight)
domain_score     = Σ(checkpoint_score * checkpoint_weight) / Σ(checkpoint_weight)
overall_score    = Σ(domain_score * domain_weight) / Σ(domain_weight)
```

严重度修正：

```text
若存在 critical FAIL：overall_score 上限 70
若存在 high FAIL >= 5：overall_score 上限 80
若 UNKNOWN 占比 > 30%：结论必须包含“证据不足”
```

---

## 6. 数据库表设计

```sql
CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  connection_mode TEXT NOT NULL,
  connection_ref TEXT,
  labels_json TEXT NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE assessment_tasks (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id),
  profile TEXT NOT NULL,
  status TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  started_at TIMESTAMP,
  ended_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE raw_snapshots (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES assessment_tasks(id),
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  namespace TEXT,
  name TEXT,
  content_json TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  collected_at TIMESTAMP NOT NULL
);

CREATE TABLE assets (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES assessment_tasks(id),
  asset_uid TEXT,
  api_version TEXT,
  kind TEXT NOT NULL,
  namespace TEXT,
  name TEXT NOT NULL,
  labels_json TEXT NOT NULL DEFAULT '{}',
  spec_hash TEXT,
  risk_tags_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE checkpoints (
  id TEXT PRIMARY KEY,
  tender_seq TEXT,
  level1 TEXT,
  level2 TEXT,
  level3 TEXT NOT NULL,
  description TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1.0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES assessment_tasks(id),
  tool_id TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id),
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  score REAL NOT NULL,
  asset_json TEXT,
  evidence_json TEXT NOT NULL,
  remediation TEXT NOT NULL,
  references_json TEXT NOT NULL DEFAULT '[]',
  fingerprint TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE metric_weights (
  checkpoint_id TEXT PRIMARY KEY REFERENCES checkpoints(id),
  weight REAL NOT NULL DEFAULT 1.0,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES assessment_tasks(id),
  summary_json TEXT NOT NULL,
  html_path TEXT,
  markdown_path TEXT,
  created_at TIMESTAMP NOT NULL
);
```

---

## 7. API 合约

### 7.1 Target API

```http
POST /api/targets
GET  /api/targets
GET  /api/targets/{target_id}
DELETE /api/targets/{target_id}
```

示例请求：

```json
{
  "name": "demo-kind",
  "type": "kubernetes",
  "connection_mode": "kubeconfig",
  "kubeconfig": "<base64 or encrypted ref>",
  "labels": {"env": "demo"}
}
```

### 7.2 Assessment API

```http
POST /api/assessments
GET  /api/assessments
GET  /api/assessments/{task_id}
POST /api/assessments/{task_id}/cancel
GET  /api/assessments/{task_id}/findings
GET  /api/assessments/{task_id}/summary
GET  /api/assessments/{task_id}/report
WS   /ws/assessments/{task_id}
```

示例请求：

```json
{
  "target_id": "target-demo-kind",
  "profile": "cloud_native_full",
  "options": {
    "include_control_plane_deep_check": false,
    "include_runtime_events": true,
    "registry_scan": "mock",
    "destructive_tests": false
  }
}
```

### 7.3 Indicator / Weight API

```http
GET  /api/checkpoints
PATCH /api/checkpoints/{checkpoint_id}/weight
POST /api/checkpoints
PATCH /api/checkpoints/{checkpoint_id}
```

### 7.4 Finding 查询 API

```http
GET /api/findings?task_id=&tool_id=&checkpoint_id=&severity=&status=&namespace=&kind=&keyword=
GET /api/findings/{finding_id}
```

---

## 8. 插件接口设计

### 8.1 Adapter 抽象接口

```python
class ToolAdapter(Protocol):
    tool_id: str

    def healthcheck(self) -> AdapterHealth:
        ...

    async def collect(self, target: Target, options: dict) -> list[RawSnapshot]:
        ...

    async def evaluate(self, task: AssessmentTask, snapshots: list[RawSnapshot]) -> list[Finding]:
        ...

    async def normalize(self, raw_findings: list[Any]) -> list[Finding]:
        ...
```

### 8.2 三类 Adapter

| Adapter | 本期状态 | 说明 |
|---|---|---|
| `CloudNativeAdapter` | 完整实现 | Kubernetes 资产采集、规则执行、结果输出。 |
| `CloudApiSecurityAdapterStub` | stub | 返回 3-5 条示例 API 风险 findings，验证集成、调度、展示链路。 |
| `SmartCloudSecurityAdapterStub` | stub | 返回 3-5 条示例智算云风险 findings，验证集成、调度、展示链路。 |

### 8.3 Rule Registry 设计

```yaml
id: CN-IMM-002
checkpoint_id: CN-23
tool_id: cloud_native
domain: 不可变基础设施与弹性安全评估
title: 容器根文件系统应设置只读
severity: high
default_weight: 1.0
resource_kinds:
  - Pod
  - Deployment
  - StatefulSet
  - DaemonSet
  - Job
logic:
  type: python
  handler: app.rules.immutable.check_readonly_rootfs
pass_condition: "所有业务容器 securityContext.readOnlyRootFilesystem == true"
fail_condition: "存在任一业务容器未设置或设置为 false"
evidence_fields:
  - spec.template.spec.containers[*].securityContext.readOnlyRootFilesystem
remediation: |
  在容器 securityContext 中设置 readOnlyRootFilesystem: true。
  对需要写入的路径使用 emptyDir 或 PVC 挂载到指定目录。
references:
  - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
```

---

## 9. Kubernetes 采集清单

### 9.1 默认只读采集资源

| 类别 | 资源 |
|---|---|
| 基础 | Namespace、Node、Event、Pod、Service、EndpointSlice、Ingress、ConfigMap、Secret 元信息 |
| Workload | Deployment、ReplicaSet、StatefulSet、DaemonSet、Job、CronJob |
| 弹性 | HPA、PDB、ResourceQuota、LimitRange、PriorityClass |
| 身份权限 | ServiceAccount、Role、RoleBinding、ClusterRole、ClusterRoleBinding、CSR |
| 网络 | NetworkPolicy、IngressClass、Gateway/HTTPRoute（如存在） |
| 存储 | StorageClass、PV、PVC、VolumeSnapshotClass、VolumeSnapshot（如存在） |
| 准入/策略 | ValidatingAdmissionPolicy、MutatingAdmissionPolicy、ValidatingWebhookConfiguration、MutatingWebhookConfiguration |
| Kyverno/Gatekeeper | Policy、ClusterPolicy、PolicyReport、ConstraintTemplate、Constraint（如存在） |
| Istio | PeerAuthentication、RequestAuthentication、AuthorizationPolicy、DestinationRule、VirtualService（如存在） |
| Trivy/Falco | VulnerabilityReport、ConfigAuditReport、RbacAssessmentReport、Falco Event（如存在） |

### 9.2 最小 RBAC 示例

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cn-security-assessor
  namespace: cn-security
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cn-security-assessor-readonly
rules:
- apiGroups: [""]
  resources: ["namespaces","nodes","pods","services","configmaps","secrets","events","persistentvolumes","persistentvolumeclaims","serviceaccounts"]
  verbs: ["get","list","watch"]
- apiGroups: ["apps"]
  resources: ["deployments","replicasets","statefulsets","daemonsets"]
  verbs: ["get","list","watch"]
- apiGroups: ["batch"]
  resources: ["jobs","cronjobs"]
  verbs: ["get","list","watch"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get","list","watch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get","list","watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies","ingresses","ingressclasses"]
  verbs: ["get","list","watch"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses","csidrivers","csinodes"]
  verbs: ["get","list","watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles","rolebindings","clusterroles","clusterrolebindings"]
  verbs: ["get","list","watch"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingadmissionpolicies","validatingadmissionpolicybindings","validatingwebhookconfigurations","mutatingwebhookconfigurations"]
  verbs: ["get","list","watch"]
- apiGroups: ["security.istio.io","networking.istio.io"]
  resources: ["peerauthentications","requestauthentications","authorizationpolicies","destinationrules","virtualservices"]
  verbs: ["get","list","watch"]
- apiGroups: ["kyverno.io","wgpolicyk8s.io","constraints.gatekeeper.sh","templates.gatekeeper.sh","aquasecurity.github.io"]
  resources: ["*"]
  verbs: ["get","list","watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cn-security-assessor-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cn-security-assessor-readonly
subjects:
- kind: ServiceAccount
  name: cn-security-assessor
  namespace: cn-security
```

> 注意：读取 Secret 内容会引入敏感数据风险。原型默认只读取 Secret 元信息、类型、引用关系、是否被滥用，不持久化 Secret data。确需检测泄露时，使用 Trivy Operator 报告或对离线测试环境开启脱敏扫描。

---

## 10. 云原生工具本体检查点覆盖矩阵

| 标书序号 | 检查点 | 规则 ID | MVP 实现 | 主要数据源 | 证据与验收 |
|---:|---|---|---|---|---|
| 6 | 微服务弹性能力评估 | CN-ELAS-001 | 检查 Deployment/StatefulSet 是否配置 HPA、PDB、resources requests/limits；如安装 Istio，检查 DestinationRule/VirtualService 是否配置 timeout/retry/outlierDetection；demo 模式可在专用 namespace 发起轻量负载触发 HPA。 | HPA、PDB、Deployment、StatefulSet、Pod、metrics、Istio CRD | 输出每个 workload 的弹性评分；至少给出 HPA 缺失、PDB 缺失、资源限制缺失、服务网格容错缺失的证据。 |
| 22 | 验证不可变部署原则 | CN-IMM-001 | 检查容器是否暴露 22 端口或运行 sshd；检查镜像是否使用 `latest` 或未固定 digest；检查 RBAC 是否给普通主体 `pods/exec` 宽泛权限；检查容器是否允许写根文件系统。 | Pod、Workload template、Service、RBAC、镜像引用 | 发现“可远程登录/可 exec 修改/镜像不可追溯/根文件系统可写”等问题，并给出对象路径。 |
| 23 | 容器不可变安全管控 | CN-IMM-002 | 检查 `readOnlyRootFilesystem`、`runAsNonRoot`、`allowPrivilegeEscalation=false`；建立 workload spec hash 基线，二次扫描识别漂移；检查 Job TTL、Completed/Failed Pod、旧 ReplicaSet、孤儿 ConfigMap/Secret。 | Pod/Workload、ReplicaSet、Job、Event、历史 spec_hash | 首次扫描生成基线；二次扫描能识别漂移；列出未只读、未清理、废弃资源。 |
| 24 | 弹性扩缩容安全 | CN-ELAS-002 | 检查 Namespace 是否启用 PSA label；检查 Kyverno/Gatekeeper/VAP 是否覆盖 Pod 安全策略；检查新版本 rollout strategy；检查 HPA 扩容后的新 Pod template 是否通过同一规则包。 | Namespace、AdmissionPolicy、Kyverno/Gatekeeper、Deployment、HPA | 证明“新增/扩容 Pod 会自动套用安全策略”；未启用准入策略时 FAIL/WARN。 |
| 25 | 弹性资源安全策略管控 | CN-ELAS-003 | 检查 ResourceQuota、LimitRange、PriorityClass、默认 requests/limits；检查节点/Pod 相关准入策略和 DaemonSet 覆盖；检查新 Pod/节点是否能被策略自动纳管。 | ResourceQuota、LimitRange、PriorityClass、Node、DaemonSet、AdmissionPolicy | 每个 namespace 输出资源治理状态；新 Pod 策略缺失标为 FAIL。 |
| 26 | 弹性扩缩容行为安全防护 | CN-ELAS-004 | 检查 HPA `minReplicas/maxReplicas`、扩容上限、资源配额；分析 `scale` subresource RBAC；从 Event/Audit log 中识别短时间异常 scale 行为；demo 中用模拟事件验证。 | HPA、ResourceQuota、RBAC、Event、Audit log | 输出恶意扩容防护评分；能发现 maxReplicas 过高、scale 权限过宽、异常扩缩事件。 |
| 27 | 弹性资源生命周期安全治理 | CN-ELAS-005 | 检查 Job/CronJob TTL、Pod ownerReferences、孤儿 PVC/PV/Service/Ingress、终止 namespace 残留 finalizer；输出清理建议。 | Pod、Job、CronJob、PVC/PV、Service、Ingress、Namespace | 生成“弹性资源生命周期风险清单”，列出残留资源和安全清理动作。 |
| 28 | 身份认证机制评估模块 | CN-IAM-001 | 检查 RBAC 是否可用、匿名访问风险、`system:unauthenticated` 绑定、OIDC/外部认证证据、ServiceAccount token 自动挂载、Istio mTLS STRICT、API Server TLS 证据。 | RBAC、ServiceAccount、Pod、API discovery、Istio PeerAuthentication、可选 apiserver flags | 输出认证机制覆盖率；匿名访问、默认不安全配置、mTLS 未强制均能定位。 |
| 29 | 动态访问控制评估模块 | CN-IAM-002 | 构建主体-资源-动作权限矩阵，覆盖 Pod/Service/ConfigMap/Secret/Ingress/Namespace 等；识别 `*`、`secrets list/watch`、`pods/exec`、`bind/escalate/impersonate`；检查准入策略是否支持基于 namespace/label/env 的上下文控制；检查临时授权过期标记。 | Role、ClusterRole、Binding、AdmissionPolicy、Kyverno/Gatekeeper、Certificate/Token 信息 | UI 支持按主体/资源查询权限；报告列出过度授权、可提权路径、缺少动态上下文策略。 |
| 30 | 身份安全强化模块 | CN-IAM-003 | 检查 Service/Pod 是否暴露 SSH；可选接入 Falco/auth.log/audit log，识别 SSH 暴破、容器 exec、异常登录；建立身份安全持续审计事件表。 | Service、Pod、Node、Falco event、auth.log、audit log | demo 能通过样例日志生成 SSH 暴破告警；无日志源时标 UNKNOWN 并给补充接入建议。 |
| 35 | etcd 访问控制与加密检测 | CN-PER-001 | 自建集群：解析 kube-apiserver/etcd static pod args，检查 etcd TLS、client-cert-auth、peer TLS、Secret encryption-provider-config；托管集群：通过可见证据判定，无法访问则 UNKNOWN。 | Static Pod、Node 文件采集器、API Server flags、Secret 加密配置 | 输出 etcd TLS 与 API 数据静态加密结论；证据不可见时说明原因。 |
| 36 | 持久卷 PV 安全评估 | CN-PER-002 | 检查 StorageClass 加密参数、KMS key、reclaimPolicy、volumeBindingMode、allowVolumeExpansion、PV accessMode、hostPath/local 风险、VolumeSnapshotClass/备份对象存在性。 | StorageClass、PV、PVC、VolumeSnapshot、Velero CRD | 每个 StorageClass/PV 输出安全基线；能发现未加密、拓扑绑定不当、快照/备份缺失。 |
| 37 | 有状态应用数据安全 | CN-PER-003 | 识别 StatefulSet/数据库 Pod；检查 PVC 加密、数据库 Service NetworkPolicy、TLS Secret 引用、明文环境变量、备份策略、KMS/CSI Secret Store 集成。 | StatefulSet、Pod、PVC、Secret 元信息、NetworkPolicy、Backup CRD | 输出有状态应用数据保护清单；发现明文密码、无网络隔离、无备份/加密。 |
| 38 | 镜像仓库数据安全 | CN-REG-001 | 从镜像引用识别仓库；支持 Harbor/Registry mock adapter；检查 HTTPS、匿名拉取、robot account、审计事件、镜像拉取/删除异常；可接入 Trivy/registry scan 检测漏洞和泄露。 | Pod image、imagePullSecret、Registry API、Trivy Report、Harbor audit | 输出仓库安全状态；无 registry 凭据时至少完成镜像引用和 pull secret 使用风险分析。 |
| 39 | 数据持久化异常监控模块 | CN-PER-004 | 接入 Falco/event/audit log；规则检测异常文件写入、卷挂载逃逸、敏感路径访问、容器内 shell、异常 PVC 挂载；demo 用样例事件驱动。 | Falco alerts、Audit log、Event、Pod volumeMounts | 能展示实时/历史异常事件；每条告警关联 Pod/PVC/Namespace 和整改建议。 |

---

## 11. 工具集成数据处理检查点覆盖矩阵

| 标书序号 | 检查点 | 实现设计 | 验收方式 |
|---:|---|---|---|
| 1 | 数据格式分析 | 对 CloudNativeAdapter、API Stub、SmartCloud Stub 的 raw output 建立 `raw_snapshots`，记录 source/kind/schema_version/hash。 | 页面或接口可查看每类工具原始输入摘要；日志显示格式识别结果。 |
| 2 | 数据格式定义 | 定义统一 `Target/Asset/Finding/Metric/Report` JSON schema，所有 adapter 输出必须转换到该模型。 | 提供 `/api/schema/finding` 或本地 JSON schema 文件；单元测试校验 schema。 |
| 3 | 数据格式转换实现 | 实现 `normalize_findings()`，将云原生规则结果、Trivy/Kyverno/Gatekeeper 报告、两个 stub 输出统一转换。 | 同一个任务中三类工具 finding 能一起查询、过滤和汇总。 |
| 4 | 数据标准化清洗 | 去重 fingerprint、严重度归一化、状态归一化、Secret data 脱敏、资产引用解析、UNKNOWN 原因归类。 | 重复 finding 不重复展示；敏感字段不会落库；数据质量报告有统计。 |
| 5 | 数据质量评估 | 计算 completeness、freshness、duplicate_rate、unknown_rate、schema_error_count。 | 任务完成后生成质量报告；UNKNOWN 占比过高时展示证据不足提示。 |
| 6 | 数据格式优化 | 对 findings、assets、raw_snapshots 建索引；维护 `schema_version`；为前端输出扁平化 summary。 | 大量 findings 下查询仍可按 namespace/severity/status 快速过滤。 |
| 7 | 工具集成框架构建 | 实现 ToolAdapter 接口、adapter registry、healthcheck、统一错误处理、任务状态机。 | 三类 adapter 均能被 orchestrator 调用；某个 stub 失败不影响云原生结果。 |
| 8 | 云上 API 安全评估工具接入适配 | 实现 `CloudApiSecurityAdapterStub`，接收统一参数，返回 mock API 风险 finding。 | API 工具详情页有示例结果和“stub”标记；统一态势能纳入 mock 分数。 |
| 9 | 云原生安全评估工具接入适配 | 实现 `CloudNativeAdapter`，完成采集、规则执行、证据输出。 | 云原生工具详情页能展示三大能力域和全部检查点结果。 |
| 10 | 智算云安全评估工具接入适配 | 实现 `SmartCloudSecurityAdapterStub`，返回 mock GPU/模型服务/镜像风险 finding。 | 智算云详情页有占位结果，不阻塞整体报告。 |
| 11 | 调用参数标准化 | 定义 `AssessmentRequest`，统一 target、profile、options、adapter 参数。 | 同一 API 可以触发单工具或多工具评估。 |
| 12 | 调用流程协调 | Orchestrator 按优先级执行 CloudNative -> stubs -> normalization -> scoring -> report；实现任务锁和状态流。 | WebSocket/轮询能看到任务进度；失败 adapter 有错误详情。 |
| 13 | 输出格式归一化 | 所有 adapter 输出 Finding；报告层只依赖 Finding/Metric，不依赖工具内部结构。 | 新增 stub 不改 UI 核心代码。 |
| 14 | 结果汇总整合 | Aggregator 按 tool/domain/checkpoint/severity 汇总，生成 overall_score 和整改优先级。 | 总览页和报告可同时显示三类工具综合态势。 |

---

## 12. 集成可视化展示检查点覆盖矩阵

| 标书序号 | 检查点 | 页面/功能 | 验收方式 |
|---:|---|---|---|
| - | 指标录入管理 | 指标管理页：CRUD 检查点、规则、启用状态、适用范围。 | 可新增一个手工指标并纳入报告。 |
| - | 评估指标赋权 | 指标权重页：按一级/二级/三级模块调整权重；保存到 `metric_weights`。 | 调整权重后重新计算综合分。 |
| - | 综合结果分析集成，符合度判定 | 结果分析页：按 PASS/WARN/FAIL/UNKNOWN 计算符合度，输出“符合/基本符合/不符合/证据不足”。 | 报告中给出每个检查点结论和依据。 |
| 16 | 多工具安全态势总览 | 首页 Dashboard：总分、风险趋势、严重度分布、工具分数、三大云原生域雷达图、Top 风险 namespace。 | 三类工具结果同屏展示；CloudNative 是主图。 |
| 17 | API 工具结果详览 | API 工具详情页：展示 stub 结果、参数、mock 证据、后续接入说明。 | 可从总览点击进入并筛选 findings。 |
| 18 | 云原生工具结果详览 | 云原生详情页：三大域、15 个检查点、规则列表、资产证据、整改 YAML、原始片段。 | 任一 finding 可 drill-down 到资产和 json_path。 |
| 19 | 智算云工具结果详览 | 智算云详情页：展示 stub 结果和未来真实 adapter 插槽。 | 页面存在，结果参与总览但标记 mock。 |
| 20 | 数据筛选交互 | 全局筛选：tool/domain/checkpoint/severity/status/namespace/kind/name/time。 | 筛选条件作用于总览、详情、报告预览。 |
| 21 | 结果交互查询 | 点击图表/表格进入 finding 详情；支持按资产查询相关 findings；支持复制整改建议。 | 用户可从风险图点击到具体 Pod/Role/PVC 的证据。 |

---

## 13. 前端页面设计

### 13.1 页面路由

```text
/
/targets
/assessments
/assessments/:taskId/overview
/assessments/:taskId/cloud-native
/assessments/:taskId/cloud-api
/assessments/:taskId/smart-cloud
/assessments/:taskId/findings
/assessments/:taskId/report
/indicators
/settings/adapters
```

### 13.2 首页总览组件

- 总分卡片：overall_score、结论、critical/high 数。
- 三工具分数卡：云原生、云上 API stub、智算云 stub。
- 严重度柱状图。
- 三大云原生域雷达图。
- 检查点符合度热力图。
- Top 10 风险资产表。
- 数据质量提示：unknown_rate、freshness、schema_error_count。

### 13.3 云原生详情页组件

- 左侧：三大域树形导航。
- 中部：检查点结果表，列包括 checkpoint、score、status、failed rules、affected assets。
- 右侧：选中 finding 的证据卡片，包括资产定位、原始字段、期望值、观察值、整改建议。
- 顶部筛选：namespace、kind、severity、status、keyword。
- 导出：当前筛选结果导出 Markdown/CSV。

---

## 14. 待测 PVE/K8s 靶场环境与 Agent SSH 运维指导

> 本节是给 coding/ops agent 的执行手册。目标不是把评估工具部署到 PVE 上，而是先在一个隔离的、可反复重建的 **嵌套虚拟化 PVE 环境** 中搭建多节点 Kubernetes，作为“待安全评估的云原生平台”。评估系统随后通过 kubeconfig、PVE/节点日志、Falco/Trivy/Kyverno 等数据源对该平台进行检测。

### 14.1 靶场建设目标、边界与交付物

**目标**

1. agent 通过 SSH 登录 PVE，自动化创建多台 VM 和必要 LXC 容器。
2. 在 VM 上用 kubeadm 搭建一个可扫描的 Kubernetes 集群。
3. 安装能支撑标书检查点取证的组件：CNI、metrics-server、Kyverno、Falco、Trivy Operator、可选 Gatekeeper、可选本地镜像仓库、可选 NFS/日志容器。
4. 部署 `cnsec-good` 与 `cnsec-bad` 两组命名空间和样例工作负载，保证所有云原生检查点都有可演示证据。
5. 导出评估系统所需连接材料：`kubeconfig`、PVE 资产清单、节点清单、可选日志样例、组件健康检查输出。

**边界**

- 本节命令只用于一次性靶场或隔离实验环境，不要在生产 PVE 上直接执行。
- PVE host 只承担虚拟化、网络、LXC/VM 生命周期管理，不建议在 PVE host 上安装 Docker、评估后端或扫描数据库。
- Kubernetes 节点使用 VM 而不是 LXC，避免容器运行时、内核参数、Falco、CNI 和 kubeadm 在 LXC 中产生额外兼容性问题。
- LXC 只用于辅助服务，例如 registry mock、NFS mock、日志收集 mock、堡垒/工具箱。
- 所有危险配置，例如暴露 22 端口、过度 RBAC、无加密 PV、HTTP registry，只允许部署在 `cnsec-bad` 命名空间或专用辅助容器中。

**交付物**

```text
/root/cnsec-lab/
  lab.env                         # 当前靶场变量
  inventory.json                   # PVE VM/LXC 与 K8s 节点资产清单
  kubeconfig                       # 供评估系统连接 Kubernetes
  join-command.sh                  # worker join 命令，仅靶场内部使用
  preflight.txt                    # PVE/KVM/存储/网络预检输出
  healthcheck.txt                  # K8s 与安全组件健康检查输出
  manifests/
    cnsec-good.yaml
    cnsec-bad.yaml
  logs/
    authlog_ssh_bruteforce.log
    falco_events.jsonl
  scripts/
    *.sh
```

### 14.2 推荐拓扑

```text
开发机 / coding agent
  │
  │ SSH: root 或具备 sudo/qm/pct 权限的 agent 用户
  ▼
PVE nested host: pve-nested-01
  ├─ vmbr0: 管理网 / 出口网，可访问互联网或软件镜像源
  ├─ vmbr1: 靶场内网 10.20.0.0/24，PVE 做 NAT 网关 10.20.0.1
  │
  ├─ VM 101: k8s-cp-1      10.20.0.11  4 vCPU / 8 GiB / 80 GiB
  ├─ VM 102: k8s-worker-1  10.20.0.21  4 vCPU / 8 GiB / 80 GiB
  ├─ VM 103: k8s-worker-2  10.20.0.22  4 vCPU / 8 GiB / 80 GiB
  ├─ VM 104: k8s-worker-3  10.20.0.23  4 vCPU / 8 GiB / 80 GiB，可选
  │
  ├─ CT 201: registry-lab  10.20.0.31  HTTP registry / Harbor mock，可选
  ├─ CT 202: nfs-lab       10.20.0.32  NFS / backup mock，可选
  └─ CT 203: log-sink      10.20.0.33  auth.log / Falco webhook mock，可选

Kubernetes Pod CIDR:     10.244.0.0/16
Kubernetes Service CIDR: 10.96.0.0/12
```

**资源建议**

| 规模 | PVE nested host 建议 | K8s 规模 | 适用场景 |
|---|---:|---|---|
| 最小演示 | 8 vCPU / 24 GiB RAM / 200 GiB SSD | 1 control-plane + 1 worker | 只跑静态检查、少量安全组件。 |
| 标准演示 | 12-16 vCPU / 48-64 GiB RAM / 300-500 GiB SSD | 1 control-plane + 2 workers + 1-2 LXC | 推荐。可运行 Falco、Trivy、Kyverno、metrics-server 和 bad workloads。 |
| 高保真演示 | 24+ vCPU / 96+ GiB RAM / 1 TiB SSD | 3 control-plane + 3 workers + registry/storage/log LXC | 用于 HA、滚动升级、更多持久化和审计场景。 |

### 14.3 Agent SSH 契约与变量文件

agent 拿到 PVE SSH 权限后，第一步写入统一变量文件，后续所有脚本只读这个文件，避免把地址、存储名、网桥名写死。

```bash
mkdir -p /root/cnsec-lab/{scripts,logs,artifacts,manifests}
cat >/root/cnsec-lab/lab.env <<'EOF'
# PVE 基础参数
PVE_NODE="pve-nested-01"
PVE_STORAGE="local-lvm"
PVE_ISO_STORAGE="local"
PVE_SNIPPET_STORAGE="local"
PVE_MGMT_BRIDGE="vmbr0"
PVE_LAB_BRIDGE="vmbr1"
PVE_LAB_CIDR="10.20.0.0/24"
PVE_LAB_GW="10.20.0.1"
PVE_NAT_OUT_IF="vmbr0"

# VM 模板与节点
UBUNTU_CLOUD_IMAGE="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
UBUNTU_TEMPLATE_ID="9000"
SSH_PUBKEY_PATH="/root/.ssh/agent_lab.pub"
K8S_MINOR="v1.36"
K8S_VERSION="stable-1.36"
POD_CIDR="10.244.0.0/16"
SERVICE_CIDR="10.96.0.0/12"

# 节点 IP
CP1_ID="101"; CP1_NAME="k8s-cp-1"; CP1_IP="10.20.0.11"
W1_ID="102";  W1_NAME="k8s-worker-1"; W1_IP="10.20.0.21"
W2_ID="103";  W2_NAME="k8s-worker-2"; W2_IP="10.20.0.22"

# 可选 LXC
REGISTRY_CT_ID="201"; REGISTRY_IP="10.20.0.31"
NFS_CT_ID="202";      NFS_IP="10.20.0.32"
LOG_CT_ID="203";      LOG_IP="10.20.0.33"
EOF
```

建议 agent 每次执行前都加载变量，并打开严格错误处理：

```bash
set -euo pipefail
source /root/cnsec-lab/lab.env
```

如果必须使用非 root 用户，可以创建 PVE 用户和 API token；但 PVE 上的 `qm`、`pct`、`pvesh` 许多操作实际仍需要 root 或等效权限。投标演示环境建议使用一次性 root SSH key，演示结束直接销毁 PVE nested host。

```bash
# 可选：创建 PVE API 用户，便于后续评估系统接 PVE API 采集资产清单。
pveum user add agent@pam --comment "cnsec lab automation agent" || true
pveum aclmod / -user agent@pam -role Administrator
pveum user token add agent@pam cnsec-lab --privsep 0
```

### 14.4 PVE 嵌套虚拟化预检

PVE 是运行在外层虚拟化上的 nested host，因此 agent 必须先确认 PVE 内部能看到硬件虚拟化扩展，否则 KVM VM 会非常慢或无法启动。

```bash
cat >/root/cnsec-lab/scripts/00-pve-preflight.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env
OUT=/root/cnsec-lab/preflight.txt
{
  echo "## PVE version"
  pveversion -v || true
  echo
  echo "## CPU virtualization flags"
  egrep -m 5 -o 'vmx|svm' /proc/cpuinfo || true
  echo
  echo "## KVM modules"
  lsmod | grep -E '^kvm|kvm_intel|kvm_amd' || true
  echo
  echo "## Nested parameter"
  cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || true
  cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || true
  echo
  echo "## Storage"
  pvesm status || true
  echo
  echo "## Network"
  ip -br addr || true
  echo
  echo "## Existing VMs/CTs"
  qm list || true
  pct list || true
} | tee "$OUT"

if ! egrep -q 'vmx|svm' /proc/cpuinfo; then
  echo "ERROR: 当前 PVE nested host 看不到 vmx/svm。请先在外层虚拟化平台开启 nested virtualization / expose hardware virtualization。" >&2
  exit 10
fi
EOF
chmod +x /root/cnsec-lab/scripts/00-pve-preflight.sh
/root/cnsec-lab/scripts/00-pve-preflight.sh
```

判定规则：

| 检查 | 通过条件 | 失败处理 |
|---|---|---|
| `vmx/svm` | `/proc/cpuinfo` 可见 | 先停止，不创建 VM。要求外层平台透传硬件虚拟化。 |
| `kvm_intel/kvm_amd` | 模块已加载 | 尝试 `modprobe kvm_intel nested=1` 或 `modprobe kvm_amd nested=1`，但通常外层未透传才是根因。 |
| `pvesm status` | `local-lvm` 或等效存储可用 | 修改 `PVE_STORAGE`。 |
| `vmbr0` | 有管理 IP 和出口 | 修改 `PVE_NAT_OUT_IF` 或使用已有出口网桥。 |

### 14.5 PVE 网络、NAT 与隔离

标准做法是保留 `vmbr0` 作为管理与出口，新增无物理端口的 `vmbr1` 作为 K8s 靶场内网。PVE 在 `vmbr1` 上提供网关 IP，并通过 `vmbr0` 做 NAT 出口。

```bash
cat >/root/cnsec-lab/scripts/01-pve-network.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env
cp /etc/network/interfaces "/etc/network/interfaces.$(date +%Y%m%d%H%M%S).bak"

if ! grep -q "iface ${PVE_LAB_BRIDGE} inet static" /etc/network/interfaces; then
cat >>/etc/network/interfaces <<EOF2

auto ${PVE_LAB_BRIDGE}
iface ${PVE_LAB_BRIDGE} inet static
    address ${PVE_LAB_GW}/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOF2
fi

if command -v ifreload >/dev/null 2>&1; then
  ifreload -a
else
  systemctl restart networking
fi

cat >/etc/sysctl.d/99-cnsec-lab.conf <<EOF2
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF2
sysctl --system

# 简化起见使用 iptables 持久化 NAT。若 PVE 已统一使用 nftables，请按现场防火墙策略改写为 nft 规则。
iptables -t nat -C POSTROUTING -s "${PVE_LAB_CIDR}" -o "${PVE_NAT_OUT_IF}" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "${PVE_LAB_CIDR}" -o "${PVE_NAT_OUT_IF}" -j MASQUERADE
iptables -C FORWARD -i "${PVE_LAB_BRIDGE}" -o "${PVE_NAT_OUT_IF}" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "${PVE_LAB_BRIDGE}" -o "${PVE_NAT_OUT_IF}" -j ACCEPT
iptables -C FORWARD -i "${PVE_NAT_OUT_IF}" -o "${PVE_LAB_BRIDGE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "${PVE_NAT_OUT_IF}" -o "${PVE_LAB_BRIDGE}" -m state --state RELATED,ESTABLISHED -j ACCEPT

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent curl jq git wget unzip || true
netfilter-persistent save || true
ip -br addr show "${PVE_LAB_BRIDGE}"
EOF
chmod +x /root/cnsec-lab/scripts/01-pve-network.sh
/root/cnsec-lab/scripts/01-pve-network.sh
```

验收命令：

```bash
ip addr show vmbr1
sysctl net.ipv4.ip_forward
iptables -t nat -S | grep 10.20.0.0 || true
```

### 14.6 Ubuntu Cloud-Init 模板与 K8s VM 创建

使用 cloud-init 模板的好处是 agent 可以快速销毁和重建节点，并保证每台 VM 有唯一主机名、IP、SSH key。

```bash
cat >/root/cnsec-lab/scripts/02-create-ubuntu-template.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env
IMG="/var/lib/vz/template/iso/ubuntu-24.04-server-cloudimg-amd64.img"

if [ ! -s "${SSH_PUBKEY_PATH}" ]; then
  echo "ERROR: 缺少 SSH public key: ${SSH_PUBKEY_PATH}" >&2
  exit 20
fi

wget -nc -O "$IMG" "$UBUNTU_CLOUD_IMAGE"

if qm status "$UBUNTU_TEMPLATE_ID" >/dev/null 2>&1; then
  echo "Template VM ${UBUNTU_TEMPLATE_ID} already exists, skip."
  exit 0
fi

qm create "$UBUNTU_TEMPLATE_ID" \
  --name ubuntu-2404-k8s-template \
  --memory 2048 \
  --cores 2 \
  --cpu host \
  --net0 virtio,bridge="$PVE_LAB_BRIDGE" \
  --ostype l26 \
  --agent enabled=1 \
  --scsihw virtio-scsi-single \
  --serial0 socket \
  --vga serial0

qm importdisk "$UBUNTU_TEMPLATE_ID" "$IMG" "$PVE_STORAGE"
qm set "$UBUNTU_TEMPLATE_ID" --scsi0 "${PVE_STORAGE}:vm-${UBUNTU_TEMPLATE_ID}-disk-0"
qm set "$UBUNTU_TEMPLATE_ID" --ide2 "${PVE_STORAGE}:cloudinit"
qm set "$UBUNTU_TEMPLATE_ID" --boot order=scsi0
qm set "$UBUNTU_TEMPLATE_ID" --ciuser agent --sshkeys "$SSH_PUBKEY_PATH"
qm set "$UBUNTU_TEMPLATE_ID" --ipconfig0 ip=dhcp
qm resize "$UBUNTU_TEMPLATE_ID" scsi0 +18G
qm template "$UBUNTU_TEMPLATE_ID"
EOF
chmod +x /root/cnsec-lab/scripts/02-create-ubuntu-template.sh
/root/cnsec-lab/scripts/02-create-ubuntu-template.sh
```

创建多台 VM：

```bash
cat >/root/cnsec-lab/scripts/03-create-k8s-vms.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env

create_vm() {
  local id="$1" name="$2" ip="$3" cores="$4" mem="$5" disk_add="$6"
  if qm status "$id" >/dev/null 2>&1; then
    echo "VM $id $name exists, skip clone."
  else
    qm clone "$UBUNTU_TEMPLATE_ID" "$id" --name "$name" --full 1 --storage "$PVE_STORAGE"
    qm set "$id" \
      --cpu host \
      --cores "$cores" \
      --memory "$mem" \
      --net0 virtio,bridge="$PVE_LAB_BRIDGE" \
      --ipconfig0 ip="${ip}/24",gw="$PVE_LAB_GW" \
      --nameserver "1.1.1.1" \
      --searchdomain "cnsec.lab" \
      --ciuser agent \
      --sshkeys "$SSH_PUBKEY_PATH" \
      --agent enabled=1
    qm resize "$id" scsi0 "+${disk_add}G" || true
  fi
  qm start "$id" || true
}

create_vm "$CP1_ID" "$CP1_NAME" "$CP1_IP" 4 8192 60
create_vm "$W1_ID"  "$W1_NAME"  "$W1_IP"  4 8192 60
create_vm "$W2_ID"  "$W2_NAME"  "$W2_IP"  4 8192 60

cat >/root/cnsec-lab/inventory.json <<EOF2
{
  "pve_node": "${PVE_NODE}",
  "network": {"bridge": "${PVE_LAB_BRIDGE}", "cidr": "${PVE_LAB_CIDR}", "gateway": "${PVE_LAB_GW}"},
  "vms": [
    {"id": ${CP1_ID}, "name": "${CP1_NAME}", "ip": "${CP1_IP}", "role": "control-plane"},
    {"id": ${W1_ID}, "name": "${W1_NAME}", "ip": "${W1_IP}", "role": "worker"},
    {"id": ${W2_ID}, "name": "${W2_NAME}", "ip": "${W2_IP}", "role": "worker"}
  ]
}
EOF2
EOF
chmod +x /root/cnsec-lab/scripts/03-create-k8s-vms.sh
/root/cnsec-lab/scripts/03-create-k8s-vms.sh
```

VM 启动后做 SSH 连通性检查：

```bash
source /root/cnsec-lab/lab.env
for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  ssh -o StrictHostKeyChecking=accept-new agent@"$ip" 'hostname; ip -br a; cloud-init status --wait || true'
done
```

### 14.7 Kubernetes 节点基础软件安装

以下脚本在每台 VM 内执行。它完成 swap、内核模块、sysctl、containerd、kubeadm/kubelet/kubectl 安装。Kubernetes v1.36 的 kubeadm 安装文档要求每台机器至少 2 GB RAM、2 CPU、节点间网络互通、唯一 hostname/MAC/product_uuid，并强调 kubelet 与容器运行时 cgroup driver 要一致；因此这里统一使用 containerd + systemd cgroup。

```bash
cat >/root/cnsec-lab/scripts/10-k8s-node-common.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
K8S_MINOR="${K8S_MINOR:-v1.36}"

sudo swapoff -a
sudo sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab

cat <<EOF2 | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF2
sudo modprobe overlay
sudo modprobe br_netfilter

cat <<EOF2 | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF2
sudo sysctl --system

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gpg apt-transport-https jq chrony containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
sudo sed -i 's/^disabled_plugins = \["cri"\]/disabled_plugins = []/' /etc/containerd/config.toml || true
sudo systemctl enable --now containerd
sudo systemctl restart containerd

sudo mkdir -p /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
cat <<EOF2 | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /
EOF2
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
sudo systemctl enable kubelet

sudo crictl info >/tmp/crictl-info.json || true
kubeadm version
kubelet --version
EOF
chmod +x /root/cnsec-lab/scripts/10-k8s-node-common.sh

source /root/cnsec-lab/lab.env
for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  scp /root/cnsec-lab/scripts/10-k8s-node-common.sh agent@"$ip":/tmp/10-k8s-node-common.sh
  ssh agent@"$ip" "K8S_MINOR=$K8S_MINOR bash /tmp/10-k8s-node-common.sh"
done
```

初始化 control-plane：

```bash
cat >/root/cnsec-lab/scripts/11-k8s-init-control-plane.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env

ssh agent@"$CP1_IP" "sudo hostnamectl set-hostname $CP1_NAME"
ssh agent@"$W1_IP"  "sudo hostnamectl set-hostname $W1_NAME"
ssh agent@"$W2_IP"  "sudo hostnamectl set-hostname $W2_NAME"
for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  ssh agent@"$ip" "cat <<EOF2 | sudo tee -a /etc/hosts
${CP1_IP} ${CP1_NAME}
${W1_IP} ${W1_NAME}
${W2_IP} ${W2_NAME}
EOF2"
done

ssh agent@"$CP1_IP" "sudo kubeadm init \
  --apiserver-advertise-address=${CP1_IP} \
  --control-plane-endpoint=${CP1_IP} \
  --pod-network-cidr=${POD_CIDR} \
  --service-cidr=${SERVICE_CIDR} \
  --kubernetes-version=${K8S_VERSION} \
  --upload-certs"

ssh agent@"$CP1_IP" 'mkdir -p $HOME/.kube && sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config && sudo chown $(id -u):$(id -g) $HOME/.kube/config'
scp agent@"$CP1_IP":/home/agent/.kube/config /root/cnsec-lab/kubeconfig

JOIN_CMD=$(ssh agent@"$CP1_IP" 'sudo kubeadm token create --print-join-command')
echo "sudo ${JOIN_CMD}" >/root/cnsec-lab/join-command.sh
chmod +x /root/cnsec-lab/join-command.sh
for ip in "$W1_IP" "$W2_IP"; do
  ssh agent@"$ip" "sudo ${JOIN_CMD}"
done
EOF
chmod +x /root/cnsec-lab/scripts/11-k8s-init-control-plane.sh
/root/cnsec-lab/scripts/11-k8s-init-control-plane.sh
```

安装 CNI。默认推荐 Calico 或 Cilium 二选一：Calico 简单稳定，适合验证 NetworkPolicy；Cilium 适合后续增强网络可观测性与 eBPF 能力。原型优先用 Calico；需要 Hubble/网络可视化时再换 Cilium。

```bash
# Calico 简化安装。版本可按现场网络策略锁定，也可以由 agent 从官方 release 选择当前稳定版本。
source /root/cnsec-lab/lab.env
CALICO_VERSION="v3.32.0"
ssh agent@"$CP1_IP" "kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
ssh agent@"$CP1_IP" "kubectl -n kube-system rollout status ds/calico-node --timeout=300s || kubectl get pods -A -o wide"
```

验证集群：

```bash
source /root/cnsec-lab/lab.env
ssh agent@"$CP1_IP" 'kubectl get nodes -o wide; kubectl get pods -A -o wide'
```

### 14.8 Helm 与安全/评估支撑组件安装

在 control-plane 上安装 Helm 与安全组件。组件的目的不是“让靶场更安全”，而是给评估工具提供可采集的 CRD、报告和事件证据。

```bash
cat >/root/cnsec-lab/scripts/12-k8s-install-addons.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# 1) metrics-server：支撑 HPA 与资源弹性检查。
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
# 嵌套实验环境常见 kubelet serving cert 不被 metrics-server 信任；仅靶场可使用 insecure tls 参数。
kubectl -n kube-system patch deployment metrics-server --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' || true

# 2) Kyverno：支撑准入策略、Pod Security Standards、策略自动套用检查。
helm repo add kyverno https://kyverno.github.io/kyverno/ || true
helm repo update
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait
helm upgrade --install kyverno-policies kyverno/kyverno-policies -n kyverno --wait \
  --set validationFailureAction=Audit || true

# 3) Trivy Operator：支撑镜像漏洞、配置审计、RBAC、PSS 报告 CRD 采集。
helm repo add aqua https://aquasecurity.github.io/helm-charts/ || true
helm repo update
helm upgrade --install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace --wait \
  --set trivy.ignoreUnfixed=true || true

# 4) Falco：支撑运行时异常、shell/写入/敏感路径访问等事件。嵌套 VM 如驱动不兼容，可用 fixtures/logs/falco_events.jsonl 替代。
helm repo add falcosecurity https://falcosecurity.github.io/charts || true
helm repo update
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace --wait \
  --set tty=true || true

kubectl get pods -A -o wide
EOF
chmod +x /root/cnsec-lab/scripts/12-k8s-install-addons.sh
source /root/cnsec-lab/lab.env
scp /root/cnsec-lab/scripts/12-k8s-install-addons.sh agent@"$CP1_IP":/tmp/12-k8s-install-addons.sh
ssh agent@"$CP1_IP" 'bash /tmp/12-k8s-install-addons.sh'
```

可选 Gatekeeper：如果需要在报告中展示 Gatekeeper ConstraintTemplate/Constraint 采集，可安装；如果 Kyverno 已覆盖准入策略演示，本期可以跳过。

```bash
# 可选，需按 Gatekeeper 官方 release 选择固定版本。
ssh agent@"$CP1_IP" 'kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.20/deploy/gatekeeper.yaml || true'
```

组件与检查点的关系：

| 组件 | 对评估工具的作用 | 覆盖/增强的检查点 |
|---|---|---|
| CNI + NetworkPolicy | 提供 Pod 间隔离策略对象和真实策略执行环境。 | 微服务隔离、有状态应用访问控制、动态访问控制。 |
| metrics-server | 为 HPA 提供 CPU/Memory metrics，支撑弹性扩缩容演示。 | 微服务弹性能力、弹性扩缩容安全、恶意扩容行为。 |
| Kyverno policies | 提供策略自动套用、PSS 审计、准入控制 CRD。 | 容器不可变安全管控、弹性扩缩容安全、动态访问控制。 |
| Trivy Operator | 生成 VulnerabilityReport、ConfigAuditReport、RbacAssessmentReport 等 CRD。 | 镜像仓库数据安全、容器配置风险、RBAC 风险。 |
| Falco | 生成容器 shell、异常写入、敏感路径访问等运行时事件。 | 身份安全强化、数据持久化异常监控。 |
| Gatekeeper，可选 | 提供 OPA/Rego 策略和约束对象。 | 动态访问控制、准入策略覆盖率。 |
| registry-lab，可选 | 提供 HTTP registry、匿名拉取、审计缺失等演示对象。 | 镜像仓库数据安全。 |
| nfs-lab，可选 | 提供 RWX/明文共享存储、备份/快照缺失对象。 | PV 安全、有状态应用数据安全。 |

### 14.9 可选 LXC 辅助容器：registry、NFS、log-sink

PVE LXC 适合放轻量辅助服务，但 Docker-in-LXC 对内核和 cgroup 配置敏感；如失败，优先改用普通 VM 或直接在 Kubernetes 中部署 registry mock。

```bash
cat >/root/cnsec-lab/scripts/20-create-lxc-helpers.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /root/cnsec-lab/lab.env

pveam update
TEMPLATE=$(pveam available --section system | awk '/debian-12-standard/ {print $2; exit}')
if [ -z "$TEMPLATE" ]; then
  echo "ERROR: 找不到 debian-12-standard LXC template" >&2
  exit 30
fi
pveam download local "$TEMPLATE" || true

create_ct() {
  local id="$1" host="$2" ip="$3" mem="$4"
  if pct status "$id" >/dev/null 2>&1; then
    echo "CT $id exists, skip."
  else
    pct create "$id" "local:vztmpl/${TEMPLATE}" \
      --hostname "$host" \
      --cores 2 \
      --memory "$mem" \
      --swap 512 \
      --rootfs "${PVE_STORAGE}:20" \
      --net0 name=eth0,bridge="$PVE_LAB_BRIDGE",ip="${ip}/24",gw="$PVE_LAB_GW" \
      --features nesting=1,keyctl=1 \
      --unprivileged 1 \
      --ssh-public-keys "$SSH_PUBKEY_PATH"
  fi
  pct start "$id" || true
}

create_ct "$REGISTRY_CT_ID" registry-lab "$REGISTRY_IP" 2048
create_ct "$NFS_CT_ID"      nfs-lab      "$NFS_IP"      1024
create_ct "$LOG_CT_ID"      log-sink     "$LOG_IP"      1024

# log-sink：用于接收/保存 demo 日志，不要求复杂依赖。
pct exec "$LOG_CT_ID" -- bash -lc 'apt-get update && apt-get install -y python3 && mkdir -p /srv/cnsec-logs'

# nfs-lab：用于演示 RWX/共享存储风险。
pct exec "$NFS_CT_ID" -- bash -lc 'apt-get update && apt-get install -y nfs-kernel-server && mkdir -p /srv/nfs/cnsec && chmod 777 /srv/nfs/cnsec && echo "/srv/nfs/cnsec *(rw,sync,no_subtree_check,no_root_squash)" >/etc/exports && exportfs -ra && systemctl enable --now nfs-server || true'

# registry-lab：优先尝试 Docker registry，失败则只保留为 HTTP registry mock。
pct exec "$REGISTRY_CT_ID" -- bash -lc 'apt-get update && apt-get install -y docker.io || true'
pct exec "$REGISTRY_CT_ID" -- bash -lc 'docker run -d --restart=always --name registry -p 5000:5000 registry:2 || (mkdir -p /srv/registry-mock && cd /srv/registry-mock && nohup python3 -m http.server 5000 >/tmp/registry-mock.log 2>&1 &)'

pct list
EOF
chmod +x /root/cnsec-lab/scripts/20-create-lxc-helpers.sh
# 可选执行：/root/cnsec-lab/scripts/20-create-lxc-helpers.sh
```

### 14.10 部署 good/bad 工作负载，覆盖全部云原生检查点

`cnsec-good` 用于展示 PASS 证据，`cnsec-bad` 用于稳定地产生 FAIL/WARN。bad workload 不追求业务可用，追求检查点证据完整。

```yaml
# /root/cnsec-lab/manifests/cnsec-bad.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cnsec-bad
  labels:
    purpose: cnsec-demo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-bad
  namespace: cnsec-bad
spec:
  replicas: 1
  selector:
    matchLabels: {app: web-bad}
  template:
    metadata:
      labels: {app: web-bad}
    spec:
      automountServiceAccountToken: true
      containers:
      - name: web
        image: nginx:latest
        ports:
        - containerPort: 80
        - containerPort: 22
        securityContext:
          allowPrivilegeEscalation: true
          runAsUser: 0
        volumeMounts:
        - name: host-etc
          mountPath: /host-etc
      volumes:
      - name: host-etc
        hostPath:
          path: /etc
---
apiVersion: v1
kind: Service
metadata:
  name: web-bad-ssh
  namespace: cnsec-bad
spec:
  selector: {app: web-bad}
  ports:
  - name: ssh
    port: 22
    targetPort: 22
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-bad-hpa
  namespace: cnsec-bad
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-bad
  minReplicas: 1
  maxReplicas: 1000
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
---
apiVersion: batch/v1
kind: Job
metadata:
  name: no-ttl-job
  namespace: cnsec-bad
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: hello
        image: busybox:latest
        command: ["sh", "-c", "echo no ttl; sleep 5"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dangerous-app-role
  namespace: cnsec-bad
rules:
- apiGroups: [""]
  resources: ["pods/exec", "pods/attach", "secrets"]
  verbs: ["get", "list", "watch", "create"]
- apiGroups: ["apps"]
  resources: ["deployments/scale"]
  verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dangerous-app-rolebinding
  namespace: cnsec-bad
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: dangerous-app-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: insecure-local
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
reclaimPolicy: Delete
allowVolumeExpansion: true
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: cnsec-hostpath-pv
spec:
  capacity: {storage: 1Gi}
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: insecure-local
  hostPath:
    path: /tmp/cnsec-hostpath-pv
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: db-data
  namespace: cnsec-bad
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: insecure-local
  resources:
    requests: {storage: 1Gi}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres-bad
  namespace: cnsec-bad
spec:
  serviceName: postgres-bad
  replicas: 1
  selector:
    matchLabels: {app: postgres-bad}
  template:
    metadata:
      labels: {app: postgres-bad}
    spec:
      containers:
      - name: postgres
        image: postgres:latest
        env:
        - name: POSTGRES_PASSWORD
          value: "plain-text-password"
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: db-data
```

建议同时创建一个最小 good manifest，用于验证 PASS 路径和报告对比：

```yaml
# /root/cnsec-lab/manifests/cnsec-good.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cnsec-good
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: rq
  namespace: cnsec-good
spec:
  hard:
    pods: "20"
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
---
apiVersion: v1
kind: LimitRange
metadata:
  name: defaults
  namespace: cnsec-good
spec:
  limits:
  - type: Container
    default: {cpu: "500m", memory: "512Mi"}
    defaultRequest: {cpu: "100m", memory: "128Mi"}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-good
  namespace: cnsec-good
spec:
  replicas: 2
  selector:
    matchLabels: {app: web-good}
  template:
    metadata:
      labels: {app: web-good}
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        runAsGroup: 101
        fsGroup: 101
        seccompProfile: {type: RuntimeDefault}
      volumes:
      - name: tmp
        emptyDir: {}
      containers:
      - name: web
        image: nginxinc/nginx-unprivileged:1.27-alpine
        ports:
        - containerPort: 8080
        resources:
          requests: {cpu: "100m", memory: "128Mi"}
          limits: {cpu: "500m", memory: "256Mi"}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web-good-pdb
  namespace: cnsec-good
spec:
  minAvailable: 1
  selector:
    matchLabels: {app: web-good}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-good-hpa
  namespace: cnsec-good
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-good
  minReplicas: 2
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: cnsec-good
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
```

部署方式：

```bash
source /root/cnsec-lab/lab.env
scp /root/cnsec-lab/manifests/cnsec-*.yaml agent@"$CP1_IP":/tmp/
ssh agent@"$CP1_IP" 'kubectl apply -f /tmp/cnsec-good.yaml; kubectl apply -f /tmp/cnsec-bad.yaml; kubectl get all -n cnsec-bad; kubectl get all -n cnsec-good'
```

### 14.11 etcd / control-plane 增强采集准备

kubeadm 自建集群的优势是 apiserver、etcd、scheduler、controller-manager 以 static pod manifest 形式存在于 control-plane 节点，可用于覆盖托管集群无法看到的检查点。

agent 需要确认以下路径可读，并把只读摘要给评估工具：

```bash
source /root/cnsec-lab/lab.env
ssh agent@"$CP1_IP" 'sudo ls -l /etc/kubernetes/manifests /etc/kubernetes/pki /var/lib/etcd'
ssh agent@"$CP1_IP" 'sudo sed -n "1,220p" /etc/kubernetes/manifests/kube-apiserver.yaml' > /root/cnsec-lab/artifacts/kube-apiserver.yaml
ssh agent@"$CP1_IP" 'sudo sed -n "1,220p" /etc/kubernetes/manifests/etcd.yaml' > /root/cnsec-lab/artifacts/etcd.yaml
```

为了演示“etcd 静态加密未启用”的 FAIL/UNKNOWN，默认 kubeadm 集群即可。为了演示 PASS，可以后续启用 encryption provider config，但这会改变 apiserver 配置，建议单独做快照后再执行。

```bash
# 仅供增强演示，不作为默认流程。
# 评估工具首先应能识别：未配置 --encryption-provider-config 时 Secret at rest 加密证据不足或未启用。
```

### 14.12 日志与运行时事件样例

Falco 在嵌套 VM 中可能因为 kernel headers/driver 兼容问题短暂失败，所以原型应同时支持真实 Falco 与离线 JSONL 事件导入。

```bash
cat >/root/cnsec-lab/logs/authlog_ssh_bruteforce.log <<'EOF'
Jun 17 10:01:01 k8s-worker-1 sshd[1001]: Failed password for invalid user admin from 10.20.0.99 port 55123 ssh2
Jun 17 10:01:03 k8s-worker-1 sshd[1002]: Failed password for root from 10.20.0.99 port 55124 ssh2
Jun 17 10:01:05 k8s-worker-1 sshd[1003]: Failed password for root from 10.20.0.99 port 55125 ssh2
Jun 17 10:01:08 k8s-worker-1 sshd[1004]: Accepted publickey for agent from 10.20.0.10 port 55126 ssh2
EOF

cat >/root/cnsec-lab/logs/falco_events.jsonl <<'EOF'
{"time":"2026-06-17T10:10:00Z","priority":"Warning","rule":"Terminal shell in container","output":"Shell spawned in container","k8s":{"ns":"cnsec-bad","pod":"web-bad-abc","container":"web"},"output_fields":{"proc.name":"sh","user.name":"root"}}
{"time":"2026-06-17T10:11:00Z","priority":"Error","rule":"Write below binary dir","output":"File below a known binary directory opened for writing","k8s":{"ns":"cnsec-bad","pod":"postgres-bad-0","container":"postgres"},"output_fields":{"fd.name":"/var/lib/postgresql/data/tmp.sh","proc.name":"sh"}}
EOF
```

评估工具导入映射：

| 日志源 | 目标检查点 | 解析规则 |
|---|---|---|
| `authlog_ssh_bruteforce.log` | 身份安全强化模块 | 同一来源 IP 短时间多次 Failed password -> SSH 暴破 WARN/FAIL。 |
| `falco_events.jsonl` | 数据持久化异常监控模块 | shell、敏感目录写入、PVC 路径异常写入 -> high finding。 |
| K8s Event / Audit log | 弹性扩缩容行为安全防护 | 非 CI/CD 主体 patch scale、replicas 突增、频繁扩缩。 |

### 14.13 给 agent 的端到端执行顺序

agent 应按以下顺序执行，不要跳步。每个阶段都要把 stdout/stderr 追加到 `/root/cnsec-lab/logs/bootstrap.log`。

```bash
set -euo pipefail
source /root/cnsec-lab/lab.env
exec > >(tee -a /root/cnsec-lab/logs/bootstrap.log) 2>&1

/root/cnsec-lab/scripts/00-pve-preflight.sh
/root/cnsec-lab/scripts/01-pve-network.sh
/root/cnsec-lab/scripts/02-create-ubuntu-template.sh
/root/cnsec-lab/scripts/03-create-k8s-vms.sh

# 等 cloud-init 完成，再装 K8s。
for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  ssh -o StrictHostKeyChecking=accept-new agent@"$ip" 'cloud-init status --wait || true'
done

for ip in "$CP1_IP" "$W1_IP" "$W2_IP"; do
  scp /root/cnsec-lab/scripts/10-k8s-node-common.sh agent@"$ip":/tmp/
  ssh agent@"$ip" "K8S_MINOR=$K8S_MINOR bash /tmp/10-k8s-node-common.sh"
done

/root/cnsec-lab/scripts/11-k8s-init-control-plane.sh
scp /root/cnsec-lab/scripts/12-k8s-install-addons.sh agent@"$CP1_IP":/tmp/
ssh agent@"$CP1_IP" 'bash /tmp/12-k8s-install-addons.sh'

# 可选 LXC helper
# /root/cnsec-lab/scripts/20-create-lxc-helpers.sh

# 部署 good/bad workloads
scp /root/cnsec-lab/manifests/cnsec-*.yaml agent@"$CP1_IP":/tmp/
ssh agent@"$CP1_IP" 'kubectl apply -f /tmp/cnsec-good.yaml && kubectl apply -f /tmp/cnsec-bad.yaml'

ssh agent@"$CP1_IP" 'kubectl get nodes -o wide; kubectl get pods -A -o wide; kubectl get hpa,pdb,quota,limitrange -A' \
  | tee /root/cnsec-lab/healthcheck.txt
```

### 14.14 运维常用命令与故障处理

| 场景 | 命令 | 说明 |
|---|---|---|
| 查看 VM | `qm list` | 检查 VM 状态。 |
| 查看 LXC | `pct list` | 检查辅助容器状态。 |
| 进入 LXC | `pct enter 201` | 无需 SSH，直接进入容器。 |
| VM 控制台 | `qm terminal 101` 或 Web Console | SSH 不通时排障。 |
| 查看 cloud-init | `ssh agent@10.20.0.11 'cloud-init status --long'` | 判断初始化是否完成。 |
| kubelet 排障 | `journalctl -u kubelet -xe --no-pager` | 节点 NotReady 常用。 |
| containerd 排障 | `crictl ps -a; crictl logs <id>` | Pod sandbox 或镜像拉取失败。 |
| CNI 排障 | `kubectl -n kube-system get pods -o wide` | calico/cilium 未 Ready 时先看这里。 |
| 组件状态 | `helm list -A; kubectl get crd | egrep 'kyverno|trivy|gatekeeper'` | 确认 CRD 可采集。 |
| 生成新 join | `kubeadm token create --print-join-command` | worker 重建后加入。 |
| 重置节点 | `kubeadm reset -f && rm -rf ~/.kube /etc/cni/net.d` | 仅靶场。 |
| 删除 VM | `qm stop 102 && qm destroy 102 --purge` | 彻底重建。 |
| 快照 VM | `qm snapshot 101 clean-k8s-base` | 在安装组件前后保存状态。 |
| 恢复快照 | `qm rollback 101 clean-k8s-base` | 快速回滚。 |

常见故障处理：

| 故障 | 可能原因 | 处理 |
|---|---|---|
| VM 无法启动或极慢 | 外层未开启 nested virtualization | 重新配置外层虚拟化；PVE 内看到 `vmx/svm` 后再继续。 |
| VM 不能访问互联网 | NAT 未生效或 DNS 错误 | 检查 `iptables -t nat -S`、`ip_forward`、`--nameserver`。 |
| `kubeadm init` 报 swap | swap 未关或 fstab 未注释 | 重新执行 node-common 脚本。 |
| 节点 NotReady | CNI 未安装或未 Ready | 查看 `calico-node`/`cilium` DaemonSet。 |
| metrics-server 无数据 | kubelet serving cert 不受信 | 靶场可加 `--kubelet-insecure-tls`，生产不建议。 |
| Falco Pod CrashLoop | nested VM kernel/driver 不兼容 | 使用离线 `falco_events.jsonl` 作为原型数据源；后续改用 Falco Operator/modern eBPF driver。 |
| Trivy 报告迟迟不出现 | 镜像扫描需要等待或拉取镜像失败 | `kubectl get vulnerabilityreports -A`，必要时先拉小镜像。 |
| Kyverno webhook 阻塞 | 策略 enforce 太严格 | demo 使用 Audit；需要 enforce 时只对 `cnsec-good` 测试。 |

### 14.15 PVE/K8s 靶场与检查点覆盖关系

| 标书检查点 | 靶场侧证据设计 | agent 需要准备的对象 |
|---|---|---|
| 微服务弹性能力评估 | HPA、PDB、resources、metrics-server。 | `web-good-hpa`、`web-good-pdb`、`web-bad-hpa`、bad workload 缺资源限制。 |
| 验证不可变部署原则 | latest 镜像、Service 暴露 22、RBAC 允许 exec、根文件系统可写。 | `web-bad`、`web-bad-ssh`、`dangerous-app-role`。 |
| 容器不可变安全管控 | readOnlyRootFilesystem、runAsNonRoot、allowPrivilegeEscalation、spec hash 漂移。 | good/bad Deployment，二次变更 bad manifest。 |
| 弹性扩缩容安全 | Namespace PSA label、Kyverno PSS policies、扩容后 Pod 继承策略。 | `cnsec-good` PSA labels、Kyverno policies。 |
| 弹性资源安全策略管控 | ResourceQuota、LimitRange、PriorityClass、DaemonSet 覆盖。 | good namespace 有 quota/limit，bad namespace 故意缺失。 |
| 弹性扩缩容行为安全防护 | HPA maxReplicas 过高、scale 子资源 RBAC 过宽、模拟 scale event。 | `web-bad-hpa maxReplicas=1000`、Role 允许 `deployments/scale`。 |
| 弹性资源生命周期安全治理 | Job 无 TTL、孤儿 PVC/PV、Completed Pod 残留。 | `no-ttl-job`、hostPath PV/PVC。 |
| 身份认证机制评估模块 | ServiceAccount token 自动挂载、匿名/认证组绑定、API TLS。 | `automountServiceAccountToken: true`、RoleBinding 到 `system:authenticated`。 |
| 动态访问控制评估模块 | RBAC 权限矩阵、危险 verbs/resources、准入策略 CRD。 | Role/RoleBinding、Kyverno/Gatekeeper CRD。 |
| 身份安全强化模块 | SSH 暴露、SSH 暴破日志、exec/shell 事件。 | `web-bad-ssh`、`authlog_ssh_bruteforce.log`、Falco shell event。 |
| etcd 访问控制与加密检测 | kubeadm static pod args、etcd TLS flags、encryption-provider-config 缺失。 | `/etc/kubernetes/manifests/*.yaml` 只读采集。 |
| 持久卷 PV 安全评估 | StorageClass 无加密参数、hostPath PV、reclaimPolicy/volumeBindingMode 风险。 | `insecure-local`、`cnsec-hostpath-pv`。 |
| 有状态应用数据安全 | StatefulSet + PVC + 明文密码 + 无 NetworkPolicy。 | `postgres-bad`。 |
| 镜像仓库数据安全 | HTTP registry mock、latest tag、imagePullSecret 使用情况。 | `registry-lab` 或 K8s registry Deployment；bad images。 |
| 数据持久化异常监控模块 | Falco 写入 PVC/敏感路径事件，离线 JSONL 兜底。 | `falco_events.jsonl`。 |

### 14.16 Agent 可直接使用的任务提示词

```text
你是靶场运维 agent。请 SSH 到 PVE host，按 /root/cnsec-lab/lab.env 中变量搭建一个嵌套虚拟化 Kubernetes 靶场。
要求：
1. 先运行 PVE preflight，确认 vmx/svm、KVM module、存储、网桥、NAT。
2. 如缺少 vmbr1，则创建 10.20.0.1/24 内网桥并通过 vmbr0 做 NAT。
3. 用 Ubuntu 24.04 cloud image 创建 template VM 9000。
4. 从模板克隆 k8s-cp-1、k8s-worker-1、k8s-worker-2 三台 VM，固定 IP。
5. 每台 VM 安装 containerd、kubeadm/kubelet/kubectl，禁用 swap，设置 br_netfilter 和 ip_forward。
6. 在 k8s-cp-1 上执行 kubeadm init，worker 执行 join。
7. 安装 Calico 或 Cilium、metrics-server、Kyverno、Trivy Operator、Falco；Falco 失败时保留离线 falco_events.jsonl。
8. 部署 cnsec-good 与 cnsec-bad manifest，确保 HPA/PDB/RBAC/PV/StatefulSet/SSH/Falco 日志等证据齐全。
9. 导出 /root/cnsec-lab/kubeconfig、inventory.json、preflight.txt、healthcheck.txt。
10. 所有命令必须幂等或在发现资源已存在时跳过；不得修改 PVE 生产网桥；不得把 Secret data 写入日志。
```

### 14.17 与评估系统的连接方式

靶场完成后，评估系统注册目标时使用：

```json
{
  "name": "pve-nested-k8s-lab",
  "type": "kubernetes",
  "connection_mode": "kubeconfig",
  "labels": {
    "env": "lab",
    "provider": "pve-nested",
    "cluster": "kubeadm",
    "purpose": "tender-demo"
  },
  "options": {
    "kubeconfig_path": "/secure/imported/kubeconfig",
    "control_plane_artifacts": [
      "kube-apiserver.yaml",
      "etcd.yaml"
    ],
    "log_sources": [
      "authlog_ssh_bruteforce.log",
      "falco_events.jsonl"
    ],
    "namespaces_in_scope": ["cnsec-good", "cnsec-bad", "kube-system", "kyverno", "trivy-system", "falco"]
  }
}
```

后端 `CloudNativeAdapter` 应额外识别以下 lab 标签，方便报告说明：

```python
if target.labels.get("provider") == "pve-nested":
    evidence_context["lab_notes"] = "This is a nested PVE kubeadm lab. Control-plane static pod manifests are available for enhanced etcd/apiserver checks."
```

### 14.18 靶场清理与重建

```bash
# 删除 K8s VM
for id in 101 102 103 104; do
  qm stop "$id" || true
  qm destroy "$id" --purge || true
done

# 删除辅助 LXC
for id in 201 202 203; do
  pct stop "$id" || true
  pct destroy "$id" --purge || true
done

# 保留模板 9000 可以加速下次重建；如需完全清理：
# qm destroy 9000 --purge
```

重建建议：

1. 模板 VM 9000 保留。
2. 每次演示前从模板克隆新 VM。
3. 安装 K8s 完成后为三台节点做 `clean-k8s-base` 快照。
4. 安装安全组件后做 `with-security-addons` 快照。
5. 部署 bad workloads 前做 `before-bad-workloads` 快照。
6. 演示结束回滚或销毁，避免危险 RBAC 和 HTTP registry 长期存在。

## 15. 里程碑式研发计划

> 不按自然时间估算，以“能独立交付、能演示、能验收”的阶段划分。

### M0：工程骨架与数据合同

**目标**：让后续 vibe coding 有稳定边界，先把接口、模型、目录、数据库跑起来。

**任务**

1. 创建 monorepo。
2. FastAPI 项目初始化，配置 SQLite。
3. 定义 Pydantic 模型、数据库表、Alembic/简单迁移。
4. 写入附件中的全部 checkpoint seed 数据。
5. 实现 `/api/checkpoints`、`/api/targets` 基础接口。
6. 前端初始化，能读取 checkpoint 列表。

**建议目录**

```text
cloud-native-security-prototype/
  apps/
    api/
      app/
        main.py
        models/
        db/
        adapters/
        collectors/
        rules/
        services/
        routers/
        seed/
    web/
      src/
        pages/
        components/
        api/
        types/
  packages/
    schemas/
  deploy/
    docker-compose.yml
    k8s/
  fixtures/
    k8s-good/
    k8s-bad/
    logs/
  docs/
```

**给编码助手的任务提示词**

```text
请在 apps/api 创建 FastAPI 项目，使用 SQLModel 或 SQLAlchemy，定义 Target、AssessmentTask、
RawSnapshot、Asset、Checkpoint、Finding、MetricWeight、Report 表。提供 /api/checkpoints 和
/api/targets CRUD。初始化时从 seed/checkpoints.yaml 导入检查点。要求返回类型有 Pydantic schema，
并编写最小 pytest。
```

**验收标准**

- `docker compose up` 后 API 可启动。
- `/api/checkpoints` 返回标书全部检查点。
- 前端能展示检查点列表。

---

### M1：云原生采集器与 Manifest 模式

**目标**：无论有没有真实集群，都能采集/导入 Kubernetes 资源并标准化入库。

**任务**

1. 实现 Manifest bundle 上传解析：支持单 YAML、多文档 YAML、tar/zip。
2. 实现 Kubernetes API collector：按资源类型 list，失败不终止全任务。
3. 实现 CRD 动态发现：Istio/Kyverno/Gatekeeper/Trivy/Falco 存在则采集，不存在则跳过。
4. 将采集结果保存到 `raw_snapshots`。
5. 将对象抽象为 `assets`。
6. 增加采集质量指标：采集成功资源数、失败资源数、不可见资源数。

**给编码助手的任务提示词**

```text
请实现 CloudNativeCollector，支持两种输入：manifest_bundle 和 kubeconfig。collector 返回 RawSnapshot 列表。
Kubernetes API 采集要容忍某些 API group 不存在或无权限，记录 warning，不抛出致命错误。
同时实现 raw snapshot 到 Asset 的转换，资产 ID 使用 kind/namespace/name/hash。
```

**验收标准**

- 上传 `fixtures/k8s-bad` 能生成 assets。
- 接入 kind 集群能采集 Pod/Deployment/RBAC/HPA/PDB/StorageClass。
- 缺少 Istio/Kyverno 等 CRD 时任务仍成功。

---

### M2：规则引擎与第一批核心规则

**目标**：让系统能真正评估并产生 findings。

**任务**

1. 实现 rule registry 加载：YAML -> RuleDefinition。
2. 实现规则执行器：按 resource_kinds 筛选资源，调用 Python handler。
3. 实现 Finding 生成、fingerprint 去重、严重度归一。
4. 先实现覆盖面最高的规则：
   - `readOnlyRootFilesystem`
   - `runAsNonRoot`
   - `allowPrivilegeEscalation`
   - image tag/digest
   - HPA/PDB/resources
   - NetworkPolicy default deny
   - RBAC dangerous verbs
   - ServiceAccount token automount
   - StorageClass encryption/reclaimPolicy/volumeBindingMode
5. 实现评分聚合。

**给编码助手的任务提示词**

```text
请实现一个规则引擎：从 rules/*.yaml 加载 RuleDefinition，按 resource_kinds 将 Asset/RawSnapshot 传给
handler。handler 返回 RuleResult，再转换成 Finding。实现以下 handler：
check_readonly_rootfs、check_run_as_non_root、check_hpa_pdb_resources、
check_rbac_dangerous_permissions、check_serviceaccount_automount、check_storageclass_security。
每个 handler 必须返回 evidence.json_path、observed、expected、remediation。
```

**验收标准**

- `fixtures/k8s-bad` 至少产生 20 条 findings。
- 每条 finding 有 checkpoint_id、rule_id、severity、evidence、remediation。
- 重复运行同一任务不会产生重复 findings。

---

### M3：云原生三大能力域深度覆盖

**目标**：补齐标书前半部分 15 个云原生检查点。

**任务**

1. 不可变与弹性：
   - spec hash 漂移检测。
   - Job TTL / orphan resource 清理检查。
   - HPA 异常扩缩容行为检测。
   - AdmissionPolicy/Kyverno/Gatekeeper 策略覆盖检查。
2. 动态访问控制与身份：
   - 权限矩阵。
   - `system:anonymous` / `system:unauthenticated` 风险。
   - `pods/exec`、`secrets`、`bind/escalate/impersonate` 提权路径。
   - OIDC / token projection / mTLS 证据。
   - SSH 暴破日志导入和 demo 事件。
3. 持久化安全：
   - etcd TLS / encryption provider 可选深度检查。
   - StatefulSet 数据安全检查。
   - 镜像仓库 adapter mock + 镜像引用分析。
   - Falco/event 异常持久化告警导入。

**给编码助手的任务提示词**

```text
请补齐 CloudNativeAdapter 的 15 个 checkpoint。每个 checkpoint 至少有 2 条规则；无法通过默认 K8s API
获得的证据必须返回 UNKNOWN 并说明需要启用 control-plane collector 或日志源。实现权限矩阵 API：
/api/assessments/{task_id}/rbac-matrix，支持按 subject、resource、verb 过滤。
```

**验收标准**

- 云原生 15 个检查点在 UI 中全部显示 PASS/WARN/FAIL/UNKNOWN。
- 每个检查点至少有一条可解释证据。
- 权限矩阵可查询主体对 Pod/Service/ConfigMap/Secret/Ingress/Namespace 的权限。
- 样例 Falco/auth.log 能生成 SSH/异常写入告警。

---

### M4：统一集成、数据加工与质量评估

**目标**：覆盖“工具集成数据处理”全部检查点，形成三工具统一链路。

**任务**

1. 实现 `CloudApiSecurityAdapterStub` 和 `SmartCloudSecurityAdapterStub`。
2. 实现 adapter registry 和 healthcheck。
3. 统一 `AssessmentRequest` 参数。
4. Orchestrator 调用三类 adapter。
5. Normalization pipeline：格式转换、清洗、去重、脱敏。
6. 数据质量报告：completeness、freshness、duplicate_rate、unknown_rate。
7. 汇总聚合：整体分、工具分、域分、检查点分。

**给编码助手的任务提示词**

```text
请实现 AdapterRegistry 和 AssessmentOrchestrator。orchestrator 根据 profile=all_tools_demo 调用
CloudNativeAdapter、CloudApiSecurityAdapterStub、SmartCloudSecurityAdapterStub。三个 adapter 的结果必须统一
写入 findings 表。实现 data_quality_summary(task_id) 和 aggregate_summary(task_id)。
```

**验收标准**

- 单个任务包含三类工具结果。
- API/智算云 stub 的 findings 能参与总览和报告。
- 数据质量报告可展示并影响“证据不足”提示。

---

### M5：可视化和交互查询

**目标**：覆盖“集成可视化展示”全部检查点。

**任务**

1. 首页态势总览。
2. 云原生工具详情页。
3. API/智算云 stub 详情页。
4. 指标管理和赋权页。
5. Findings 列表筛选和详情弹窗。
6. 图表点击 drill-down。
7. 报告预览和 Markdown/HTML 导出。

**给编码助手的任务提示词**

```text
请在前端实现 AssessmentOverview 页面：展示 overall_score、severity 分布、工具分数、云原生三域雷达图、
Top 风险资产。实现 CloudNativeDetail 页面：左侧三大域树，右侧 checkpoint/finding 表，点击 finding
展示 evidence 和 remediation。所有页面使用同一个 findings filter store。
```

**验收标准**

- 总览、云原生详情、API stub、智算云 stub、指标管理、报告页都可访问。
- 过滤条件能联动图表和表格。
- 点击任一风险能看到证据、原始字段和整改建议。
- 调整指标权重后重新计算分数。

---

### M6：演示数据、测试与交付包装

**目标**：让原型系统稳定可演示、可复现、可继续扩展。

**任务**

1. 准备 `fixtures/k8s-good` 和 `fixtures/k8s-bad`。
2. 准备 `fixtures/logs/authlog_ssh_bruteforce.log`、`falco_events.jsonl`。
3. 准备 demo kind 集群脚本。
4. 单元测试：规则 handler。
5. 集成测试：一次完整 assessment。
6. E2E 测试：上传 manifest -> 运行评估 -> 查看报告。
7. Docker Compose 一键启动。
8. 准备 `deploy/pve-lab/` 靶场自动化脚本、`lab.env.example`、good/bad manifest。
9. 在 PVE nested host 上实际跑通一次：创建 VM -> kubeadm -> 安装安全组件 -> 部署 bad workloads -> 导出 kubeconfig。
10. README：部署、运行、PVE/K8s 靶场搭建、演示流程、限制说明。

**给编码助手的任务提示词**

```text
请创建 fixtures/k8s-bad，包含以下问题：无 HPA/PDB、容器 root 运行、readOnlyRootFilesystem 缺失、
使用 latest 镜像、Role 允许 pods/exec、ClusterRoleBinding 绑定 system:authenticated 到高权限、
StorageClass 未配置加密、Service 暴露 22 端口、StatefulSet 明文 DB_PASSWORD。为每个问题写 pytest
断言，确保扫描结果包含对应 rule_id。
```

**验收标准**

- 新环境按 README 可复现完整演示。
- PVE nested 靶场按 `deploy/pve-lab/README.md` 可复现创建 K8s 目标集群。
- 测试覆盖每个云原生检查点至少一个 FAIL 场景。
- 报告导出包含所有检查点覆盖矩阵和整改建议。

---

## 16. 规则实现细节建议

### 16.1 RBAC 权限矩阵算法

输入：Role/ClusterRole、RoleBinding/ClusterRoleBinding、ServiceAccount/User/Group。  
输出：`subject -> namespace -> resource -> verbs -> risk_tags`。

核心逻辑：

1. 展开 RoleBinding 到 namespace scope。
2. 展开 ClusterRoleBinding 到 cluster scope。
3. 处理 ClusterRole aggregation labels。
4. 对每条 rule 识别危险组合：
   - `resources=["*"]` 或 `verbs=["*"]`
   - `resources=["secrets"]` 且包含 `get/list/watch`
   - `resources=["pods/exec","pods/attach","pods/portforward"]`
   - `verbs=["bind","escalate","impersonate"]`
   - 绑定主体包含 `system:anonymous`、`system:unauthenticated`、`system:authenticated`
5. 根据资源类型映射到标书关注对象：Pod、Service、ConfigMap、Secret、Ingress、Namespace、容器编排资源。
6. 生成 finding 和权限矩阵 UI 数据。

### 16.2 Workload 安全上下文检查

规则要支持所有 workload template：

```text
Pod: spec.containers
Deployment: spec.template.spec.containers
StatefulSet: spec.template.spec.containers
DaemonSet: spec.template.spec.containers
Job: spec.template.spec.containers
CronJob: spec.jobTemplate.spec.template.spec.containers
```

检查字段：

- `securityContext.runAsNonRoot == true`
- `securityContext.allowPrivilegeEscalation == false`
- `securityContext.readOnlyRootFilesystem == true`
- `securityContext.privileged != true`
- `securityContext.capabilities.drop` 包含 `ALL`
- `seccompProfile.type` 为 `RuntimeDefault` 或 `Localhost`
- image 不使用 `latest`，优先固定 digest。
- 不挂载 Docker socket、宿主机敏感路径。
- `automountServiceAccountToken` 按需关闭。

### 16.3 弹性与恶意扩容检测

检查内容：

- HPA 是否存在。
- HPA `maxReplicas` 是否设置合理上限。
- Workload 是否有 CPU/Memory requests，否则 HPA 和配额治理依据不足。
- ResourceQuota 是否限制 pods、requests.cpu、requests.memory、limits.cpu、limits.memory。
- LimitRange 是否设置默认 request/limit。
- RBAC 中谁可以 `update/patch` `deployments/scale`、`statefulsets/scale`。
- Event/Audit log 中是否出现短时间异常扩容：
  - 同一 workload 在窗口内 scale 次数超过阈值。
  - 非 CI/CD 或 autoscaler 主体触发 scale。
  - replicas 突增超过 baseline 倍数。

### 16.4 持久化安全检测

检查内容：

- StorageClass:
  - `parameters.encrypted` / 云厂商加密参数 / KMS key。
  - `reclaimPolicy` 是否符合数据保留要求。
  - `volumeBindingMode` 建议拓扑受限存储使用 `WaitForFirstConsumer`。
  - `allowVolumeExpansion` 是否符合治理策略。
- PV/PVC:
  - `hostPath`、local PV 风险。
  - RWX 卷是否有网络隔离和访问审计。
  - PVC 是否长期 Pending/Released。
  - 孤儿 PV/PVC。
- StatefulSet:
  - 数据库口令是否通过 Secret 引用。
  - 是否有 NetworkPolicy 限制访问。
  - 是否有 TLS Secret 或 mTLS。
  - 是否有备份/快照策略。
- etcd:
  - etcd client/peer TLS。
  - kube-apiserver 到 etcd 的证书参数。
  - encryption-provider-config 是否启用 secrets 等资源加密。
  - encryption providers 中 `identity` 不应作为第一优先 provider。

### 16.5 异常监控事件模型

```json
{
  "event_id": "falco-001",
  "source": "falco",
  "time": "2026-06-17T10:00:00Z",
  "rule": "Write below binary dir",
  "priority": "Warning",
  "k8s": {
    "namespace": "demo",
    "pod": "db-0",
    "container": "postgres"
  },
  "fields": {
    "proc.name": "sh",
    "fd.name": "/var/lib/postgresql/data/tmp.sh"
  }
}
```

转换为 Finding：

- checkpoint_id: `CN-39`
- rule_id: `CN-PER-004-runtime-abnormal-write`
- severity: high
- asset: Pod/PVC
- evidence: Falco 事件内容
- remediation: 审查容器进程、限制 shell、设置只读根文件系统、检查 PVC 挂载权限。

---

## 17. 报告结构

报告建议以 Markdown/HTML 输出，投标演示时可转 PDF。

```text
1. 评估摘要
   - 目标、时间、工具、数据质量
   - 总体分、结论、严重风险统计

2. 标书检查点覆盖情况
   - 云原生三大域覆盖矩阵
   - 工具集成数据处理覆盖矩阵
   - 集成可视化展示覆盖矩阵

3. 云原生安全评估结果
   - 不可变基础设施与弹性安全评估
   - 动态访问控制与身份安全评估
   - 容器持久化安全评估

4. 重点风险清单
   - Critical/High findings
   - 受影响资产
   - 证据
   - 整改建议

5. 指标赋权与符合度判定
   - 权重表
   - 分数计算说明
   - PASS/WARN/FAIL/UNKNOWN

6. 数据质量与限制
   - 不可见资源
   - UNKNOWN 原因
   - 托管集群限制

7. 附录
   - 规则 ID 列表
   - 原始采集资源摘要
   - 参考基线
```

---

## 18. 原型演示脚本

### 18.1 演示主线

1. 进入系统首页，展示“暂无评估任务”。
2. 导入 `fixtures/k8s-bad` 或连接 kind 集群。
3. 创建评估任务，profile 选择 `all_tools_demo`。
4. 展示任务进度：采集 -> 云原生规则 -> API stub -> 智算云 stub -> 数据清洗 -> 打分 -> 报告。
5. 进入总览页：
   - 展示总分、三工具分数、风险分布。
   - 强调云原生工具为当前完整实现。
6. 点击云原生详情：
   - 展开“不可变基础设施与弹性安全评估”：查看 `readOnlyRootFilesystem`、HPA/PDB、扩容权限风险。
   - 展开“动态访问控制与身份安全评估”：查看 RBAC 权限矩阵和匿名/exec/secrets 风险。
   - 展开“容器持久化安全评估”：查看 StorageClass、PVC、StatefulSet、etcd UNKNOWN/FAIL。
7. 进入指标赋权页，将“动态访问控制”权重调高，返回总览展示分数重算。
8. 进入报告页导出 Markdown/HTML。

### 18.2 Demo bad manifest 建议包含的问题

| 问题 | 对应检查点 |
|---|---|
| Deployment 无 HPA/PDB | 微服务弹性能力评估 |
| 容器使用 `nginx:latest` | 验证不可变部署原则 |
| `readOnlyRootFilesystem` 缺失 | 容器不可变安全管控 |
| Namespace 无 PSA label | 弹性扩缩容安全 |
| 无 ResourceQuota/LimitRange | 弹性资源安全策略管控 |
| HPA maxReplicas=1000 | 弹性扩缩容行为安全防护 |
| Job 无 TTL | 弹性资源生命周期安全治理 |
| ClusterRoleBinding 给 `system:authenticated` 高权限 | 身份认证机制/动态访问控制 |
| Role 允许 `pods/exec` 和 `secrets list` | 动态访问控制 |
| Service 暴露 22 端口 | 身份安全强化 |
| 无 encryption config 证据 | etcd 访问控制与加密检测 |
| StorageClass 未配置加密 | 持久卷 PV 安全评估 |
| StatefulSet 明文 `DB_PASSWORD` | 有状态应用数据安全 |
| 镜像仓库使用 http registry | 镜像仓库数据安全 |
| Falco 样例事件：异常写 PVC | 数据持久化异常监控 |

---

## 19. 风险、限制与处理方式

| 风险/限制 | 处理方式 |
|---|---|
| 托管 Kubernetes 隐藏 apiserver/etcd 配置 | 输出 UNKNOWN，要求用户补充云厂商配置截图/API 证据，或运行增强采集器。 |
| 读取 Secret 内容有泄露风险 | 默认不读取 Secret data；只检查元数据、引用关系、Trivy 报告和明文 env。 |
| Falco/audit/auth.log 不一定可用 | 设计为可选数据源；无数据时不阻塞主评估。 |
| Registry API 凭据可能缺失 | 先做镜像引用、pull secret、HTTP/HTTPS、tag/digest 静态分析；Harbor 适配后增强。 |
| 主动弹性测试可能影响生产 | 默认关闭；只允许 demo namespace 且显式 `destructive_tests=false/true`。 |
| API/智算云工具暂未完整实现 | 明确标注 stub，保证集成、展示、汇总链路可用，后续替换 adapter。 |

---

## 20. Definition of Done

### 原型级完成标准

- [ ] 附件中所有检查点均已入库，并有 UI 展示。
- [ ] 云原生 15 个检查点均有规则、证据、状态和整改建议。
- [ ] 工具集成数据处理所有检查点有后端能力支撑。
- [ ] 集成可视化展示所有检查点有页面或交互功能。
- [ ] 云上 API / 智算云以 stub 方式接入，能参与任务、汇总、展示。
- [ ] Manifest 模式和 Kubernetes API 模式至少一种可完整跑通。
- [ ] PVE nested + kubeadm 靶场能按脚本创建，agent 可通过 SSH 完成 VM/LXC/K8s/安全组件安装。
- [ ] `cnsec-good` / `cnsec-bad` 靶场对象能稳定产生覆盖所有云原生检查点的风险。
- [ ] 报告导出包含评分、发现、证据、整改、数据质量和限制说明。
- [ ] 单元测试覆盖核心规则；集成测试覆盖完整 assessment。
- [ ] README 说明安装、运行、演示和限制。

### 投标演示级完成标准

- [ ] 一键启动系统。
- [ ] 一键导入演示目标。
- [ ] 可选择导入离线 manifest，或连接 PVE nested K8s 靶场 kubeconfig。
- [ ] 评估过程有进度可视化。
- [ ] 重点页能清楚展示“云原生安全评估工具”为完整实现。
- [ ] API/智算云工具不显得缺失，而是体现“可插拔、已适配、待接入真实能力”。
- [ ] 每个标书检查点能在页面或报告中被定位。

---

## 21. 参考资料 URL

- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes Security Context: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- Kubernetes RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- Kubernetes RBAC Good Practices: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes Authentication / OIDC / ServiceAccount: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- Kubernetes ServiceAccount for Pods: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- Kubernetes NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Kubernetes HPA: https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/
- Kubernetes ResourceQuota: https://kubernetes.io/docs/concepts/policy/resource-quotas/
- Kubernetes PDB: https://kubernetes.io/docs/tasks/run-application/configure-pdb/
- Kubernetes Encryption at Rest: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
- Kubernetes StorageClass: https://kubernetes.io/docs/concepts/storage/storage-classes/
- Kubernetes Persistent Volumes: https://kubernetes.io/docs/concepts/storage/persistent-volumes/
- Kubernetes ValidatingAdmissionPolicy: https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
- Istio PeerAuthentication: https://istio.io/latest/docs/reference/config/security/peer_authentication/
- Istio mTLS Authentication Policy: https://istio.io/latest/docs/tasks/security/authentication/authn-policy/
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- kube-bench: https://github.com/aquasecurity/kube-bench
- Trivy Operator: https://github.com/aquasecurity/trivy-operator
- Kyverno Validate Rules: https://kyverno.io/docs/policy-types/cluster-policy/validate/
- OPA Gatekeeper: https://open-policy-agent.github.io/gatekeeper/website/docs/
- Falco: https://falco.org/docs/
- OWASP Kubernetes Top 10: https://owasp.org/www-project-kubernetes-top-ten/
- NIST SP 800-190: https://csrc.nist.gov/pubs/sp/800/190/final

- Proxmox VE Administration Guide: https://pve.proxmox.com/pve-docs/pve-admin-guide.html
- Proxmox VE Nested Virtualization: https://pve.proxmox.com/wiki/Nested_Virtualization
- Proxmox VE Cloud-Init Support: https://pve.proxmox.com/wiki/Cloud-Init_Support
- Proxmox VE Network Configuration: https://pve.proxmox.com/wiki/Network_Configuration
- Proxmox VE API / pvesh: https://pve.proxmox.com/wiki/Proxmox_VE_API
- Proxmox VE qm manual: https://pve.proxmox.com/pve-docs/qm.1.html
- Proxmox VE pct / LXC manual: https://pve.proxmox.com/pve-docs/pct.1.html
- Kubernetes kubeadm install: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
- Kubernetes kubeadm create cluster: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
- Kubernetes Container Runtimes: https://kubernetes.io/docs/setup/production-environment/container-runtimes/
- Calico on-premises install: https://docs.tigera.io/calico/latest/getting-started/kubernetes/self-managed-onprem/onpremises
- Cilium Quick Installation: https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/
- Kubernetes Metrics Server: https://github.com/kubernetes-sigs/metrics-server
- Kyverno Installation: https://kyverno.io/docs/installation/installation/
- Falco Kubernetes Helm deployment: https://falco.org/docs/setup/kubernetes/

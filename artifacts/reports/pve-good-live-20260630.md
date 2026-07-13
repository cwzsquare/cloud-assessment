# 云原生安全评估报告

## 1. 评估摘要

- Task ID: `pve-good-live-20260630`
- Generated At: `2026-06-30T07:27:33.738366+00:00`
- Tools: `cloud_api_stub, cloud_native, registry_stub, smart_cloud_stub, platform`
- Overall Score: `91.57`
- Conclusion: **不符合，存在多个 high 风险失败项**
- Evidence Coverage: `82.69%`
- Severity Count: `high=9, info=62, medium=14`

### 工具聚合摘要

| Tool | Status | Schema | Findings | Fail/Warn/Unknown | Warnings | Raw Keys |
|---|---|---|---:|---|---:|---|
| cloud_api_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| cloud_native | ready | kubernetes-json/v1 | 50 | 2/3/32 | 53 | collected_at, kind_count, kinds, mode, object_count, rbac_matrix, resource_inventory, schema_version |
| registry_stub | stub (stub/mock) | stub/v1 | 1 | 0/0/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| smart_cloud_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| platform | ready | internal/v1 | 26 | 1/1/0 | 0 | integration_findings, visualization_findings |

## 2. 标书检查点覆盖情况

### 云原生三大域

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | UNKNOWN | 0.0 | 2 | 0/0/1 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 1 | 0/0/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 0.0 | 2 | 1/0/1 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 25.0 | 4 | 1/1/2 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 3 | 0/0/2 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 4 | 0/0/2 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | PASS | 87.5 | 6 | 0/1/2 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 5 | 0/0/4 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | UNKNOWN | 0.0 | 4 | 0/0/4 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | PASS | 87.5 | 9 | 0/1/5 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 6 | 0/0/5 |
### 工具集成数据处理

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | FAIL | 75.0 | 6 | 1/1/0 |
| INT-6 数据格式优化 | 工具集成数据处理 | 0.7 | PASS | 100.0 | 1 | 0/0/0 |
| INT-7 工具集成框架构建 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 2 | 0/0/0 |
| INT-8 云上 API 安全评估工具接入适配 | 工具集成数据处理 | 0.8 | PASS | 87.5 | 4 | 0/1/0 |
| INT-9 云原生安全评估工具接入适配 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-10 智算云安全评估工具接入适配 | 工具集成数据处理 | 0.8 | PASS | 87.5 | 4 | 0/1/0 |
| INT-11 调用参数标准化 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-12 调用流程协调 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-13 输出格式归一化 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-14 结果汇总整合 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
### 集成可视化展示

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| VIZ-16 多工具安全态势总览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-17 API 工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-18 云原生工具结果详览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-19 智算云工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-20 数据筛选交互 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-21 结果交互查询 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |

## 3. 云原生安全评估结果

### 不可变基础设施与弹性安全评估

- Domain Score: `56.25`
- Scored Checkpoints: `4`
- Unknown Checkpoints: `3`

- **FAIL high** `CN-24` `CN-ELAS-002-admission-policy-present` 准入策略覆盖检查 (_cluster)
  - Evidence: 检查 Kyverno/Gatekeeper/VAP 是否存在并完整覆盖核心 Pod 安全约束
  - Remediation: 安装并启用 Pod 安全准入策略，至少覆盖 runAsNonRoot、禁止提权、禁用特权容器、drop ALL capabilities、seccompProfile。
- **FAIL high** `CN-25` `CN-ELAS-003-admission-governance` 新 Pod/节点准入治理检查 (_cluster)
  - Evidence: 准入策略应覆盖 Pod/Node 等新资源的创建或更新，证明新增对象会自动套用治理策略
  - Remediation: 为 Pod/Node 配置 ValidatingAdmissionPolicy、Kyverno 或等效准入策略，确保新对象自动继承安全与资源治理。
- **WARN medium** `CN-25` `CN-ELAS-003-priorityclass` PriorityClass 优先级治理检查 (_cluster)
  - Evidence: PriorityClass 应定义业务优先级并被业务 workload 引用，防止资源争抢时无序驱逐
  - Remediation: 定义系统、业务和批处理等 PriorityClass，并在关键 workload 中引用非 system-* 优先级类。
- **UNKNOWN medium** `CN-25` `CN-ELAS-003-daemonset-governance` 节点 DaemonSet 自动纳管检查 (_cluster)
  - Evidence: 至少一个节点级 DaemonSet 应证明新节点加入后会自动被安全/网络/观测组件纳管
  - Remediation: 部署并验证 CNI、Falco、日志采集等 DaemonSet 覆盖全部节点，确保新节点加入后自动纳管。
- **UNKNOWN medium** `CN-6` `CN-ELAS-001-metrics-api` metrics-server / metrics API 可用性检查 (_cluster)
  - Evidence: HPA 依赖 metrics-server 或 metrics.k8s.io API 提供运行态指标
  - Remediation: 安装并验证 metrics-server，确保 v1beta1.metrics.k8s.io APIService Available，且 kubectl top 或 HPA currentMetrics 能返回实时指标。
- **UNKNOWN info** `CN-23` `CN-IMM-002-no-evidence` 容器不可变安全管控 证据覆盖检查 (_cluster)
  - Evidence: 规则未生成证据
  - Remediation: 补充采集源或规则实现。
- **UNKNOWN info** `CN-24` `CN-ELAS-002-workload-policy-inheritance` 扩缩容工作负载策略继承检查 (_cluster)
  - Evidence: 新 Pod 由 HPA/Deployment/StatefulSet 扩容创建时应继承 namespace PSA 或准入策略
  - Remediation: 为业务工作负载 namespace 启用 PSA restricted/baseline 或等价 Kyverno/Gatekeeper/VAP 策略，确保扩容后新 Pod 自动继承约束。
- **UNKNOWN info** `CN-25` `CN-ELAS-003-daemonset-coverage` DaemonSet 节点覆盖检查 (_cluster)
  - Evidence: 用于节点纳管的 DaemonSet 数量
  - Remediation: 部署 CNI/Falco/日志采集等 DaemonSet 纳管节点。
- **UNKNOWN info** `CN-26` `CN-ELAS-004-abnormal-scale-events` 异常扩缩容事件检查 (_cluster)
  - Evidence: Event/AuditLog 中的异常 scale 行为
  - Remediation: 启用审计日志并告警：非 CI/CD/HPA 主体修改 scale、短时间频繁扩缩、目标副本数异常增大。
- **UNKNOWN info** `CN-26` `CN-ELAS-004-scale-event-source` 扩缩容事件/审计源覆盖检查 (_cluster)
  - Evidence: 识别到的 scale 事件数量
  - Remediation: 接入 Kubernetes Event 或 apiserver audit log，用于识别异常扩缩容。
### 动态访问控制与身份安全评估

- Domain Score: `95.83`
- Scored Checkpoints: `3`
- Unknown Checkpoints: `0`

- **WARN medium** `CN-29` `CN-IAM-002-context-policy` 动态上下文准入策略检查 (_cluster)
  - Evidence: 准入策略应包含 namespace/label/env/subject 等动态上下文条件
  - Remediation: 增加基于 namespace、label、env/tenant、userInfo/subject 的准入控制策略。
- **UNKNOWN medium** `CN-28` `CN-IAM-001-apiserver-tls` API Server TLS 证据检查 (_cluster)
  - Evidence: kube-apiserver 应提供 TLS 证书、私钥和 secure-port 证据，且不应启用 insecure 监听
  - Remediation: 确保 kube-apiserver 使用 TLS 证书/私钥并仅暴露 secure-port；禁用任何 insecure 监听。
- **UNKNOWN medium** `CN-28` `CN-IAM-001-external-auth-evidence` OIDC/外部认证证据检查 (_cluster)
  - Evidence: kube-apiserver 应提供 OIDC、webhook、front-proxy 或明确的本地认证依据
  - Remediation: 如需企业统一身份，配置 OIDC/webhook/front-proxy；否则至少保留 apiserver client CA 与 service-account issuer 等本地认证依据。
- **UNKNOWN medium** `CN-29` `CN-IAM-002-permission-matrix-coverage` 主体-资源-动作权限矩阵覆盖检查 (_cluster)
  - Evidence: RBAC 矩阵应覆盖 Pod/Service/ConfigMap/Secret/Ingress/Namespace 并支持按主体/资源查询
  - Remediation: 补充 Role/ClusterRole/Binding 采集权限，确保权限矩阵覆盖 Pod、Service、ConfigMap、Secret、Ingress、Namespace 等标书关注对象。
- **UNKNOWN medium** `CN-29` `CN-IAM-002-permission-queryability` 主体/资源权限查询能力检查 (_cluster)
  - Evidence: 权限矩阵应支持按 subject/resource/verb/binding/role/scope 维度查询，便于定位过度授权和提权路径
  - Remediation: 保留 RBAC rows 明细，并在报告/UI 中支持按主体、资源和动作用例检索权限。
- **UNKNOWN medium** `CN-30` `CN-IAM-003-abnormal-login` 异常登录行为检查 (_cluster)
  - Evidence: 应识别 root 登录、口令登录成功、来自公网/未知来源的 SSH 成功登录等异常身份事件
  - Remediation: 禁止 root 和口令 SSH 登录；对公网来源、成功登录和暴破行为建立告警与处置流程。
- **UNKNOWN medium** `CN-30` `CN-IAM-003-container-exec-audit` 容器 exec 审计检查 (_cluster)
  - Evidence: 应能从 audit log 识别容器 exec 行为，并区分业务主体与系统控制器
  - Remediation: 开启并保留 apiserver audit log；对业务主体的 pod exec 建立审批、告警和过期访问控制。
- **UNKNOWN medium** `CN-30` `CN-IAM-003-identity-incident-ledger` 身份安全持续审计事件台账 (_cluster)
  - Evidence: 归一化 auth.log、apiserver audit 与 Falco 身份事件，形成连续身份安全台账
  - Remediation: 持续接入 auth.log、apiserver audit log 或等效身份审计源，保留用户、来源 IP、目标 Pod/节点和时间等关键信息。
- **UNKNOWN info** `CN-30` `CN-IAM-003-falco-or-authlog` 身份安全审计日志源检查 (_cluster)
  - Evidence: Falco/auth/audit 事件或 Falco 工作负载
  - Remediation: 接入 Falco webhook、auth.log 或 audit log 作为持续审计数据源。
- **PASS info** `CN-28` `CN-IAM-001-anonymous-binding` 匿名主体绑定检查 (_cluster)
  - Evidence: 匿名/未认证主体绑定
  - Remediation: 删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding；仅保留经论证的公开发现/引导只读例外。
### 容器持久化安全评估

- Domain Score: `93.75`
- Scored Checkpoints: `2`
- Unknown Checkpoints: `3`

- **UNKNOWN high** `CN-35` `CN-PER-001-apiserver-etcd-client-cert` API Server 到 etcd 双向 TLS 检查 (_cluster)
  - Evidence: kube-apiserver etcd flags from kubernetes-pod
  - Remediation: 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。
- **UNKNOWN high** `CN-35` `CN-PER-001-etcd-tls` etcd TLS/client-cert-auth 检查 (_cluster)
  - Evidence: etcd flags from kubernetes-pod
  - Remediation: 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。
- **UNKNOWN high** `CN-35` `CN-PER-001-secret-encryption` Secret 静态加密检查 (_cluster)
  - Evidence: kube-apiserver encryption-provider-config from kubernetes-pod
  - Remediation: 配置 Kubernetes encryption provider/KMS 加密 Secret。
- **UNKNOWN high** `CN-39` `CN-PER-004-falco-events` Falco/Audit/Event 数据源检查 (_cluster)
  - Evidence: Falco/Audit/Event 数据源覆盖
  - Remediation: 接入 Falco 事件流、Kubernetes Event 或 apiserver audit log；无异常事件时保留数据源健康证据。
- **UNKNOWN high** `CN-39` `CN-PER-004-incident-ledger` 持久化异常事件台账 (_cluster)
  - Evidence: 归一化 Falco/Audit/Event/PVC 异常事件，形成可追溯历史台账
  - Remediation: 将 Falco、Kubernetes Event 和 apiserver audit log 持续写入事件台账，并保留 Pod/PVC/Namespace 关联。
- **WARN info** `CN-38` `CN-REG-001-security-posture` 镜像仓库安全状态汇总 (_cluster)
  - Evidence: 汇总镜像引用、RegistryEndpoint adapter、审计事件、pull secret、Trivy/SecretReport 证据的仓库安全态势
  - Remediation: 持续接入 registry API、审计日志和镜像扫描报告；按 registry 维度跟踪 TLS、匿名拉取、robot 权限、异常事件和漏洞泄露。
- **UNKNOWN info** `CN-35` `CN-PER-001-control-plane-source` Control-plane static pod 证据源检查 (_cluster)
  - Evidence: kubeadm static pod manifest 或 mirror pod 采集状态
  - Remediation: 自建集群启用 control-plane collector；托管集群补充云厂商控制面配置证据。
- **UNKNOWN info** `CN-36` `CN-PER-002-no-storage` 存储资源采集检查 (_cluster)
  - Evidence: 未采集 StorageClass/PV
  - Remediation: 扩大存储资源采集范围。
- **UNKNOWN info** `CN-37` `CN-PER-003-no-statefulset` 有状态应用采集检查 (_cluster)
  - Evidence: 未采集 StatefulSet/数据库 Pod/PVC
  - Remediation: 采集有状态应用、数据库 Pod 或标记场景不适用。
- **UNKNOWN info** `CN-38` `CN-REG-001-registry-audit` Registry 审计异常检查 (_cluster)
  - Evidence: RegistryAuditEvent 审计事件；无 registry audit adapter 时用 Kubernetes image pull event 作为有限证据
  - Remediation: 接入 Harbor/Registry 审计日志，告警匿名拉取、删除镜像、认证失败、ImagePullBackOff 和异常批量拉取。

## 4. 重点风险清单

- **FAIL high** `CN-24` `CN-ELAS-002-admission-policy-present` 准入策略覆盖检查 (_cluster)
  - Evidence: 检查 Kyverno/Gatekeeper/VAP 是否存在并完整覆盖核心 Pod 安全约束
  - Remediation: 安装并启用 Pod 安全准入策略，至少覆盖 runAsNonRoot、禁止提权、禁用特权容器、drop ALL capabilities、seccompProfile。
- **FAIL high** `CN-25` `CN-ELAS-003-admission-governance` 新 Pod/节点准入治理检查 (_cluster)
  - Evidence: 准入策略应覆盖 Pod/Node 等新资源的创建或更新，证明新增对象会自动套用治理策略
  - Remediation: 为 Pod/Node 配置 ValidatingAdmissionPolicy、Kyverno 或等效准入策略，确保新对象自动继承安全与资源治理。
- **FAIL high** `INT-5` `INT-DATA-005-unknown-rate` UNKNOWN 证据不足率评估 (AssessmentPipeline/_cluster/pve-good-live-20260630)
  - Evidence: UNKNOWN finding 过高说明证据链不足
  - Remediation: 补充采集权限、增强采集器或在报告限制说明中标注不可见证据。

### 整改优先级

| Priority | Score | Checkpoint | Rule | Severity/Status | Asset | Remediation |
|---|---:|---|---|---|---|---|
| P1 | 16 | CN-24 | CN-ELAS-002-admission-policy-present | high/FAIL | _cluster | 安装并启用 Pod 安全准入策略，至少覆盖 runAsNonRoot、禁止提权、禁用特权容器、drop ALL capabilities、seccompProfile。 |
| P1 | 16 | CN-25 | CN-ELAS-003-admission-governance | high/FAIL | _cluster | 为 Pod/Node 配置 ValidatingAdmissionPolicy、Kyverno 或等效准入策略，确保新对象自动继承安全与资源治理。 |
| P1 | 16 | INT-5 | INT-DATA-005-unknown-rate | high/FAIL | AssessmentPipeline/_cluster/pve-good-live-20260630 | 补充采集权限、增强采集器或在报告限制说明中标注不可见证据。 |
| P2 | 9 | CN-29 | CN-IAM-002-context-policy | medium/WARN | _cluster | 增加基于 namespace、label、env/tenant、userInfo/subject 的准入控制策略。 |
| P3 | 6 | CN-25 | CN-ELAS-003-priorityclass | medium/WARN | _cluster | 定义系统、业务和批处理等 PriorityClass，并在关键 workload 中引用非 system-* 优先级类。 |
| P3 | 6 | INT-10 | INT-SMART-001-model-auth | medium/WARN | ModelEndpoint/_cluster/mock-llm-endpoint | 真实 adapter 应检查模型服务入口鉴权、调用配额、来源限制和审计日志。 |
| P3 | 6 | INT-5 | INT-DATA-005-collection-warnings | medium/WARN | AssessmentPipeline/_cluster/pve-good-live-20260630 | 安装缺失 CRD、补齐权限，或在限制说明中记录非致命采集 warning。 |
| P3 | 6 | INT-8 | INT-API-001-public-admin | medium/WARN | CloudApiEndpoint/_cluster/https://api.example.invalid | 真实 adapter 应校验管理 API 暴露范围、来源白名单、mTLS 或专线接入。 |
| P3 | 4 | CN-35 | CN-PER-001-apiserver-etcd-client-cert | high/UNKNOWN | _cluster | 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。 |
| P3 | 4 | CN-35 | CN-PER-001-etcd-tls | high/UNKNOWN | _cluster | 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。 |
| P3 | 4 | CN-35 | CN-PER-001-secret-encryption | high/UNKNOWN | _cluster | 配置 Kubernetes encryption provider/KMS 加密 Secret。 |
| P3 | 4 | CN-39 | CN-PER-004-falco-events | high/UNKNOWN | _cluster | 接入 Falco 事件流、Kubernetes Event 或 apiserver audit log；无异常事件时保留数据源健康证据。 |
| P3 | 4 | CN-39 | CN-PER-004-incident-ledger | high/UNKNOWN | _cluster | 将 Falco、Kubernetes Event 和 apiserver audit log 持续写入事件台账，并保留 Pod/PVC/Namespace 关联。 |
| P3 | 3 | CN-25 | CN-ELAS-003-daemonset-governance | medium/UNKNOWN | _cluster | 部署并验证 CNI、Falco、日志采集等 DaemonSet 覆盖全部节点，确保新节点加入后自动纳管。 |
| P3 | 3 | CN-28 | CN-IAM-001-apiserver-tls | medium/UNKNOWN | _cluster | 确保 kube-apiserver 使用 TLS 证书/私钥并仅暴露 secure-port；禁用任何 insecure 监听。 |
| P3 | 3 | CN-28 | CN-IAM-001-external-auth-evidence | medium/UNKNOWN | _cluster | 如需企业统一身份，配置 OIDC/webhook/front-proxy；否则至少保留 apiserver client CA 与 service-account issuer 等本地认证依据。 |
| P3 | 3 | CN-29 | CN-IAM-002-permission-matrix-coverage | medium/UNKNOWN | _cluster | 补充 Role/ClusterRole/Binding 采集权限，确保权限矩阵覆盖 Pod、Service、ConfigMap、Secret、Ingress、Namespace 等标书关注对象。 |
| P3 | 3 | CN-29 | CN-IAM-002-permission-queryability | medium/UNKNOWN | _cluster | 保留 RBAC rows 明细，并在报告/UI 中支持按主体、资源和动作用例检索权限。 |
| P3 | 3 | CN-30 | CN-IAM-003-abnormal-login | medium/UNKNOWN | _cluster | 禁止 root 和口令 SSH 登录；对公网来源、成功登录和暴破行为建立告警与处置流程。 |
| P3 | 3 | CN-30 | CN-IAM-003-container-exec-audit | medium/UNKNOWN | _cluster | 开启并保留 apiserver audit log；对业务主体的 pod exec 建立审批、告警和过期访问控制。 |

## 5. 指标赋权与符合度判定

- 计分口径: UNKNOWN 检查点不计入得分分母；Critical/High 失败项会触发符合度门禁。
- Scored Weight: `30.1`
- Unknown Weight: `6.3`

### 权重与状态

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | FAIL | 75.0 | 6 | 1/1/0 |
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | UNKNOWN | 0.0 | 2 | 0/0/1 |
| INT-6 数据格式优化 | 工具集成数据处理 | 0.7 | PASS | 100.0 | 1 | 0/0/0 |
| INT-7 工具集成框架构建 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 2 | 0/0/0 |
| INT-8 云上 API 安全评估工具接入适配 | 工具集成数据处理 | 0.8 | PASS | 87.5 | 4 | 0/1/0 |
| INT-9 云原生安全评估工具接入适配 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-10 智算云安全评估工具接入适配 | 工具集成数据处理 | 0.8 | PASS | 87.5 | 4 | 0/1/0 |
| INT-11 调用参数标准化 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-12 调用流程协调 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-13 输出格式归一化 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-14 结果汇总整合 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-16 多工具安全态势总览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-17 API 工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-18 云原生工具结果详览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-19 智算云工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-20 数据筛选交互 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-21 结果交互查询 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 1 | 0/0/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 0.0 | 2 | 1/0/1 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 25.0 | 4 | 1/1/2 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 3 | 0/0/2 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 4 | 0/0/2 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | PASS | 87.5 | 6 | 0/1/2 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 5 | 0/0/4 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | UNKNOWN | 0.0 | 4 | 0/0/4 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | UNKNOWN | 0.0 | 1 | 0/0/1 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | PASS | 87.5 | 9 | 0/1/5 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 6 | 0/0/5 |
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |

## 6. 数据质量与限制

- Completeness: `100.0%`
- Freshness: `100.0%`
- Duplicate Rate: `0.0%`
- Unknown Rate: `37.65%`
- Schema Errors: `0`
- Collection Warnings: `53`
- UNKNOWN 原因样例:
  - `CN-23` 规则未生成证据
  - `CN-24` 新 Pod 由 HPA/Deployment/StatefulSet 扩容创建时应继承 namespace PSA 或准入策略
  - `CN-25` 用于节点纳管的 DaemonSet 数量
  - `CN-25` 至少一个节点级 DaemonSet 应证明新节点加入后会自动被安全/网络/观测组件纳管
  - `CN-26` Event/AuditLog 中的异常 scale 行为
  - `CN-26` 识别到的 scale 事件数量
  - `CN-27` 未采集 Job/PVC
  - `CN-28` kube-apiserver 应提供 TLS 证书、私钥和 secure-port 证据，且不应启用 insecure 监听
  - `CN-28` kube-apiserver 应提供 OIDC、webhook、front-proxy 或明确的本地认证依据
  - `CN-29` RBAC 矩阵应覆盖 Pod/Service/ConfigMap/Secret/Ingress/Namespace 并支持按主体/资源查询
  - `CN-29` 权限矩阵应支持按 subject/resource/verb/binding/role/scope 维度查询，便于定位过度授权和提权路径
  - `CN-30` 应识别 root 登录、口令登录成功、来自公网/未知来源的 SSH 成功登录等异常身份事件
  - `CN-30` 应能从 audit log 识别容器 exec 行为，并区分业务主体与系统控制器
  - `CN-30` Falco/auth/audit 事件或 Falco 工作负载
  - `CN-30` 归一化 auth.log、apiserver audit 与 Falco 身份事件，形成连续身份安全台账
  - `CN-35` kube-apiserver etcd flags from kubernetes-pod
  - `CN-35` kubeadm static pod manifest 或 mirror pod 采集状态
  - `CN-35` etcd flags from kubernetes-pod
  - `CN-35` kube-apiserver encryption-provider-config from kubernetes-pod
  - `CN-36` 未采集 StorageClass/PV
- 限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。

## 7. 附录

- Schema Version: `1.0`
- Raw Snapshot Count: `4`
- Normalized Finding Count: `85`
- References: 当前报告未采集到外部引用。

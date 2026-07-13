# 云原生安全评估报告

## 1. 评估摘要

- Task ID: `local-all-tools`
- Generated At: `2026-06-22T10:12:40.874065+00:00`
- Tools: `cloud_native, cloud_api_stub, smart_cloud_stub`
- Overall Score: `75.95`
- Conclusion: **不符合，存在 critical 必检失败项**
- Evidence Coverage: `96.7%`
- Severity Count: `critical=2, high=29, info=27, low=5, medium=38`

## 2. 标书检查点覆盖情况

### 云原生三大域

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 33.33 | 12 | 8/0/0 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 40.0 | 10 | 4/4/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 27.78 | 9 | 6/1/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 33.33 | 3 | 2/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | WARN | 75.0 | 5 | 0/2/1 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 33.33 | 3 | 2/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | WARN | 78.57 | 7 | 0/3/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | WARN | 70.0 | 6 | 0/3/1 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | FAIL | 25.0 | 2 | 1/1/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 33.33 | 4 | 2/0/1 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | UNKNOWN | 0.0 | 2 | 0/0/2 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | FAIL | 33.33 | 3 | 1/2/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | FAIL | 30.0 | 5 | 2/3/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | WARN | 75.0 | 3 | 0/1/1 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 2 | 0/0/1 |
### 工具集成数据处理

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | FAIL | 50.0 | 1 | 0/1/0 |
| INT-6 数据格式优化 | 工具集成数据处理 | 0.7 | PASS | 100.0 | 1 | 0/0/0 |
| INT-7 工具集成框架构建 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-8 云上 API 安全评估工具接入适配 | 工具集成数据处理 | 0.8 | WARN | 75.0 | 2 | 0/1/0 |
| INT-9 云原生安全评估工具接入适配 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-10 智算云安全评估工具接入适配 | 工具集成数据处理 | 0.8 | WARN | 75.0 | 2 | 0/1/0 |
| INT-11 调用参数标准化 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-12 调用流程协调 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-13 输出格式归一化 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-14 结果汇总整合 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
### 集成可视化展示

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-16 多工具安全态势总览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-17 API 工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-18 云原生工具结果详览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-19 智算云工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-20 数据筛选交互 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-21 结果交互查询 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |

## 3. 云原生安全评估结果

### 不可变基础设施与弹性安全评估

- Domain Score: `45.91`
- Scored Checkpoints: `7`
- Unknown Checkpoints: `0`

- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/kube-system/metrics-server 根文件系统只读检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` StatefulSet/cnsec-bad/postgres-bad 根文件系统只读检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/cnsec-bad/web-bad 根文件系统只读检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` StatefulSet/cnsec-bad/postgres-bad 禁止提权检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/cnsec-bad/web-bad 禁止提权检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/kube-system/metrics-server 禁止提权检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Deployment/cnsec-bad/web-bad 非 root 运行检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Deployment/kube-system/metrics-server 非 root 运行检查 (Deployment/kube-system/metrics-server)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` StatefulSet/cnsec-bad/postgres-bad 非 root 运行检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
### 动态访问控制与身份安全评估

- Domain Score: `42.78`
- Scored Checkpoints: `3`
- Unknown Checkpoints: `0`

- **FAIL critical** `CN-29` `CN-IAM-002-dangerous-rbac` Role/cnsec-bad/dangerous-app-role 高危 RBAC 权限 (Role/cnsec-bad/dangerous-app-role)
  - Evidence: 发现高危 verbs/resources
  - Remediation: 移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限。
- **PASS critical** `CN-28` `CN-IAM-001-anonymous-binding` 匿名主体绑定检查 (_cluster)
  - Evidence: 匿名/未认证主体绑定
  - Remediation: 删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-container` Deployment/cnsec-bad/web-bad SSH 容器暴露检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器不应运行 sshd 或暴露 22 端口
  - Remediation: 删除容器内 sshd，使用 Kubernetes 原生审计访问路径。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH Service 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kube-system/metrics-server SSH Service 暴露检查 (Service/kube-system/metrics-server)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **WARN medium** `CN-28` `CN-IAM-001-sa-token-automount` Deployment/cnsec-bad/web-bad SA token 自动挂载检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 默认不应自动挂载 ServiceAccount token
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false。
- **WARN medium** `CN-28` `CN-IAM-001-sa-token-automount` Deployment/kube-system/metrics-server SA token 自动挂载检查 (Deployment/kube-system/metrics-server)
  - Evidence: 默认不应自动挂载 ServiceAccount token
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false。
- **WARN medium** `CN-28` `CN-IAM-001-sa-token-automount` StatefulSet/cnsec-bad/postgres-bad SA token 自动挂载检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 默认不应自动挂载 ServiceAccount token
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false。
- **WARN medium** `CN-29` `CN-IAM-002-context-policy` 动态上下文准入策略检查 (_cluster)
  - Evidence: 可用于 namespace/label/env 上下文控制的策略
  - Remediation: 增加基于 namespace/label/env 的准入控制策略。
- **PASS medium** `CN-28` `CN-IAM-001-sa-token-automount` Deployment/cnsec-good/web-good SA token 自动挂载检查 (Deployment/cnsec-good/web-good)
  - Evidence: 默认不应自动挂载 ServiceAccount token
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false。
### 容器持久化安全评估

- Domain Score: `59.58`
- Scored Checkpoints: `4`
- Unknown Checkpoints: `1`

- **FAIL high** `CN-36` `CN-PER-002-hostpath-local-pv` PersistentVolume/_cluster/cnsec-hostpath-pv PV 类型检查 (PersistentVolume/_cluster/cnsec-hostpath-pv)
  - Evidence: hostPath/local PV 需要额外隔离和备份证明
  - Remediation: 避免 hostPath/local PV；如必须使用，补充节点隔离、备份和访问控制。
- **FAIL high** `CN-37` `CN-PER-003-no-plaintext-env` StatefulSet/cnsec-bad/postgres-bad 明文环境变量检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 敏感配置不应以明文 env value 暴露
  - Remediation: 使用 Secret 引用或 CSI Secret Store，避免明文 env。
- **FAIL high** `CN-37` `CN-PER-003-stateful-networkpolicy` StatefulSet/cnsec-bad/postgres-bad 网络隔离检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务 namespace 应配置 NetworkPolicy
  - Remediation: 为数据库/有状态服务配置默认拒绝和精确允许的 NetworkPolicy。
- **UNKNOWN high** `CN-35` `CN-PER-001-etcd-tls` etcd TLS/client-cert-auth 检查 (_cluster)
  - Evidence: etcd static pod args
  - Remediation: 启用 control-plane collector 并确保 etcd client/peer TLS。
- **UNKNOWN high** `CN-35` `CN-PER-001-secret-encryption` Secret 静态加密检查 (_cluster)
  - Evidence: kube-apiserver encryption-provider-config
  - Remediation: 配置 Kubernetes encryption provider/KMS 加密 Secret。
- **UNKNOWN high** `CN-39` `CN-PER-004-falco-events` Falco 运行时异常事件检查 (_cluster)
  - Evidence: Falco/运行时异常事件数量
  - Remediation: 接入 Falco 事件流；无事件时保留数据源健康证据。
- **PASS high** `CN-38` `CN-REG-001-insecure-registry` HTTP/本地明文仓库引用检查 (_cluster)
  - Evidence: 不安全镜像引用
  - Remediation: 使用 HTTPS registry，禁用匿名/明文 HTTP registry。
- **PASS high** `CN-39` `CN-PER-004-risky-volume-mount` 敏感路径挂载检查 (_cluster)
  - Evidence: 敏感路径挂载
  - Remediation: 避免将宿主敏感路径或根目录挂载进容器。
- **WARN medium** `CN-36` `CN-PER-002-storageclass-encryption` StorageClass/_cluster/insecure-local 加密参数检查 (StorageClass/_cluster/insecure-local)
  - Evidence: StorageClass 应声明加密/KMS 参数
  - Remediation: 为 StorageClass 配置加密参数或记录底层存储默认加密证据。
- **WARN medium** `CN-37` `CN-PER-003-backup-or-snapshot` StatefulSet/cnsec-bad/postgres-bad 备份/快照证据检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备 Velero Backup/Schedule 或 VolumeSnapshot 证据
  - Remediation: 为有状态服务配置 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。

## 4. 重点风险清单

- **FAIL critical** `CN-29` `CN-IAM-002-dangerous-rbac` Role/cnsec-bad/dangerous-app-role 高危 RBAC 权限 (Role/cnsec-bad/dangerous-app-role)
  - Evidence: 发现高危 verbs/resources
  - Remediation: 移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限。
- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/kube-system/metrics-server 根文件系统只读检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` StatefulSet/cnsec-bad/postgres-bad 根文件系统只读检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/cnsec-bad/web-bad 根文件系统只读检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` StatefulSet/cnsec-bad/postgres-bad 禁止提权检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/cnsec-bad/web-bad 禁止提权检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/kube-system/metrics-server 禁止提权检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器应禁止 allowPrivilegeEscalation
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Deployment/cnsec-bad/web-bad 非 root 运行检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Deployment/kube-system/metrics-server 非 root 运行检查 (Deployment/kube-system/metrics-server)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` StatefulSet/cnsec-bad/postgres-bad 非 root 运行检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: Pod 应设置 runAsNonRoot
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID。
- **FAIL high** `CN-24` `CN-ELAS-002-admission-policy-present` 准入策略覆盖检查 (_cluster)
  - Evidence: 检查 Kyverno/Gatekeeper/VAP 是否存在
  - Remediation: 安装并启用 Pod 安全准入策略。
- **FAIL high** `CN-26` `CN-ELAS-004-hpa-max` HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa HPA 上限检查 (HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa)
  - Evidence: HPA maxReplicas 不应过高
  - Remediation: 结合 ResourceQuota 设置合理 maxReplicas。
- **FAIL high** `CN-26` `CN-ELAS-004-scale-rbac` scale 子资源权限检查 (_cluster)
  - Evidence: 具备 scale 修改权限的角色
  - Remediation: 限制 deployments/scale update/patch 权限，仅授予 CI/CD 或自动伸缩控制器。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-container` Deployment/cnsec-bad/web-bad SSH 容器暴露检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器不应运行 sshd 或暴露 22 端口
  - Remediation: 删除容器内 sshd，使用 Kubernetes 原生审计访问路径。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH Service 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **FAIL high** `CN-36` `CN-PER-002-hostpath-local-pv` PersistentVolume/_cluster/cnsec-hostpath-pv PV 类型检查 (PersistentVolume/_cluster/cnsec-hostpath-pv)
  - Evidence: hostPath/local PV 需要额外隔离和备份证明
  - Remediation: 避免 hostPath/local PV；如必须使用，补充节点隔离、备份和访问控制。
- **FAIL high** `CN-37` `CN-PER-003-no-plaintext-env` StatefulSet/cnsec-bad/postgres-bad 明文环境变量检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 敏感配置不应以明文 env value 暴露
  - Remediation: 使用 Secret 引用或 CSI Secret Store，避免明文 env。
- **FAIL high** `CN-37` `CN-PER-003-stateful-networkpolicy` StatefulSet/cnsec-bad/postgres-bad 网络隔离检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务 namespace 应配置 NetworkPolicy
  - Remediation: 为数据库/有状态服务配置默认拒绝和精确允许的 NetworkPolicy。

## 5. 指标赋权与符合度判定

- 计分口径: UNKNOWN 检查点不计入得分分母；Critical/High 失败项会触发符合度门禁。
- Scored Weight: `35.2`
- Unknown Weight: `1.2`

### 权重与状态

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | FAIL | 50.0 | 1 | 0/1/0 |
| INT-6 数据格式优化 | 工具集成数据处理 | 0.7 | PASS | 100.0 | 1 | 0/0/0 |
| INT-7 工具集成框架构建 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-8 云上 API 安全评估工具接入适配 | 工具集成数据处理 | 0.8 | WARN | 75.0 | 2 | 0/1/0 |
| INT-9 云原生安全评估工具接入适配 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-10 智算云安全评估工具接入适配 | 工具集成数据处理 | 0.8 | WARN | 75.0 | 2 | 0/1/0 |
| INT-11 调用参数标准化 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-12 调用流程协调 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| INT-13 输出格式归一化 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-14 结果汇总整合 | 工具集成数据处理 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-16 多工具安全态势总览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-17 API 工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-18 云原生工具结果详览 | 集成可视化展示 | 1.0 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-19 智算云工具结果详览 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-20 数据筛选交互 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-21 结果交互查询 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 33.33 | 12 | 8/0/0 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 40.0 | 10 | 4/4/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 27.78 | 9 | 6/1/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 33.33 | 3 | 2/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | WARN | 75.0 | 5 | 0/2/1 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 33.33 | 3 | 2/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | WARN | 78.57 | 7 | 0/3/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | WARN | 70.0 | 6 | 0/3/1 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | FAIL | 25.0 | 2 | 1/1/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 33.33 | 4 | 2/0/1 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | UNKNOWN | 0.0 | 2 | 0/0/2 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | FAIL | 33.33 | 3 | 1/2/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | FAIL | 30.0 | 5 | 2/3/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | WARN | 75.0 | 3 | 0/1/1 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 2 | 0/0/1 |

## 6. 数据质量与限制

- Completeness: `100.0%`
- Freshness: `100.0%`
- Duplicate Rate: `0.0%`
- Unknown Rate: `6.93%`
- Schema Errors: `0`
- UNKNOWN 原因样例:
  - `CN-25` 用于节点纳管的 DaemonSet 数量
  - `CN-28` Istio PeerAuthentication STRICT
  - `CN-30` Falco/auth/audit 事件或 Falco 工作负载
  - `CN-35` etcd static pod args
  - `CN-35` kube-apiserver encryption-provider-config
  - `CN-38` VulnerabilityReport 数量
  - `CN-39` Falco/运行时异常事件数量
- 限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。

## 7. 附录

- Schema Version: `1.0`
- Raw Snapshot Count: `3`
- Normalized Finding Count: `101`
- References: 当前报告未采集到外部引用。

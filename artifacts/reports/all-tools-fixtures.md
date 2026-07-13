# 云原生安全评估报告

## 1. 评估摘要

- Task ID: `fixture-all-tools`
- Generated At: `2026-06-23T04:29:06.358656+00:00`
- Tools: `cloud_api_stub, cloud_native, registry_stub, smart_cloud_stub, platform`
- Overall Score: `75.12`
- Conclusion: **不符合，存在 critical 必检失败项**
- Evidence Coverage: `100.0%`
- Severity Count: `critical=5, high=57, info=80, low=12, medium=60`

### 工具聚合摘要

| Tool | Status | Schema | Findings | Fail/Warn/Unknown | Warnings | Raw Keys |
|---|---|---|---:|---|---:|---|
| cloud_api_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| cloud_native | ready | kubernetes-json/v1 | 179 | 77/30/2 | 0 | collected_at, kind_count, kinds, mode, object_count, rbac_matrix, resource_inventory, schema_version |
| registry_stub | stub (stub/mock) | stub/v1 | 1 | 0/0/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| smart_cloud_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| platform | ready | internal/v1 | 26 | 0/0/0 | 0 | integration_findings, visualization_findings |

## 2. 标书检查点覆盖情况

### 云原生三大域

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 52.27 | 23 | 8/5/0 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 52.63 | 19 | 7/4/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 30.43 | 23 | 13/6/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 55.56 | 9 | 4/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 40.0 | 6 | 3/0/1 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 42.86 | 7 | 4/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 46.15 | 13 | 7/0/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 56.25 | 9 | 1/5/1 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | FAIL | 58.33 | 6 | 1/3/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 50.0 | 6 | 3/0/0 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | FAIL | 25.0 | 4 | 3/0/0 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | FAIL | 84.09 | 22 | 1/5/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | FAIL | 28.57 | 14 | 10/0/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | FAIL | 27.78 | 9 | 6/1/0 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | FAIL | 27.78 | 9 | 6/1/0 |
### 工具集成数据处理

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 6 | 0/0/0 |
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

- Domain Score: `45.7`
- Scored Checkpoints: `7`
- Unknown Checkpoints: `0`

- **FAIL critical** `CN-22` `CN-IMM-001-exec-rbac` 普通主体 pods/exec 修改路径检查 (_cluster)
  - Evidence: 不可变部署不应给普通/业务主体宽泛 pods/exec 权限
  - Remediation: 移除普通主体的 pods/exec create/update/patch 权限；调试访问应临时授权、带审批和过期标记。
- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-container` Deployment/cnsec-bad/web-bad 容器 SSH/sshd 检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 不可变容器不应暴露 22 端口或运行 sshd/openssh-server
  - Remediation: 移除容器内 SSH 服务，使用审计受控的 kubectl exec、临时调试容器或节点级运维通道。
- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/kube-system/metrics-server 根文件系统只读检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` StatefulSet/cnsec-bad/postgres-bad 根文件系统只读检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Pod/cnsec-bad/db-data-debug-mounter 根文件系统只读检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/cnsec-bad/web-bad 根文件系统只读检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Pod/cnsec-bad/db-data-debug-mounter 禁止提权检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` StatefulSet/cnsec-bad/postgres-bad 禁止提权检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/cnsec-bad/web-bad 禁止提权检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
### 动态访问控制与身份安全评估

- Domain Score: `54.86`
- Scored Checkpoints: `3`
- Unknown Checkpoints: `0`

- **FAIL critical** `CN-28` `CN-IAM-001-anonymous-binding` 匿名主体绑定检查 (_cluster)
  - Evidence: 匿名/未认证主体绑定
  - Remediation: 删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding。
- **FAIL critical** `CN-29` `CN-IAM-002-dangerous-rbac` Group:system:authenticated 高危 RBAC 授权 (RoleBinding/cnsec-bad/dangerous-app-rolebinding)
  - Evidence: 绑定后的主体权限矩阵发现业务/非系统主体高危授权
  - Remediation: 移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限；避免绑定 system:authenticated 等宽泛主体。
- **FAIL high** `CN-30` `CN-IAM-003-authlog-ssh-bruteforce` 10.20.0.99 SSH 暴破行为 (AuthLogEvent/_cluster/authlog_ssh_bruteforce-1)
  - Evidence: auth.log 识别到同一来源多次 SSH 登录失败
  - Remediation: 封禁来源 IP，关闭节点 SSH 暴露，改用堡垒机或受审计的临时访问。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-container` Deployment/cnsec-bad/web-bad SSH 容器暴露检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器不应运行 sshd 或暴露 22 端口
  - Remediation: 删除容器内 sshd，使用 Kubernetes 原生审计访问路径。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH Service 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **WARN high** `CN-29` `CN-IAM-002-temporary-grant-expiry` 临时/高危授权过期标记检查 (_cluster)
  - Evidence: 高危业务授权缺少 expires/ttl 等过期标记
  - Remediation: 为临时或高危授权添加可解析且未过期的 expires-at 注解，并由准入策略或定时清理任务回收。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/orphan-service SSH Service 暴露检查 (Service/cnsec-bad/orphan-service)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/postgres-bad SSH Service 暴露检查 (Service/cnsec-bad/postgres-bad)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **WARN medium** `CN-28` `CN-IAM-001-sa-token-automount` Deployment/cnsec-bad/web-bad SA token 自动挂载检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 业务 workload 默认不应自动挂载 ServiceAccount token；平台控制器按 API 访问需求单独复核，controller 管理的 Pod 由其 workload 模板代表
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false；需要 API 权限的组件记录用途并最小化 RBAC。
- **WARN medium** `CN-28` `CN-IAM-001-sa-token-automount` StatefulSet/cnsec-bad/postgres-bad SA token 自动挂载检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 业务 workload 默认不应自动挂载 ServiceAccount token；平台控制器按 API 访问需求单独复核，controller 管理的 Pod 由其 workload 模板代表
  - Remediation: 不需要访问 API 的 workload 设置 automountServiceAccountToken=false；需要 API 权限的组件记录用途并最小化 RBAC。
### 容器持久化安全评估

- Domain Score: `38.64`
- Scored Checkpoints: `5`
- Unknown Checkpoints: `0`

- **FAIL critical** `CN-39` `CN-PER-004-runtime-abnormal-write` Falco 异常文件写入: Write below persistent data dir (Pod/cnsec-bad/postgres-bad-0)
  - Evidence: Falco 事件关联运行时异常或敏感持久化访问，并关联 Pod/PVC/Namespace 上下文
  - Remediation: 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。
- **FAIL critical** `CN-39` `CN-PER-004-volume-mount-escape` Falco 卷挂载逃逸/异常访问: Terminal shell in container (Pod/cnsec-bad/web-bad)
  - Evidence: Falco 事件关联运行时异常或敏感持久化访问，并关联 Pod/PVC/Namespace 上下文
  - Remediation: 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。
- **FAIL high** `CN-35` `CN-PER-001-apiserver-etcd-client-cert` API Server 到 etcd 双向 TLS 检查 (_cluster)
  - Evidence: kube-apiserver etcd flags from static-pod-manifest
  - Remediation: 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。
- **FAIL high** `CN-35` `CN-PER-001-etcd-tls` etcd TLS/client-cert-auth 检查 (_cluster)
  - Evidence: etcd flags from static-pod-manifest
  - Remediation: 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。
- **FAIL high** `CN-35` `CN-PER-001-secret-encryption` Secret 静态加密检查 (_cluster)
  - Evidence: kube-apiserver encryption-provider-config from static-pod-manifest
  - Remediation: 配置 Kubernetes encryption provider/KMS 加密 Secret。
- **FAIL high** `CN-36` `CN-PER-002-hostpath-local-pv` PersistentVolume/_cluster/cnsec-hostpath-pv PV 类型检查 (PersistentVolume/_cluster/cnsec-hostpath-pv)
  - Evidence: hostPath/local PV 需要额外隔离和备份证明
  - Remediation: 避免 hostPath/local PV；如必须使用，补充节点隔离、备份和访问控制。
- **FAIL high** `CN-37` `CN-PER-003-backup-or-snapshot` StatefulSet/cnsec-bad/postgres-bad 备份/快照证据检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据
  - Remediation: 为有状态服务配置覆盖对应 PVC 或工作负载 selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。
- **FAIL high** `CN-37` `CN-PER-003-database-service-exposure` StatefulSet/cnsec-bad/postgres-bad 数据库 Service 暴露检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 数据库/有状态服务不应通过 NodePort/LoadBalancer 直接暴露；未匹配到 Service 时作为证据缺口复核
  - Remediation: 将数据库 Service 限制为 ClusterIP/headless，并通过 NetworkPolicy 控制访问来源；未发现关联 Service 时补充服务发现或暴露面证明。
- **FAIL high** `CN-37` `CN-PER-003-kms-or-csi-secret-store` StatefulSet/cnsec-bad/postgres-bad KMS/CSI Secret Store 集成检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备 KMS 参数或 CSI Secret Store 集成证据
  - Remediation: 为数据库凭据和存储加密接入 KMS、External Secrets 或 CSI Secret Store。
- **FAIL high** `CN-37` `CN-PER-003-no-plaintext-env` StatefulSet/cnsec-bad/postgres-bad 明文环境变量检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 敏感配置不应以明文 env value 暴露
  - Remediation: 使用 Secret 引用或 CSI Secret Store，避免明文 env。

## 4. 重点风险清单

- **FAIL critical** `CN-22` `CN-IMM-001-exec-rbac` 普通主体 pods/exec 修改路径检查 (_cluster)
  - Evidence: 不可变部署不应给普通/业务主体宽泛 pods/exec 权限
  - Remediation: 移除普通主体的 pods/exec create/update/patch 权限；调试访问应临时授权、带审批和过期标记。
- **FAIL critical** `CN-28` `CN-IAM-001-anonymous-binding` 匿名主体绑定检查 (_cluster)
  - Evidence: 匿名/未认证主体绑定
  - Remediation: 删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding。
- **FAIL critical** `CN-29` `CN-IAM-002-dangerous-rbac` Group:system:authenticated 高危 RBAC 授权 (RoleBinding/cnsec-bad/dangerous-app-rolebinding)
  - Evidence: 绑定后的主体权限矩阵发现业务/非系统主体高危授权
  - Remediation: 移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限；避免绑定 system:authenticated 等宽泛主体。
- **FAIL critical** `CN-39` `CN-PER-004-runtime-abnormal-write` Falco 异常文件写入: Write below persistent data dir (Pod/cnsec-bad/postgres-bad-0)
  - Evidence: Falco 事件关联运行时异常或敏感持久化访问，并关联 Pod/PVC/Namespace 上下文
  - Remediation: 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。
- **FAIL critical** `CN-39` `CN-PER-004-volume-mount-escape` Falco 卷挂载逃逸/异常访问: Terminal shell in container (Pod/cnsec-bad/web-bad)
  - Evidence: Falco 事件关联运行时异常或敏感持久化访问，并关联 Pod/PVC/Namespace 上下文
  - Remediation: 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。
- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-container` Deployment/cnsec-bad/web-bad 容器 SSH/sshd 检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 不可变容器不应暴露 22 端口或运行 sshd/openssh-server
  - Remediation: 移除容器内 SSH 服务，使用审计受控的 kubectl exec、临时调试容器或节点级运维通道。
- **FAIL high** `CN-22` `CN-IMM-001-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/kube-system/metrics-server 根文件系统只读检查 (Deployment/kube-system/metrics-server)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` StatefulSet/cnsec-bad/postgres-bad 根文件系统只读检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Pod/cnsec-bad/db-data-debug-mounter 根文件系统只读检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-22` `CN-IMM-001-rootfs-readonly` Deployment/cnsec-bad/web-bad 根文件系统只读检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器根文件系统应只读
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Pod/cnsec-bad/db-data-debug-mounter 禁止提权检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` StatefulSet/cnsec-bad/postgres-bad 禁止提权检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-no-privilege-escalation` Deployment/cnsec-bad/web-bad 禁止提权检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 业务容器应禁止 allowPrivilegeEscalation；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-rootfs-readonly` Pod/cnsec-bad/db-data-debug-mounter 只读根文件系统管控检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 业务容器应设置 readOnlyRootFilesystem=true；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。
- **FAIL high** `CN-23` `CN-IMM-002-rootfs-readonly` StatefulSet/cnsec-bad/postgres-bad 只读根文件系统管控检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 业务容器应设置 readOnlyRootFilesystem=true；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。
- **FAIL high** `CN-23` `CN-IMM-002-rootfs-readonly` Deployment/cnsec-bad/web-bad 只读根文件系统管控检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 业务容器应设置 readOnlyRootFilesystem=true；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` StatefulSet/cnsec-bad/postgres-bad 非 root 运行检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 业务容器应设置 runAsNonRoot；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Deployment/cnsec-bad/web-bad 非 root 运行检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 业务容器应设置 runAsNonRoot；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-run-as-non-root` Pod/cnsec-bad/db-data-debug-mounter 非 root 运行检查 (Pod/cnsec-bad/db-data-debug-mounter)
  - Evidence: 业务容器应设置 runAsNonRoot；平台组件缺失时作为兼容性复核项
  - Remediation: 设置 pod/container securityContext.runAsNonRoot=true 并指定非 root UID；平台组件记录例外依据。
- **FAIL high** `CN-23` `CN-IMM-002-spec-hash-baseline` Deployment/cnsec-bad/web-bad spec hash 基线检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 首次扫描应记录 workload spec hash，二次扫描用于识别漂移；支持注解基线和历史 Asset/SpecHashBaseline 基线
  - Remediation: 为业务 workload 写入 cnsec.io/spec-hash 基线或持久化 Asset.spec_hash；发现 hash 漂移时走变更审批或回滚。
- **FAIL high** `CN-24` `CN-ELAS-002-admission-policy-present` 准入策略覆盖检查 (_cluster)
  - Evidence: 检查 Kyverno/Gatekeeper/VAP 是否存在并完整覆盖核心 Pod 安全约束
  - Remediation: 安装并启用 Pod 安全准入策略，至少覆盖 runAsNonRoot、禁止提权、禁用特权容器、drop ALL capabilities、seccompProfile。
- **FAIL high** `CN-24` `CN-ELAS-002-hpa-template-inheritance` HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa HPA 扩容模板安全继承检查 (HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa)
  - Evidence: HPA 扩容后的 Pod template 应继承 namespace PSA/准入策略并满足基础安全上下文
  - Remediation: 为 HPA 目标 workload 配置非 root、禁止提权、只读根文件系统、drop ALL capabilities、requests/limits，并确保 namespace PSA 或准入策略覆盖扩容 Pod。
- **FAIL high** `CN-24` `CN-ELAS-002-workload-policy-inheritance` 扩缩容工作负载策略继承检查 (_cluster)
  - Evidence: 新 Pod 由 HPA/Deployment/StatefulSet 扩容创建时应继承 namespace PSA 或准入策略
  - Remediation: 为业务工作负载 namespace 启用 PSA restricted/baseline 或等价 Kyverno/Gatekeeper/VAP 策略，确保扩容后新 Pod 自动继承约束。
- **FAIL high** `CN-26` `CN-ELAS-004-abnormal-scale-events` 异常扩缩容事件检查 (_cluster)
  - Evidence: Event/AuditLog 中的异常 scale 行为
  - Remediation: 启用审计日志并告警：非 CI/CD/HPA 主体修改 scale、短时间频繁扩缩、目标副本数异常增大。
- **FAIL high** `CN-26` `CN-ELAS-004-hpa-max` HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa HPA 副本边界检查 (HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa)
  - Evidence: HPA 应设置合理 minReplicas/maxReplicas，避免异常扩容或单副本弹性窗口
  - Remediation: 结合 ResourceQuota 设置合理 minReplicas/maxReplicas。
- **FAIL high** `CN-26` `CN-ELAS-004-resourcequota-guardrail` HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa ResourceQuota 扩容护栏检查 (HorizontalPodAutoscaler/cnsec-bad/web-bad-hpa)
  - Evidence: HPA 所在 namespace 应有完整 pods 与 CPU/Memory requests/limits ResourceQuota；当 HPA maxReplicas 过高时，pods quota 应形成二级上限
  - Remediation: 为启用 HPA 的业务 namespace 配置完整 pods、requests.cpu、requests.memory、limits.cpu、limits.memory ResourceQuota；对高 maxReplicas 场景设置能实际限制异常扩容的 pods quota。
- **FAIL high** `CN-26` `CN-ELAS-004-scale-rbac` scale 子资源权限检查 (_cluster)
  - Evidence: 具备 scale 修改权限的角色
  - Remediation: 限制 deployments/scale/statefulsets/scale update/patch 权限，仅授予 CI/CD 或自动伸缩控制器；系统内置角色单独复核绑定范围。
- **FAIL high** `CN-30` `CN-IAM-003-authlog-ssh-bruteforce` 10.20.0.99 SSH 暴破行为 (AuthLogEvent/_cluster/authlog_ssh_bruteforce-1)
  - Evidence: auth.log 识别到同一来源多次 SSH 登录失败
  - Remediation: 封禁来源 IP，关闭节点 SSH 暴露，改用堡垒机或受审计的临时访问。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-container` Deployment/cnsec-bad/web-bad SSH 容器暴露检查 (Deployment/cnsec-bad/web-bad)
  - Evidence: 容器不应运行 sshd 或暴露 22 端口
  - Remediation: 删除容器内 sshd，使用 Kubernetes 原生审计访问路径。
- **FAIL high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-bad/web-bad-ssh SSH Service 暴露检查 (Service/cnsec-bad/web-bad-ssh)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **FAIL high** `CN-35` `CN-PER-001-apiserver-etcd-client-cert` API Server 到 etcd 双向 TLS 检查 (_cluster)
  - Evidence: kube-apiserver etcd flags from static-pod-manifest
  - Remediation: 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。
- **FAIL high** `CN-35` `CN-PER-001-etcd-tls` etcd TLS/client-cert-auth 检查 (_cluster)
  - Evidence: etcd flags from static-pod-manifest
  - Remediation: 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。
- **FAIL high** `CN-35` `CN-PER-001-secret-encryption` Secret 静态加密检查 (_cluster)
  - Evidence: kube-apiserver encryption-provider-config from static-pod-manifest
  - Remediation: 配置 Kubernetes encryption provider/KMS 加密 Secret。
- **FAIL high** `CN-36` `CN-PER-002-hostpath-local-pv` PersistentVolume/_cluster/cnsec-hostpath-pv PV 类型检查 (PersistentVolume/_cluster/cnsec-hostpath-pv)
  - Evidence: hostPath/local PV 需要额外隔离和备份证明
  - Remediation: 避免 hostPath/local PV；如必须使用，补充节点隔离、备份和访问控制。
- **FAIL high** `CN-37` `CN-PER-003-backup-or-snapshot` StatefulSet/cnsec-bad/postgres-bad 备份/快照证据检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据
  - Remediation: 为有状态服务配置覆盖对应 PVC 或工作负载 selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。
- **FAIL high** `CN-37` `CN-PER-003-database-service-exposure` StatefulSet/cnsec-bad/postgres-bad 数据库 Service 暴露检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 数据库/有状态服务不应通过 NodePort/LoadBalancer 直接暴露；未匹配到 Service 时作为证据缺口复核
  - Remediation: 将数据库 Service 限制为 ClusterIP/headless，并通过 NetworkPolicy 控制访问来源；未发现关联 Service 时补充服务发现或暴露面证明。
- **FAIL high** `CN-37` `CN-PER-003-kms-or-csi-secret-store` StatefulSet/cnsec-bad/postgres-bad KMS/CSI Secret Store 集成检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备 KMS 参数或 CSI Secret Store 集成证据
  - Remediation: 为数据库凭据和存储加密接入 KMS、External Secrets 或 CSI Secret Store。
- **FAIL high** `CN-37` `CN-PER-003-no-plaintext-env` StatefulSet/cnsec-bad/postgres-bad 明文环境变量检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 敏感配置不应以明文 env value 暴露
  - Remediation: 使用 Secret 引用或 CSI Secret Store，避免明文 env。
- **FAIL high** `CN-37` `CN-PER-003-pvc-data-protection` PersistentVolumeClaim/cnsec-bad/db-data PVC 数据保护证据检查 (PersistentVolumeClaim/cnsec-bad/db-data)
  - Evidence: PVC 应同时具备存储加密和可恢复备份/快照证据
  - Remediation: 为持久化 PVC 绑定加密/KMS StorageClass，并配置 CSI VolumeSnapshot、Velero Schedule 或等效备份证据。
- **FAIL high** `CN-37` `CN-PER-003-pvc-encryption-evidence` StatefulSet/cnsec-bad/postgres-bad PVC 加密证据检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务 PVC 应有关联 StorageClass 加密/KMS 证据
  - Remediation: 为 StatefulSet 使用带加密/KMS 参数的 StorageClass，或补充底层存储默认加密证明。
- **FAIL high** `CN-37` `CN-PER-003-pvc-namespace-isolation` PersistentVolumeClaim/cnsec-bad/db-data PVC 网络隔离与共享面检查 (PersistentVolumeClaim/cnsec-bad/db-data)
  - Evidence: PVC 所在 namespace 应具备 NetworkPolicy，且共享读写卷需要额外访问控制
  - Remediation: 为承载持久化数据的 namespace 配置覆盖 PVC 消费工作负载的默认拒绝和精确允许 NetworkPolicy；RWX 卷需补充租户隔离和应用级权限控制。
- **FAIL high** `CN-37` `CN-PER-003-secret-reference` StatefulSet/cnsec-bad/postgres-bad Secret/CSI 引用检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务敏感配置应来自 Secret 或 CSI Secret Store
  - Remediation: 使用 Secret、External Secrets 或 CSI Secret Store 管理数据库口令和证书。
- **FAIL high** `CN-37` `CN-PER-003-stateful-networkpolicy` StatefulSet/cnsec-bad/postgres-bad 网络隔离检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应被 Ingress NetworkPolicy 覆盖，不能只依赖 namespace 内任意策略
  - Remediation: 为数据库/有状态服务配置默认拒绝和精确允许的 NetworkPolicy，确保 podSelector 覆盖对应 StatefulSet。
- **FAIL high** `CN-37` `CN-PER-003-tls-or-mtls` StatefulSet/cnsec-bad/postgres-bad TLS/mTLS 证据检查 (StatefulSet/cnsec-bad/postgres-bad)
  - Evidence: 有状态服务应具备 TLS Secret 或服务网格 mTLS STRICT 证据
  - Remediation: 为数据库启用 TLS 证书 Secret，或通过服务网格启用 STRICT mTLS。
- **FAIL high** `CN-38` `CN-REG-001-insecure-registry` HTTP/本地明文仓库引用检查 (_cluster)
  - Evidence: 不安全镜像引用
  - Remediation: 使用 HTTPS registry，禁用匿名/明文 HTTP registry。
- **FAIL high** `CN-38` `CN-REG-001-pull-secret` 私有仓库拉取凭据检查 (_cluster)
  - Evidence: 私有仓库 imagePullSecret 风险
  - Remediation: 为私有仓库 workload 配置 kubernetes.io/dockerconfigjson pull secret，并避免使用默认匿名拉取。
- **FAIL high** `CN-38` `CN-REG-001-registry-audit` Registry 审计异常检查 (_cluster)
  - Evidence: RegistryAuditEvent 审计事件；无 registry audit adapter 时用 Kubernetes image pull event 作为有限证据
  - Remediation: 接入 Harbor/Registry 审计日志，告警匿名拉取、删除镜像、认证失败、ImagePullBackOff 和异常批量拉取。
- **FAIL high** `CN-38` `CN-REG-001-registry-endpoint` Registry TLS/匿名/robot/audit 配置检查 (_cluster)
  - Evidence: RegistryEndpoint mock/adapter 证据；无 adapter 时用镜像引用推导有限 registry inventory
  - Remediation: 接入 Harbor/Registry API 或 mock adapter，开启 TLS、关闭匿名拉取、使用最小权限 robot account 并启用审计。
- **FAIL high** `CN-38` `CN-REG-001-secret-leak-reports` 镜像/仓库 Secret 泄露扫描检查 (_cluster)
  - Evidence: SecretReport 或 Trivy secret 扫描摘要
  - Remediation: 接入 Trivy SecretReport 或 registry secret scan，清理业务镜像中的密钥、令牌和凭据；平台组件泄露项单独复核。

### 整改优先级

| Priority | Score | Checkpoint | Rule | Severity/Status | Asset | Remediation |
|---|---:|---|---|---|---|---|
| P0 | 23 | CN-22 | CN-IMM-001-exec-rbac | critical/FAIL | _cluster | 移除普通主体的 pods/exec create/update/patch 权限；调试访问应临时授权、带审批和过期标记。 |
| P0 | 23 | CN-29 | CN-IAM-002-dangerous-rbac | critical/FAIL | RoleBinding/cnsec-bad/dangerous-app-rolebinding | 移除 *, bind/escalate/impersonate, secrets list/watch, pods/exec 等高危权限；避免绑定 system:authenticated 等宽泛主体。 |
| P0 | 20 | CN-28 | CN-IAM-001-anonymous-binding | critical/FAIL | _cluster | 删除 system:anonymous/system:unauthenticated 的 RoleBinding/ClusterRoleBinding。 |
| P0 | 20 | CN-39 | CN-PER-004-runtime-abnormal-write | critical/FAIL | Pod/cnsec-bad/postgres-bad-0 | 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。 |
| P0 | 20 | CN-39 | CN-PER-004-volume-mount-escape | critical/FAIL | Pod/cnsec-bad/web-bad | 审查容器进程和挂载路径，限制 shell，设置只读根文件系统，检查 PVC/hostPath 访问权限。 |
| P0 | 19 | CN-22 | CN-IMM-001-no-ssh-container | high/FAIL | Deployment/cnsec-bad/web-bad | 移除容器内 SSH 服务，使用审计受控的 kubectl exec、临时调试容器或节点级运维通道。 |
| P0 | 19 | CN-22 | CN-IMM-001-no-ssh-service | high/FAIL | Service/cnsec-bad/web-bad-ssh | 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。 |
| P0 | 19 | CN-22 | CN-IMM-001-rootfs-readonly | high/FAIL | Deployment/kube-system/metrics-server | 设置 securityContext.readOnlyRootFilesystem=true。 |
| P0 | 19 | CN-22 | CN-IMM-001-rootfs-readonly | high/FAIL | StatefulSet/cnsec-bad/postgres-bad | 设置 securityContext.readOnlyRootFilesystem=true。 |
| P0 | 19 | CN-22 | CN-IMM-001-rootfs-readonly | high/FAIL | Pod/cnsec-bad/db-data-debug-mounter | 设置 securityContext.readOnlyRootFilesystem=true。 |
| P0 | 19 | CN-22 | CN-IMM-001-rootfs-readonly | high/FAIL | Deployment/cnsec-bad/web-bad | 设置 securityContext.readOnlyRootFilesystem=true。 |
| P0 | 19 | CN-35 | CN-PER-001-apiserver-etcd-client-cert | high/FAIL | _cluster | 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。 |
| P0 | 19 | CN-35 | CN-PER-001-etcd-tls | high/FAIL | _cluster | 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。 |
| P0 | 19 | CN-35 | CN-PER-001-secret-encryption | high/FAIL | _cluster | 配置 Kubernetes encryption provider/KMS 加密 Secret。 |
| P1 | 16 | CN-23 | CN-IMM-002-no-privilege-escalation | high/FAIL | Pod/cnsec-bad/db-data-debug-mounter | 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。 |
| P1 | 16 | CN-23 | CN-IMM-002-no-privilege-escalation | high/FAIL | StatefulSet/cnsec-bad/postgres-bad | 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。 |
| P1 | 16 | CN-23 | CN-IMM-002-no-privilege-escalation | high/FAIL | Deployment/cnsec-bad/web-bad | 设置 allowPrivilegeEscalation=false 并 drop ALL capabilities；平台组件记录例外依据。 |
| P1 | 16 | CN-23 | CN-IMM-002-rootfs-readonly | high/FAIL | Pod/cnsec-bad/db-data-debug-mounter | 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。 |
| P1 | 16 | CN-23 | CN-IMM-002-rootfs-readonly | high/FAIL | StatefulSet/cnsec-bad/postgres-bad | 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。 |
| P1 | 16 | CN-23 | CN-IMM-002-rootfs-readonly | high/FAIL | Deployment/cnsec-bad/web-bad | 设置 securityContext.readOnlyRootFilesystem=true，并为必要写入挂载 emptyDir/PVC 到明确路径。 |

## 5. 指标赋权与符合度判定

- 计分口径: UNKNOWN 检查点不计入得分分母；Critical/High 失败项会触发符合度门禁。
- Scored Weight: `36.4`
- Unknown Weight: `0.0`

### 权重与状态

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 6 | 0/0/0 |
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 52.27 | 23 | 8/5/0 |
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
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 52.63 | 19 | 7/4/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 30.43 | 23 | 13/6/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 55.56 | 9 | 4/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 40.0 | 6 | 3/0/1 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | FAIL | 42.86 | 7 | 4/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | FAIL | 46.15 | 13 | 7/0/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 56.25 | 9 | 1/5/1 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | FAIL | 58.33 | 6 | 1/3/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | FAIL | 50.0 | 6 | 3/0/0 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | FAIL | 25.0 | 4 | 3/0/0 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | FAIL | 84.09 | 22 | 1/5/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | FAIL | 28.57 | 14 | 10/0/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | FAIL | 27.78 | 9 | 6/1/0 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | FAIL | 27.78 | 9 | 6/1/0 |
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |

## 6. 数据质量与限制

- Completeness: `100.0%`
- Freshness: `100.0%`
- Duplicate Rate: `0.0%`
- Unknown Rate: `0.93%`
- Schema Errors: `0`
- Collection Warnings: `0`
- UNKNOWN 原因样例:
  - `CN-25` 用于节点纳管的 DaemonSet 数量
  - `CN-28` Istio PeerAuthentication STRICT
- 限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。

## 7. 附录

- Schema Version: `1.0`
- Raw Snapshot Count: `4`
- Normalized Finding Count: `214`
- References: 当前报告未采集到外部引用。

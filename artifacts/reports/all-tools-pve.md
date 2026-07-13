# 云原生安全评估报告

## 1. 评估摘要

- Task ID: `pve-all-tools`
- Generated At: `2026-06-23T06:52:30.083010+00:00`
- Tools: `cloud_api_stub, cloud_native, registry_stub, smart_cloud_stub, platform`
- Overall Score: `98.74`
- Conclusion: **符合**
- Evidence Coverage: `100.0%`
- Severity Count: `high=26, info=309, low=4, medium=42`

### 工具聚合摘要

| Tool | Status | Schema | Findings | Fail/Warn/Unknown | Warnings | Raw Keys |
|---|---|---|---:|---|---:|---|
| cloud_api_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| cloud_native | ready | kubernetes-json/v1 | 346 | 3/2/0 | 5 | collected_at, kind_count, kinds, mode, object_count, rbac_matrix, resource_inventory, schema_version |
| registry_stub | stub (stub/mock) | stub/v1 | 1 | 0/0/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| smart_cloud_stub | stub (stub/mock) | stub/v1 | 4 | 0/1/0 | 0 | capabilities, collected_at, integration_contract, kind, mock_assets, mock_findings, schema_version, stub_mode |
| platform | ready | internal/v1 | 26 | 0/1/0 | 0 | integration_findings, visualization_findings |

## 2. 标书检查点覆盖情况

### 云原生三大域

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | WARN | 84.21 | 46 | 3/0/0 |
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 97.78 | 72 | 0/2/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 87 | 0/0/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | PASS | 100.0 | 20 | 0/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 10 | 0/0/0 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 5 | 0/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | PASS | 100.0 | 21 | 0/0/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 21 | 0/0/0 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | PASS | 100.0 | 6 | 0/0/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 16 | 0/0/0 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | PASS | 100.0 | 4 | 0/0/0 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 11 | 0/0/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 12 | 0/0/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | PASS | 100.0 | 9 | 0/0/0 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 6 | 0/0/0 |
### 工具集成数据处理

| Checkpoint | Domain | Weight | Status | Score | Findings | Fail/Warn/Unknown |
|---|---|---:|---:|---:|---:|---|
| INT-1 数据格式分析 | 工具集成数据处理 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| INT-2 数据格式定义 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-3 数据格式转换实现 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-4 数据标准化清洗 | 工具集成数据处理 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | PASS | 91.67 | 6 | 0/1/0 |
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

- Domain Score: `97.43`
- Scored Checkpoints: `7`
- Unknown Checkpoints: `0`

- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kyverno/kyverno-background-controller-metrics SSH 暴露检查 (Service/kyverno/kyverno-background-controller-metrics)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/trivy-system/trivy-operator SSH 暴露检查 (Service/trivy-system/trivy-operator)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kyverno/kyverno-svc-metrics SSH 暴露检查 (Service/kyverno/kyverno-svc-metrics)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kyverno/kyverno-reports-controller-metrics SSH 暴露检查 (Service/kyverno/kyverno-reports-controller-metrics)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kube-system/metrics-server SSH 暴露检查 (Service/kube-system/metrics-server)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kyverno/kyverno-cleanup-controller-metrics SSH 暴露检查 (Service/kyverno/kyverno-cleanup-controller-metrics)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kube-system/kube-dns SSH 暴露检查 (Service/kube-system/kube-dns)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/kyverno/kyverno-svc SSH 暴露检查 (Service/kyverno/kyverno-svc)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/default/kubernetes SSH 暴露检查 (Service/default/kubernetes)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
- **PASS high** `CN-22` `CN-IMM-001-no-ssh-service` Service/cnsec-good/orders-db SSH 暴露检查 (Service/cnsec-good/orders-db)
  - Evidence: Service 不应暴露 SSH
  - Remediation: 移除容器 SSH 暴露，使用 kubectl exec 审计流程或临时调试容器。
### 动态访问控制与身份安全评估

- Domain Score: `100.0`
- Scored Checkpoints: `3`
- Unknown Checkpoints: `0`

- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kube-system/kube-dns SSH Service 暴露检查 (Service/kube-system/kube-dns)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-reports-controller-metrics SSH Service 暴露检查 (Service/kyverno/kyverno-reports-controller-metrics)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/default/kubernetes SSH Service 暴露检查 (Service/default/kubernetes)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-svc SSH Service 暴露检查 (Service/kyverno/kyverno-svc)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-cleanup-controller SSH Service 暴露检查 (Service/kyverno/kyverno-cleanup-controller)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/cnsec-good/orders-db SSH Service 暴露检查 (Service/cnsec-good/orders-db)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/trivy-system/trivy-operator SSH Service 暴露检查 (Service/trivy-system/trivy-operator)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-background-controller-metrics SSH Service 暴露检查 (Service/kyverno/kyverno-background-controller-metrics)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-svc-metrics SSH Service 暴露检查 (Service/kyverno/kyverno-svc-metrics)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
- **PASS high** `CN-30` `CN-IAM-003-no-ssh-service` Service/kyverno/kyverno-cleanup-controller-metrics SSH Service 暴露检查 (Service/kyverno/kyverno-cleanup-controller-metrics)
  - Evidence: 身份安全强化要求不暴露 SSH 服务
  - Remediation: 移除 SSH Service 暴露，使用受审计的 kubectl exec/ephemeral container。
### 容器持久化安全评估

- Domain Score: `100.0`
- Scored Checkpoints: `5`
- Unknown Checkpoints: `0`

- **PASS high** `CN-35` `CN-PER-001-apiserver-etcd-client-cert` API Server 到 etcd 双向 TLS 检查 (_cluster)
  - Evidence: kube-apiserver etcd flags from static-pod-manifest
  - Remediation: 为 kube-apiserver 配置 etcd HTTPS endpoint、etcd CA、client cert 与 client key。
- **PASS high** `CN-35` `CN-PER-001-etcd-tls` etcd TLS/client-cert-auth 检查 (_cluster)
  - Evidence: etcd flags from static-pod-manifest
  - Remediation: 启用 etcd client/peer TLS、client-cert-auth、peer-client-cert-auth，并配置 client/peer CA、cert、key 文件。
- **PASS high** `CN-35` `CN-PER-001-secret-encryption` Secret 静态加密检查 (_cluster)
  - Evidence: kube-apiserver encryption-provider-config from static-pod-manifest
  - Remediation: 配置 Kubernetes encryption provider/KMS 加密 Secret。
- **PASS medium** `CN-36` `CN-PER-002-pv-reclaim-policy` PersistentVolume/_cluster/cnsec-good-local-pv PV 回收策略检查 (PersistentVolume/_cluster/cnsec-good-local-pv)
  - Evidence: PV 回收策略应避免误删关键数据
  - Remediation: 关键业务 PV 使用 Retain；Delete 策略需有自动化备份和恢复演练记录。
- **PASS medium** `CN-36` `CN-PER-002-pvc-backup-evidence` PersistentVolumeClaim/cnsec-good/orders-db-data PVC 快照/备份证据检查 (PersistentVolumeClaim/cnsec-good/orders-db-data)
  - Evidence: PVC 应有关联 VolumeSnapshot 或 namespace 级备份计划
  - Remediation: 为关键 PVC 配置 CSI VolumeSnapshot、Velero Schedule，或补充等效备份证据。
- **PASS medium** `CN-36` `CN-PER-002-pvc-storage-encryption` PersistentVolumeClaim/cnsec-good/orders-db-data PVC 存储加密继承检查 (PersistentVolumeClaim/cnsec-good/orders-db-data)
  - Evidence: PVC 应继承加密/KMS StorageClass
  - Remediation: 为 PVC 绑定加密 StorageClass，或补充底层存储默认加密证明。
- **PASS medium** `CN-36` `CN-PER-002-snapshot-backup-evidence` StorageClass/_cluster/encrypted-local 快照/备份能力检查 (StorageClass/_cluster/encrypted-local)
  - Evidence: StorageClass 应具备 CSI VolumeSnapshotClass、VolumeSnapshot 或 Velero 备份证据
  - Remediation: 部署 CSI 快照类、Velero 备份计划，或补充等效备份平台证据。
- **PASS medium** `CN-36` `CN-PER-002-storageclass-encryption` StorageClass/_cluster/encrypted-local 加密参数检查 (StorageClass/_cluster/encrypted-local)
  - Evidence: StorageClass 应声明加密/KMS 参数
  - Remediation: 为 StorageClass 配置加密参数或记录底层存储默认加密证据。
- **PASS medium** `CN-36` `CN-PER-002-storageclass-reclaim-policy` StorageClass/_cluster/encrypted-local 回收策略检查 (StorageClass/_cluster/encrypted-local)
  - Evidence: 持久化业务 StorageClass 建议使用 Retain 或记录自动删除例外
  - Remediation: 为关键数据 StorageClass 设置 reclaimPolicy=Retain，或记录 Delete 策略的备份和审批依据。
- **PASS medium** `CN-37` `CN-PER-003-backup-or-snapshot` StatefulSet/cnsec-good/orders-db 备份/快照证据检查 (StatefulSet/cnsec-good/orders-db)
  - Evidence: 有状态服务应具备绑定到 PVC/工作负载范围的 Velero Backup/Schedule 或 VolumeSnapshot 证据
  - Remediation: 为有状态服务配置覆盖对应 PVC 或工作负载 selector 的 Velero 备份计划、CSI VolumeSnapshot 或等效备份证据。

## 4. 重点风险清单

- 未发现 Critical/High 失败项。

### 整改优先级

| Priority | Score | Checkpoint | Rule | Severity/Status | Asset | Remediation |
|---|---:|---|---|---|---|---|
| P2 | 12 | CN-6 | CN-ELAS-001-hpa-present | medium/FAIL | StatefulSet/cnsec-good/orders-db | 为业务 workload StatefulSet/cnsec-good/orders-db 补充 配置 HPA；平台组件缺失时记录高可用部署或托管例外依据。 |
| P2 | 12 | CN-6 | CN-ELAS-001-pdb-present | medium/FAIL | StatefulSet/cnsec-good/orders-db | 为业务 workload StatefulSet/cnsec-good/orders-db 补充 配置 PDB；平台组件缺失时记录高可用部署或托管例外依据。 |
| P2 | 12 | CN-6 | CN-ELAS-001-workload-resilience-score | medium/FAIL | StatefulSet/cnsec-good/orders-db | 补齐 workload 的 HPA、PDB、requests/limits；当前缺口：hpa_present, pdb_present。 |
| P2 | 9 | CN-22 | CN-IMM-001-image-pinned-digest | medium/WARN | StatefulSet/cnsec-good/orders-db | 使用不可变 digest 引用镜像，至少避免 latest。 |
| P2 | 9 | CN-22 | CN-IMM-001-image-pinned-digest | medium/WARN | Deployment/cnsec-good/web-good | 使用不可变 digest 引用镜像，至少避免 latest。 |
| P3 | 6 | INT-10 | INT-SMART-001-model-auth | medium/WARN | ModelEndpoint/_cluster/mock-llm-endpoint | 真实 adapter 应检查模型服务入口鉴权、调用配额、来源限制和审计日志。 |
| P3 | 6 | INT-5 | INT-DATA-005-collection-warnings | medium/WARN | AssessmentPipeline/_cluster/pve-all-tools | 安装缺失 CRD、补齐权限，或在限制说明中记录非致命采集 warning。 |
| P3 | 6 | INT-8 | INT-API-001-public-admin | medium/WARN | CloudApiEndpoint/_cluster/https://api.example.invalid | 真实 adapter 应校验管理 API 暴露范围、来源白名单、mTLS 或专线接入。 |

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
| INT-5 数据质量评估 | 工具集成数据处理 | 0.9 | PASS | 91.67 | 6 | 0/1/0 |
| CN-6 微服务弹性能力评估 | 不可变基础设施与弹性安全评估 | 1.0 | WARN | 84.21 | 46 | 3/0/0 |
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
| CN-22 验证不可变部署原则 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 97.78 | 72 | 0/2/0 |
| CN-23 容器不可变安全管控 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 87 | 0/0/0 |
| CN-24 弹性扩缩容安全 | 不可变基础设施与弹性安全评估 | 1.0 | PASS | 100.0 | 20 | 0/0/0 |
| CN-25 弹性资源安全策略管控 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 10 | 0/0/0 |
| CN-26 弹性扩缩容行为安全防护 | 不可变基础设施与弹性安全评估 | 1.1 | PASS | 100.0 | 5 | 0/0/0 |
| CN-27 弹性资源生命周期安全治理 | 不可变基础设施与弹性安全评估 | 1.0 | PASS | 100.0 | 21 | 0/0/0 |
| CN-28 身份认证机制评估模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 21 | 0/0/0 |
| CN-29 动态访问控制评估模块 | 动态访问控制与身份安全评估 | 1.2 | PASS | 100.0 | 6 | 0/0/0 |
| CN-30 身份安全强化模块 | 动态访问控制与身份安全评估 | 1.1 | PASS | 100.0 | 16 | 0/0/0 |
| CN-35 etcd 访问控制与加密检测 | 容器持久化安全评估 | 1.2 | PASS | 100.0 | 4 | 0/0/0 |
| CN-36 持久卷 PV 安全评估 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 11 | 0/0/0 |
| CN-37 有状态应用数据安全 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 12 | 0/0/0 |
| CN-38 镜像仓库数据安全 | 容器持久化安全评估 | 1.1 | PASS | 100.0 | 9 | 0/0/0 |
| CN-39 数据持久化异常监控模块 | 容器持久化安全评估 | 1.0 | PASS | 100.0 | 6 | 0/0/0 |
| VIZ-MGMT 指标录入管理 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-WEIGHT 评估指标赋权 | 集成可视化展示 | 0.8 | PASS | 100.0 | 1 | 0/0/0 |
| VIZ-ANALYSIS 综合结果分析集成，符合度判定 | 集成可视化展示 | 0.9 | PASS | 100.0 | 1 | 0/0/0 |

## 6. 数据质量与限制

- Completeness: `100.0%`
- Freshness: `100.0%`
- Duplicate Rate: `0.0%`
- Unknown Rate: `0.0%`
- Schema Errors: `0`
- Collection Warnings: `5`
- UNKNOWN 原因样例: 无。
- 限制说明: 原型以当前采集到的 Kubernetes/工具快照为依据，托管控制面、云账号 API、镜像仓库和运行时日志的不可见资源会降低结论完整性。

## 7. 附录

- Schema Version: `1.0`
- Raw Snapshot Count: `4`
- Normalized Finding Count: `381`
- References: 当前报告未采集到外部引用。

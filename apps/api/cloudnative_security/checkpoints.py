from __future__ import annotations

from .models import Checkpoint


CLOUD_NATIVE_CHECKPOINTS: list[Checkpoint] = [
    Checkpoint("CN-6", 6, "微服务弹性能力评估", "CN-ELAS-001", "不可变基础设施与弹性安全评估", 1.0, ["弹性", "高可用", "资源约束"], ["Deployment", "StatefulSet", "HPA", "PDB", "Pod", "metrics"]),
    Checkpoint("CN-22", 22, "验证不可变部署原则", "CN-IMM-001", "不可变基础设施与弹性安全评估", 1.1, ["镜像可追溯", "最小暴露", "禁止在线修改"], ["Pod", "Service", "RBAC", "image"]),
    Checkpoint("CN-23", 23, "容器不可变安全管控", "CN-IMM-002", "不可变基础设施与弹性安全评估", 1.1, ["容器加固", "漂移控制", "废弃资源治理"], ["Pod", "Workload", "ReplicaSet", "Job", "Event"]),
    Checkpoint("CN-24", 24, "弹性扩缩容安全", "CN-ELAS-002", "不可变基础设施与弹性安全评估", 1.0, ["准入策略", "扩缩容一致性"], ["Namespace", "Kyverno", "Gatekeeper", "AdmissionPolicy", "Deployment", "HPA"]),
    Checkpoint("CN-25", 25, "弹性资源安全策略管控", "CN-ELAS-003", "不可变基础设施与弹性安全评估", 1.1, ["资源治理", "默认约束", "节点纳管"], ["ResourceQuota", "LimitRange", "PriorityClass", "Node", "DaemonSet"]),
    Checkpoint("CN-26", 26, "弹性扩缩容行为安全防护", "CN-ELAS-004", "不可变基础设施与弹性安全评估", 1.1, ["异常扩容", "滥用防护", "scale 权限"], ["HPA", "ResourceQuota", "RBAC", "Event", "AuditLog"]),
    Checkpoint("CN-27", 27, "弹性资源生命周期安全治理", "CN-ELAS-005", "不可变基础设施与弹性安全评估", 1.0, ["资源回收", "残留治理"], ["Job", "CronJob", "Pod", "PVC", "PV", "Service", "Ingress", "Namespace"]),
    Checkpoint("CN-28", 28, "身份认证机制评估模块", "CN-IAM-001", "动态访问控制与身份安全评估", 1.1, ["认证覆盖", "匿名访问", "ServiceAccount token"], ["RBAC", "ServiceAccount", "Pod", "PeerAuthentication", "APIServer"]),
    Checkpoint("CN-29", 29, "动态访问控制评估模块", "CN-IAM-002", "动态访问控制与身份安全评估", 1.2, ["授权边界", "提权路径", "动态上下文"], ["Role", "ClusterRole", "Binding", "AdmissionPolicy", "Kyverno", "Gatekeeper"]),
    Checkpoint("CN-30", 30, "身份安全强化模块", "CN-IAM-003", "动态访问控制与身份安全评估", 1.1, ["持续审计", "登录暴露", "运行时身份事件"], ["Service", "Pod", "Node", "Falco", "AuthLog", "AuditLog"]),
    Checkpoint("CN-35", 35, "etcd 访问控制与加密检测", "CN-PER-001", "容器持久化安全评估", 1.2, ["控制面加密", "etcd TLS", "Secret 静态加密"], ["StaticPod", "APIServerFlags", "EtcdFlags", "NodeCollector"]),
    Checkpoint("CN-36", 36, "持久卷 PV 安全评估", "CN-PER-002", "容器持久化安全评估", 1.0, ["存储加密", "绑定策略", "快照备份"], ["StorageClass", "PV", "PVC", "VolumeSnapshot", "Velero"]),
    Checkpoint("CN-37", 37, "有状态应用数据安全", "CN-PER-003", "容器持久化安全评估", 1.0, ["数据保护", "网络隔离", "备份", "明文凭据"], ["StatefulSet", "Deployment", "Job", "CronJob", "Pod", "PVC", "Secret", "NetworkPolicy", "Backup"]),
    Checkpoint("CN-38", 38, "镜像仓库数据安全", "CN-REG-001", "容器持久化安全评估", 1.1, ["供应链", "仓库安全", "镜像漏洞"], ["PodImage", "PullSecret", "Registry", "TrivyReport"]),
    Checkpoint("CN-39", 39, "数据持久化异常监控模块", "CN-PER-004", "容器持久化安全评估", 1.0, ["运行时异常", "敏感写入", "PVC 异常访问"], ["Falco", "AuditLog", "Event", "PodVolumeMount"]),
]


INTEGRATION_CHECKPOINTS: list[Checkpoint] = [
    Checkpoint("INT-1", 1, "数据格式分析", "INT-DATA-001", "工具集成数据处理", 0.8, ["raw snapshot", "格式识别"], ["RawSnapshot"]),
    Checkpoint("INT-2", 2, "数据格式定义", "INT-DATA-002", "工具集成数据处理", 0.9, ["统一 schema", "Finding 模型"], ["Finding", "Asset", "Report"]),
    Checkpoint("INT-3", 3, "数据格式转换实现", "INT-DATA-003", "工具集成数据处理", 0.9, ["normalize", "adapter output"], ["AdapterOutput", "Finding"]),
    Checkpoint("INT-4", 4, "数据标准化清洗", "INT-DATA-004", "工具集成数据处理", 0.9, ["去重", "脱敏", "严重度归一"], ["Finding"]),
    Checkpoint("INT-5", 5, "数据质量评估", "INT-DATA-005", "工具集成数据处理", 0.9, ["completeness", "unknown rate", "duplicate rate"], ["DataQuality"]),
    Checkpoint("INT-6", 6, "数据格式优化", "INT-DATA-006", "工具集成数据处理", 0.7, ["索引", "扁平 summary", "schema version"], ["SQLite", "ReportSummary"]),
    Checkpoint("INT-7", 7, "工具集成框架构建", "INT-FRAME-001", "工具集成数据处理", 1.0, ["adapter registry", "healthcheck", "错误隔离"], ["AdapterRegistry"]),
    Checkpoint("INT-8", 8, "云上 API 安全评估工具接入适配", "INT-API-001", "工具集成数据处理", 0.8, ["stub adapter", "统一 Finding"], ["CloudApiSecurityAdapterStub"]),
    Checkpoint("INT-9", 9, "云原生安全评估工具接入适配", "INT-CN-001", "工具集成数据处理", 1.0, ["collector", "rules", "evidence"], ["CloudNativeAdapter"]),
    Checkpoint("INT-10", 10, "智算云安全评估工具接入适配", "INT-SMART-001", "工具集成数据处理", 0.8, ["stub adapter", "统一 Finding"], ["SmartCloudSecurityAdapterStub"]),
    Checkpoint("INT-11", 11, "调用参数标准化", "INT-REQ-001", "工具集成数据处理", 0.8, ["AssessmentRequest", "profile", "options"], ["AssessmentRequest"]),
    Checkpoint("INT-12", 12, "调用流程协调", "INT-ORCH-001", "工具集成数据处理", 1.0, ["orchestrator", "任务状态", "错误处理"], ["AssessmentOrchestrator"]),
    Checkpoint("INT-13", 13, "输出格式归一化", "INT-NORM-001", "工具集成数据处理", 0.9, ["Finding only", "工具解耦"], ["NormalizationPipeline"]),
    Checkpoint("INT-14", 14, "结果汇总整合", "INT-AGG-001", "工具集成数据处理", 1.0, ["overall score", "tool/domain/checkpoint summary"], ["Aggregator"]),
]


VISUALIZATION_CHECKPOINTS: list[Checkpoint] = [
    Checkpoint("VIZ-MGMT", 1501, "指标录入管理", "VIZ-IND-001", "集成可视化展示", 0.8, ["检查点 CRUD", "规则启用状态", "适用范围"], ["Dashboard", "Checkpoint API", "SQLite"]),
    Checkpoint("VIZ-WEIGHT", 1502, "评估指标赋权", "VIZ-WGT-001", "集成可视化展示", 0.8, ["权重调整", "重新计算"], ["MetricWeights", "Report Recalculate API"]),
    Checkpoint("VIZ-ANALYSIS", 1503, "综合结果分析集成，符合度判定", "VIZ-ANA-001", "集成可视化展示", 0.9, ["符合度", "风险分布", "证据覆盖"], ["AssessmentReport", "Dashboard"]),
    Checkpoint("VIZ-16", 16, "多工具安全态势总览", "VIZ-OVR-001", "集成可视化展示", 1.0, ["总分", "严重度分布", "工具态势", "数据质量"], ["OverviewPage"]),
    Checkpoint("VIZ-17", 17, "API 工具结果详览", "VIZ-API-001", "集成可视化展示", 0.8, ["API stub", "参数", "mock 证据"], ["ApiStubPage"]),
    Checkpoint("VIZ-18", 18, "云原生工具结果详览", "VIZ-CN-001", "集成可视化展示", 1.0, ["三大域", "15 检查点", "证据 drill-down"], ["CloudNativePage"]),
    Checkpoint("VIZ-19", 19, "智算云工具结果详览", "VIZ-SMART-001", "集成可视化展示", 0.8, ["智算云 stub", "未来 adapter 插槽"], ["SmartCloudPage"]),
    Checkpoint("VIZ-20", 20, "数据筛选交互", "VIZ-FLT-001", "集成可视化展示", 0.9, ["tool", "checkpoint", "severity", "status", "namespace", "kind", "keyword"], ["FindingFilterStore"]),
    Checkpoint("VIZ-21", 21, "结果交互查询", "VIZ-DRILL-001", "集成可视化展示", 0.9, ["finding 详情", "资产定位", "证据", "整改建议"], ["FindingDetail"]),
]


ASSESSMENT_CHECKPOINTS = [*INTEGRATION_CHECKPOINTS, *VISUALIZATION_CHECKPOINTS, *CLOUD_NATIVE_CHECKPOINTS]


CHECKPOINT_BY_ID = {checkpoint.id: checkpoint for checkpoint in ASSESSMENT_CHECKPOINTS}

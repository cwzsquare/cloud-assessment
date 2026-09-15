# 非异构章节严格覆盖核对

## 当前包的正确口径

当前目录新增 13 张逐功能截图，对应 `/tmp/图-待调整.docx` 中的 image1–image13。每张图均来自真实仪表盘页面或已验证的 SmartCloud 资源链路场景，并已按功能区域绘制红框。

## 已覆盖功能

- 多源数据采集、来源清单、采集运行记录
- 清洗动作、缺失值策略、非法 IP / 端口异常记录
- 指纹、去重和关系构建步骤
- 字段映射、目标格式、处理配置
- 14 步数据处理流水线
- 内置、正则、SQL、Python handler 质量规则及 PASS / FAIL / UNKNOWN
- entity_id、IP、端口、时间戳 exact 条件
- 服务名 fuzzy、事件描述 semantic 匹配方式
- MATCHED / UNKNOWN / AMBIGUOUS 跨源关联组和关联图谱
- 质量血缘、异常引用、根因 code、影响记录和来源
- 缺失、错误、重复、AI 标签均衡四项质量指标
- 数据冲突候选值、选中来源、处理原因
- 真实 finding 详情、风险分析、发现依据和处理建议
- 对象存储、分布式文件系统、计算节点、GPU、调度平台、结果回传链路

## 截图与条款对应

1. `28.1.1-01-multisource-collection.png`：可观测性数据采集第 1 项，多源采集与运行。
2. `28.1.1-02-cleaning-anomalies.png`：可观测性数据采集第 1 项，缺失和异常清洗。
3. `28.1.1-03-deduplication.png`：可观测性数据采集第 1 项，去重处理。
4. `28.1.2-01-field-mapping.png`：可观测性数据采集第 2 项，字段映射。
5. `28.1.2-02-format-standardization.png`：可观测性数据采集第 2 项，目标格式和配置。
6. `28.1.2-03-processing-pipeline.png`：可观测性数据采集第 2 项，处理流水线。
7. `28.1.3-01-smartcloud-infrastructure.png`：可观测性数据采集第 3 项，智算云基础设施链路。
8. `28.2.1-01-quality-rules-custom.png`：多源数据质量第 1 项，质量规则、自定义类型和通过率。
9. `28.2.2-01-cross-source-association.png`：多源数据质量第 2 项，关联条件、匹配方式和图谱。
10. `28.2.2-02-lineage-dag.png`：多源数据质量第 2、3 项，质量血缘和根因下钻。
11. `28.2.3-01-quality-metrics-root-causes.png`：多源数据质量第 3 项，四项指标和根因统计。
12. `28.2.3-02-quality-conflicts.png`：多源数据质量第 2 项，跨源冲突候选值。
13. `28.2.3-03-finding-detail.png`：多源数据质量第 3 项，结果详情下钻。

## 数据与可见边界

- `structured-gap-multisource` 截图使用仓库 fixture 任务，包含 kubernetes 和 observability 两来源，页面数据来自真实处理结果和持久化 dashboard-data。
- `pve-live-20260910b` 截图使用真实评估任务的来源和 finding 页面交互。
- SmartCloud 截图展示已验证的资源链路场景；当前普通结构化页的智算云 stub 不作为第 3 项证据。
- 浏览器截图采用独立页面会话并只保留目标面板，避免超长页面整页截图的 Chromium 协议超时；未拼接虚假业务数据。
- 上一轮 13 个图片节点通过 `officecli batch` 回写到 `图-待调整-新版.docx`；本轮重制仅更新 `28*.png` 并保存 `unannotated/` 无框版，未回写 Word。当前红框目标以同名 `.md` 为准。

# 最新版投标截图准备包

本目录提供 `/tmp/图-待调整.docx` 的新版截图包及通过 `officecli` 回写的文档副本。新版共 13 张结构化数据功能截图，逐一对应文档中的 13 个图片位置；截图来自真实仪表盘页面或已验证的 SmartCloud 资源链路场景，均以 2000×1775 PNG 输出。

## 截图口径

- 每张图只对应一个功能主题，画面顶部给出功能标题和数据口径。
- 红框已绘制在对应功能区域；红框只标记功能点，不作为数据内容。
- 浏览器截图使用独立真实页面会话，聚焦保留目标面板，避免超长页面整页捕获导致失败；页面内容仍来自真实 API / 持久化任务结果。
- `structured-gap-multisource` 用于清洗、去重、映射、质量、关联、血缘和冲突截图，包含 kubernetes 与 observability 两个来源。
- `pve-live-20260910b` 用于真实来源采集和问题详情交互截图。
- 智算云第 3 项使用已验证的资源链路场景图，展示对象存储、分布式文件系统、计算节点、GPU、调度平台和结果回传。

## 文件清单

| 文档图片位置 | 截图文件 | 功能对应 |
| --- | --- | --- |
| image1 | `28.1.1-01-multisource-collection.png` | 多源采集与运行记录 |
| image2 | `28.1.1-02-cleaning-anomalies.png` | 清洗动作与异常记录 |
| image3 | `28.1.1-03-deduplication.png` | 去重与处理步骤 |
| image4 | `28.1.2-01-field-mapping.png` | 字段映射 |
| image5 | `28.1.2-02-format-standardization.png` | 格式标准化与质量配置 |
| image6 | `28.1.2-03-processing-pipeline.png` | 数据处理流水线 |
| image7 | `28.1.3-01-smartcloud-infrastructure.png` | 智算云基础设施资源链路 |
| image8 | `28.2.1-01-quality-rules-custom.png` | 质量规则与自定义校验 |
| image9 | `28.2.2-01-cross-source-association.png` | 跨源关联条件与匹配图谱 |
| image10 | `28.2.2-02-lineage-dag.png` | 质量血缘与根因下钻 |
| image11 | `28.2.3-01-quality-metrics-root-causes.png` | 质量指标与根因统计 |
| image12 | `28.2.3-02-quality-conflicts.png` | 数据冲突与候选值 |
| image13 | `28.2.3-03-finding-detail.png` | 问题详情与处理建议 |

每张图均配有同名 `.md`，记录条款映射、红框目标、数据来源和可见边界。

## 文档输出

- 新版文档：`图-待调整-新版.docx`
- 新版文档已通过 `officecli batch` 更新 13 个图片节点，并用 `officecli query` 核对 13 个图片引用和替换后的 alt 文本。
- `officecli validate` 报告的 8 项 numbering/styles schema warning 来自原文档既有 OOXML 结构；图片批处理 13/13 成功，未出现图片节点写入失败。

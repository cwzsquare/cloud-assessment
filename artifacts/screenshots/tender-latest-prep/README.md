# 最新版投标截图准备包

本目录提供 `/tmp/图-待调整.docx` 对应的 13 张功能截图。本轮已重制 `28*.png` 红框版；10 张按真实页面面板重新放大渲染，采集、智算云和问题详情 3 张复用无框原图裁切。输出按内容高度自适应，不再固定为 2000×1775。

## 截图口径

- 每张图只对应一个功能主题，移除无关导航和大面积留白。
- 表格重新渲染使用 18px 正文、24px 标题和 2 倍像素密度；复用原图的 3 张采用裁切与等比放大，不声称增加原始细节。
- 红框为细线，贴合目标记录、配置或图谱；无框版保存在 `unannotated/` 下，文件名与红框版一一对应。
- 页面聚焦和排版只作用于截图会话，不修改业务数据或应用源文件。关联展示前 4 条、冲突展示前 3 条，并在图内注明总数；流水线省略长 JSON 摘要列，保留全部 14 步及状态、计数和耗时。
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

- `图-待调整-新版.docx` 为上一轮输出，本轮只更新 PNG，尚未回写本轮红框图。
- 当前应使用目录中的 `28*.png`；需要重新标注时使用 `unannotated/` 同名文件。
- `officecli validate` 报告的 8 项 numbering/styles schema warning 来自原文档既有 OOXML 结构；图片批处理 13/13 成功，未出现图片节点写入失败。

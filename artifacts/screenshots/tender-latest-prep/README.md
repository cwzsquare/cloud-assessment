# 最新版投标截图准备包

本目录提供最新版 DOCX「软件功能（提供截图）」对应的干净截图，以及每张图的说明文字和红框描述清单。当前包共 12 张截图，其中 9 张属于非异构章节、3 张属于异构算力智能调度章节。截图均未绘制红框；红框由接替模型按各图片的描述列表执行。

## 严格覆盖口径

当前包定位为页面功能概览，不宣称已完整证明最新版表格的每个细项。非异构章节的 9 张图覆盖已有前端可见的来源、运行、流水线、映射、清洗、质量规则、冲突、血缘、资产关系、结果下钻和智算云基础设施链路；清洗配置与异常统计、跨源关联条件与匹配方式、质量指标明细与根因节点下钻仍需单独补图。

本仓库当前前端没有上述三类独立配置 / 下钻面板。为保持“其余截图来自正常前端”的口径，本次不使用临时拼接页面冒充正式功能；具体缺口和后续截图验收项见 `coverage-gaps.md`。

## 文件清单

| 截图 | 主要对应条款 |
| --- | --- |
| `latest-heterogeneous-scheduling-template.png` | 异构算力智能调度系统第 1 项 |
| `latest-tenant-quota-and-validation.png` | 异构算力智能调度系统第 2 项 |
| `latest-ai-workloads-and-services.png` | 异构算力智能调度系统第 3 项 |
| `latest-real-30.3-sources-and-runs.png` | 可观测性数据采集工具第 1 项 |
| `latest-real-30.3-processing-pipeline.png` | 可观测性数据采集工具第 1、2 项 |
| `latest-real-30.3-field-mapping.png` | 可观测性数据采集工具第 2 项 |
| `latest-real-30.3-cleaning-actions.png` | 可观测性数据采集工具第 1、2 项 |
| `latest-smartcloud-infrastructure-flow.png` | 可观测性数据采集工具第 3 项 |
| `latest-real-30.3-quality-rules.png` | 多源数据质量管理与验证工具第 1 项 |
| `latest-real-30.3-quality-and-conflicts.png` | 多源数据质量管理与验证工具第 2、3 项 |
| `latest-real-30.3-lineage-and-asset-graph.png` | 多源数据质量管理与验证工具第 2、3 项 |
| `latest-real-30.4-finding-detail.png` | 多源数据质量管理与验证工具第 3 项的结果下钻展示 |
| 每张图片同名 `.md` | 图片说明、数据口径、红框目标 |

3 张异构章节截图（`latest-heterogeneous-scheduling-template.png`、`latest-tenant-quota-and-validation.png`、`latest-ai-workloads-and-services.png`）采用场景化输入以展示最新版条款要求；另外 9 张非异构截图来自实际云原生清单适配器运行后的前端展示，其中 `latest-smartcloud-infrastructure-flow.png` 明确属于可观测性数据采集工具第 3 项，不属于异构章节。该口径只写在本目录说明中，不写入对应截图画面。

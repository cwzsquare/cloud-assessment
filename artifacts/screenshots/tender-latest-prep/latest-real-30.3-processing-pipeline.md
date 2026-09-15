# 处理流水线步骤详情

- 文件：`latest-real-30.3-processing-pipeline.png`
- 截图状态：干净截图，未加红框；红框由接替模型执行。
- 对应最新版 DOCX：软件功能（提供截图）—可观测性数据采集工具第 1、2 项。
- 前端页面：实际 `#structured` 数据处理页面。

## 说明文字

页面以步骤表展示从输入加载、结构解析、资源归一化、字段映射、数据清洗、指纹处理、去重、关系构建到质量评估、结果汇总和持久化的处理链路。每一步均保留状态、输入输出数量、丢弃数量、告警、错误、耗时和摘要。

## 红框描述列表

1. 框选「处理流水线步骤详情」标题及表头，覆盖步骤、状态、输入、输出、丢弃、警告、错误、耗时、摘要字段。
2. 框选 `input_loading`、`structure_parsing`、`resource_normalization` 三行，证明原始输入经过解析和资源归一化。
3. 框选 `field_mapping` 与 `data_cleaning` 两行，覆盖字段映射、清洗状态及摘要中的 `mapped_fields` / `cleaning_actions`。
4. 框选 `fingerprint`、`deduplication`、`relationship_building` 三行，覆盖指纹、重复数据去除和关系构建步骤。
5. 框选 `data_quality`、`finding_aggregation`、`checkpoint_scoring`、`report_building`、`persistence` 行，证明质量评估、结果汇总、报告构建和持久化均有运行记录。

## 标注边界

不要只框选某一行的 `SUCCESS`；应将步骤名称和右侧摘要一起纳入红框，体现处理动作及其结果。

## 数据口径

该图由实际云原生清单适配器运行结果经前端 `#structured` 页面展示生成，任务为 `tender-latest-cloudnative`。

# 数据质量与数据冲突

- 文件：`latest-real-30.3-quality-and-conflicts.png`
- 截图状态：干净截图，未加红框；红框由接替模型执行。
- 对应最新版 DOCX：软件功能（提供截图）—多源数据质量管理与验证工具第 2、3 项。
- 前端页面：实际 `#structured` 数据处理页面。

## 说明文字

页面左侧展示同一 Deployment 的 `spec` 字段冲突及两个候选值，右侧展示完整质量规则结果。冲突记录保留对象键、字段、候选值、来源引用和确定性选择原因，质量表同时呈现 PASS、FAIL、UNKNOWN 状态。

## 红框描述列表

1. 框选「数据冲突」标题、对象 `Deployment/ai-prod/inference-gateway` 和字段 `spec`。
2. 框选冲突候选值区域，至少覆盖 `replicas: 3` 与 `replicas: 5` 两个版本，以及两个镜像 / 资源规格差异。
3. 框选候选值中的 `source_reference: record:0`、`record:1` 和 `same precedence rank; selected deterministically`，证明冲突保留来源和选择原因。
4. 框选右侧「数据质量规则」表的全部规则行，覆盖 `DQ-COMPLETE`、`DQ-UNIQUE`、`DQ-REFERENCE`、`DQ-TIME` 等状态。
5. 可将下方「数据血缘」统计卡和「资产关系图」作为冲突对象关联结果的辅助框选。

## 标注边界

不要把左侧整块长 JSON 当作唯一框选目标；应优先框住对象 / 字段、两组候选值和选择原因三个证据区域。
## 覆盖边界

本图证明冲突候选值、来源引用和确定性选择原因可见；不展示时间戳 / IP / 端口 / 实体 ID 关联条件，也不展示模糊或语义匹配配置，因此不能作为跨源关联能力的完整证明。

## 数据口径

该图由实际云原生清单适配器对两份同键资源清单执行归一化与去重后，经前端 `#structured` 页面展示生成，任务为 `tender-latest-conflict`。

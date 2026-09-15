# 字段映射

- 文件：`latest-real-30.3-field-mapping.png`
- 截图状态：干净截图，未加红框；红框由接替模型执行。
- 对应最新版 DOCX：软件功能（提供截图）—可观测性数据采集工具第 2 项。
- 前端页面：实际 `#structured` 数据处理页面。

## 说明文字

页面展示 Kubernetes 来源字段向统一模型字段的映射关系，明确给出 `kind`、`metadata.name`、`metadata.namespace` 到 `normalized.kind`、`normalized.name`、`normalized.namespace` 的目标字段。

## 红框描述列表

1. 框选「字段映射」标题及表头「来源模式、来源字段、目标字段」。
2. 框选 `kubernetes / kind → normalized.kind` 行。
3. 框选 `kubernetes / metadata.name → normalized.name` 行。
4. 框选 `kubernetes / metadata.namespace → normalized.namespace` 行。
5. 可将右侧「清洗动作」表作为同屏辅助框选，但不要把空状态误标为已有清洗动作。

## 标注边界

红框优先落在三条映射记录的来源字段和目标字段，不要覆盖下方数据血缘图；数据质量表仅作状态辅助。
## 覆盖边界

本图证明来源字段到统一模型字段的映射结果可见；不展示按数据类型、质量规则、目标格式配置完整处理流程的独立配置界面，因此不能作为该配置细项的完整证明。

## 数据口径

该图由实际云原生清单适配器运行结果经前端 `#structured` 页面展示生成，任务为 `tender-latest-cloudnative`。

# AI 任务与模型服务

- 文件：`latest-ai-workloads-and-services.png`
- 截图状态：干净截图，未加红框；红框由接替模型执行。
- 对应最新版 DOCX：软件功能（提供截图）—异构算力智能调度系统第 3 项。

## 说明文字

页面统一呈现 AIJob 任务列表和 AIService 模型服务状态，任务表提供运行状态、GPU 资源、运行时长、提交时间以及查看详情、重启、删除等运维操作。下方模型服务卡片补充 READY 和 DEGRADED 状态。

## 红框描述列表

1. 框选顶部标题「AI 任务与模型服务」及说明文字，证明页面同时覆盖 AIJob 和 AIService。
2. 框选「AIJob 任务列表」表头和任务行，覆盖任务名称、租户 / Namespace、运行状态、GPU、运行时长、提交时间和操作列。
3. 框选 `llm-finetune-118` 与 `train-vision-042` 行的「运行中」状态及 GPU 资源，证明任务运行状态可查看。
4. 框选 `embedding-refresh-031` 行的「排队中」与「删除」操作，以及 `rl-policy-eval-007` 行的「异常」与「重启」操作，证明异常任务可识别并可执行操作。
5. 框选「AIService 模型服务」区域，覆盖 `llm-gateway-prod`、`vision-inference`、`embedding-service` 及 READY / DEGRADED 状态。

## 标注边界

不要只框选顶部数量卡片；数量卡片只能作为概览，主要红框应覆盖任务明细和模型服务状态。

## 数据口径

本页为按条款组织的场景化输入，用于提供 AIJob / AIService 详情画面；后续红框不改变页面文字。

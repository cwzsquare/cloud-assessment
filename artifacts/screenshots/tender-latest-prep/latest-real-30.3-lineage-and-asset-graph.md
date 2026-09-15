# 数据血缘与资产关系图

- 文件：`latest-real-30.3-lineage-and-asset-graph.png`
- 截图状态：干净截图，未加红框；红框由接替模型执行。
- 对应最新版 DOCX：软件功能（提供截图）—多源数据质量管理与验证工具第 2、3 项。
- 前端页面：实际 `#structured` 数据处理页面。

## 说明文字

页面并列展示数据血缘统计、血缘节点关系图和资产关系图。左侧图谱以规范化资产、问题和评估任务为节点，右侧图谱按资源类型展示 Namespace、Deployment、Service 等资产，支持按类型筛选和名称搜索。

## 红框描述列表

1. 框选「数据血缘」标题及统计卡，覆盖节点 `146`、关系 `202`、可追溯对象 `16`。
2. 框选左侧血缘图的第一组节点，包括 `v1beta1.metrics.k8s.io`、`tender-latest-cloudnative`、`static-dashboard` 和 `web-good`。
3. 框选左侧图中从规范化资产到 finding 的连线区域，证明页面提供 DAG 式关联关系展示。
4. 框选右侧「资产关系图」标题、类型筛选、名称搜索和「恢复全部」控件。
5. 框选右侧资源节点区域，覆盖 APIService、Deployment、Namespace、NetworkPolicy、PersistentVolume 和 ResourceQuota 等可见类型。

## 标注边界

不需要为每条虚线单独加框；以图谱整体、统计卡和关键节点组为红框目标，避免遮挡节点文字。
## 覆盖边界

本图证明血缘 DAG 和资产关系图可见；不展示缺失 / 错误 / 重复 / AI 标签均衡的完整指标明细，也不提供质量异常到根因节点的专用下钻。

## 数据口径

该图由实际云原生清单适配器运行结果经前端 `#structured` 页面展示生成，任务为 `tender-latest-cloudnative`。

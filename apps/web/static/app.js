(function () {
  var state = {
    tasks: [],
    targets: [],
    taskId: "",
    report: null,
    findings: [],
    checkpoints: [],
    rawSnapshots: [],
    rbacMatrix: null,
    taskEvents: [],
    selectedFinding: null,
    filters: { tool_id: "", domain: "", severity: "", status: "", namespace: "", kind: "", name: "", keyword: "" },
    rbacFilters: { subject: "", resource: "", verb: "", scope: "", dangerous_only: true },
  };

  var $ = function (id) { return document.getElementById(id); };
  var api = function (path) { return fetch(path).then(function (res) { if (!res.ok) throw new Error(path + " " + res.status); return res.json(); }); };
  var text = function (value, fallback) { return value === undefined || value === null || value === "" ? (fallback || "--") : String(value); };
  var safeJson = function (value, fallback) {
    if (!value) return fallback;
    if (typeof value !== "string") return value;
    try { return JSON.parse(value); } catch (_) { return fallback; }
  };
  var assetOf = function (finding) {
    var asset = safeJson(finding.asset_json, finding.asset || null);
    if (!asset) return { label: "_cluster", namespace: "", kind: "" };
    return { label: [asset.kind, asset.namespace || "_cluster", asset.name].filter(Boolean).join("/"), namespace: asset.namespace || "", kind: asset.kind || "", name: asset.name || "" };
  };

  var cloudNativePresentation = {
    "CN-6": { module: "不可变基础设施与弹性安全评估", name: "微服务弹性能力评估", title: "服务在压力或故障时仍能稳定运行", analysis: "检查服务在流量突增、实例故障或自动扩缩容时，是否具备减少故障扩散和拒绝服务影响的保护能力。" },
    "CN-22": { module: "不可变基础设施与弹性安全评估", name: "验证不可变部署原则", title: "应用发布后不应被在线修改", analysis: "检查发布后的应用是否可能被远程登录、运行中改写文件或使用过大的容器操作权限绕过发布流程。" },
    "CN-23": { module: "不可变基础设施与弹性安全评估", name: "容器不可变安全管控", title: "容器应保持受控且不可随意变更", analysis: "检查容器是否以较低权限运行、限制在线写入和提权，并能发现应用配置或运行状态的异常变化。" },
    "CN-24": { module: "不可变基础设施与弹性安全评估", name: "弹性扩缩容安全", title: "扩缩容时安全策略应保持一致", analysis: "检查应用新增实例或版本变更时，安全准入和运行约束是否仍然生效，避免新实例绕过既有安全要求。" },
    "CN-25": { module: "不可变基础设施与弹性安全评估", name: "弹性资源安全策略管控", title: "新增资源应自动获得安全限制", analysis: "检查资源数量、计算使用和节点上的工作负载是否有明确边界，避免资源争抢、失控扩张或新节点未纳入安全管理。" },
    "CN-26": { module: "不可变基础设施与弹性安全评估", name: "弹性扩缩容行为安全防护", title: "扩缩容操作应经过授权并可追溯", analysis: "检查谁可以调整实例数量、是否存在异常扩容行为，以及相关操作是否有事件或审计记录可供追查。" },
    "CN-27": { module: "不可变基础设施与弹性安全评估", name: "弹性资源生命周期安全治理", title: "临时资源应按规则回收", analysis: "检查临时任务、实例、存储和访问入口是否在使用结束后及时回收，避免遗留资源继续暴露或占用数据。" },
    "CN-28": { module: "动态访问控制与身份安全评估", name: "身份认证机制评估模块", title: "访问云原生资源前应完成身份认证", analysis: "检查访问者和服务身份是否经过可靠认证，是否存在匿名访问、未保护的服务间通信或默认身份配置风险。" },
    "CN-29": { module: "动态访问控制与身份安全评估", name: "动态访问控制评估模块", title: "不同账号只能访问被授权的资源", analysis: "检查账号、服务和角色之间的访问边界，确认高风险权限不会被无关主体继承，并且临时授权能够按时失效。" },
    "CN-30": { module: "动态访问控制与身份安全评估", name: "身份安全强化模块", title: "登录与运行身份需要持续保护", analysis: "检查远程登录入口、容器身份和身份相关事件，及时识别暴力尝试、异常操作和缺少审计记录的情况。" },
    "CN-35": { module: "容器持久化安全评估", name: "etcd 访问控制与加密检测", title: "控制面敏感数据应受访问控制和加密保护", analysis: "检查集群控制面保存的配置和敏感信息是否限制访问，并在传输和存储过程中得到加密保护。" },
    "CN-36": { module: "容器持久化安全评估", name: "持久卷PV安全评估", title: "持久卷应具备加密、备份和恢复保障", analysis: "检查持久化存储的加密、共享范围、回收策略以及快照和备份能力，降低数据误删、泄露或无法恢复的风险。" },
    "CN-37": { module: "容器持久化安全评估", name: "有状态应用数据安全", title: "有状态应用数据应避免泄露和误操作", analysis: "检查数据库等有状态应用的数据访问隔离、敏感配置保护、传输加密和备份覆盖情况。" },
    "CN-38": { module: "容器持久化安全评估", name: "镜像仓库数据安全", title: "镜像仓库数据应受保护并可审计", analysis: "检查镜像存储和传输保护、镜像来源与敏感信息泄露情况，并确认重要账户操作能够被审计。" },
    "CN-39": { module: "容器持久化安全评估", name: "数据持久化异常监控模块", title: "数据持久化异常应被及时发现", analysis: "检查数据目录、存储卷和运行时事件，识别异常读写、越权挂载或可能导致数据泄露的行为。" },
  };

  var cloudNativeModules = [
    "不可变基础设施与弹性安全评估",
    "动态访问控制与身份安全评估",
    "容器持久化安全评估",
  ];

  function isCloudNativeModule(value) {
    return cloudNativeModules.indexOf(value) >= 0;
  }

  function checkpointInfo(checkpointId) {
    var presentation = cloudNativePresentation[checkpointId];
    if (presentation) return presentation;
    var checkpoint = state.checkpoints.find(function (item) { return item.id === checkpointId; });
    var fallbackName = /^CN-/.test(checkpointId || "") ? "云原生安全检查项" : (checkpoint && checkpoint.name) || checkpointId || "未标记检查项";
    return checkpoint ? { module: checkpoint.domain || "", name: fallbackName, title: fallbackName, analysis: "该检查项用于补充评估结果。" } : { module: "", name: fallbackName, title: /^CN-/.test(checkpointId || "") ? "云原生安全问题" : fallbackName, analysis: "该问题暂未关联到已登记的检查项。" };
  }

  function checkpointLabel(checkpointId) {
    var info = checkpointInfo(checkpointId);
    return info.module ? info.module + " · " + info.name : info.name;
  }

  function userAssetLabel(asset) {
    return asset.name ? (asset.namespace ? asset.namespace + " / " : "") + asset.name : "整个评估范围";
  }

  function checkpointRiskTitle(checkpointId, assetName) {
    var info = cloudNativePresentation[checkpointId];
    return info ? info.title + (assetName ? "（" + assetName + "）" : "") : "";
  }

  function findingTitle(finding) {
    var asset = assetOf(finding);
    return checkpointRiskTitle(finding.checkpoint_id, asset.name) || text(finding.title);
  }

  function findingAnalysis(finding) {
    var info = checkpointInfo(finding.checkpoint_id);
    return info.analysis + " 当前评估对象为“" + userAssetLabel(assetOf(finding)) + "”，结果为“" + statusLabel(finding.status) + "”。";
  }

  function setRoute(route) {
    route = route || "overview";
    var validRoutes = ["overview", "findings", "observability", "report", "targets", "cloudnative", "api", "smart", "registry", "metrics"];
    if (validRoutes.indexOf(route) < 0) route = "overview";
    document.querySelectorAll(".tab").forEach(function (tab) { tab.classList.toggle("active", tab.dataset.route === route); });
    document.querySelectorAll(".view").forEach(function (view) { view.classList.toggle("active", view.id === route); });
    var secondaryRoutes = ["targets", "cloudnative", "api", "smart", "registry", "metrics"];
    var secondary = document.querySelector(".nav-secondary");
    if (secondary) secondary.open = secondaryRoutes.indexOf(route) >= 0;
    if (location.hash !== "#" + route) location.hash = route;
  }

  function normalizeTasks(payload) {
    var list = Array.isArray(payload) ? payload : (payload && (payload.items || payload.tasks || payload.assessments)) || [];
    return list.map(function (item) {
      if (typeof item === "string") return { id: item, status: "" };
      return { id: item.id || item.task_id || item.taskId, status: item.status || "", profile: item.profile || "", created_at: item.created_at || item.generated_at || "" };
    }).filter(function (item) { return item.id; });
  }

  function discoverTasks() {
    return api("/api/assessments").then(normalizeTasks).catch(function () {
      return api("/api/findings").then(function (findings) {
        var ids = {};
        (findings || []).forEach(function (f) { if (f.task_id) ids[f.task_id] = true; });
        return Object.keys(ids).map(function (id) { return { id: id, status: "discovered" }; });
      }).catch(function () { return []; });
    });
  }

  function loadTask(taskId) {
    state.taskId = taskId;
    var query = "?task_id=" + encodeURIComponent(taskId);
    return api("/api/dashboard-data" + query).then(function (data) {
      state.checkpoints = data.checkpoints || [];
      state.findings = data.findings || [];
      state.report = data.report || null;
      state.rawSnapshots = data.raw_snapshots || [];
      state.rbacMatrix = data.rbac_matrix || null;
      state.taskEvents = data.task_events || [];
      if (state.report && state.report.findings && !state.findings.length) state.findings = state.report.findings;
      renderAll();
    });
  }

  function loadTargets() {
    return api("/api/targets").then(function (targets) {
      state.targets = targets || [];
      renderTargets();
    }).catch(function () {
      state.targets = [];
      renderTargets();
    });
  }

  function summary() {
    if (state.report && state.report.summary) return state.report.summary;
    if (state.report && state.report.report && state.report.report.summary) return state.report.report.summary;
    var status = countBy(state.findings, "status");
    var severity = countBy(state.findings, "severity");
    return { finding_total: state.findings.length, checkpoint_total: state.checkpoints.length, status_count: status, severity_count: severity };
  }

  function checkpointScores() {
    var scores = state.report && (state.report.checkpoint_scores || (state.report.report && state.report.report.checkpoint_scores));
    if (scores && scores.length) return scores;
    var byId = {};
    state.findings.forEach(function (f) {
      var id = f.checkpoint_id || "UNKNOWN";
      byId[id] = byId[id] || { checkpoint_id: id, status: "PASS", score: 100, finding_count: 0, failed_count: 0, warn_count: 0, unknown_count: 0 };
      byId[id].finding_count += 1;
      if (f.status === "FAIL") byId[id].failed_count += 1;
      if (f.status === "WARN") byId[id].warn_count += 1;
      if (f.status === "UNKNOWN") byId[id].unknown_count += 1;
      if (f.status === "FAIL") byId[id].status = "FAIL";
      else if (f.status === "WARN" && byId[id].status !== "FAIL") byId[id].status = "WARN";
    });
    return state.checkpoints.map(function (cp) { return Object.assign({}, cp, byId[cp.id] || { checkpoint_id: cp.id, status: "UNKNOWN", score: "--", finding_count: 0 }); });
  }

  function countBy(list, key) {
    return (list || []).reduce(function (acc, item) { var value = item[key] || "unknown"; acc[value] = (acc[value] || 0) + 1; return acc; }, {});
  }

  function renderAll() {
    renderHeader();
    renderOverview();
    renderTargets();
    renderCheckpoints();
    renderRbacMatrix();
    renderFilters();
    renderFindings();
    renderStubs();
    renderMetrics();
    renderReport();
    renderObservability();
  }


  function renderHeader() {
    var s = summary();
    $("taskMeta").textContent = state.taskId ? "当前任务 " + state.taskId + " · " + text(s.conclusion, "暂无结论") : "没有可用评估任务";
  }

  function renderOverview() {
    var s = summary();
    $("overallScore").textContent = text(s.overall_score);
    $("conclusion").textContent = text(s.conclusion, "等待报告");
    $("checkpointTotal").textContent = cloudNativeModules.length;
    $("findingTotal").textContent = text(s.finding_total || state.findings.length);
    $("criticalHigh").textContent = "严重 / 高风险未通过: " + text((s.critical_fail_count || 0) + (s.high_fail_count || 0), "0");
    $("evidenceCoverage").textContent = s.evidence_coverage === undefined ? "--" : s.evidence_coverage + "%";
    $("scoredWeight").textContent = "已计分权重: " + text(s.scored_weight);
    renderDonut("severityDonut", s.severity_count || countBy(state.findings, "severity"), severityLabel, "条问题");
    renderDonut("moduleDonut", cloudNativeRiskCounts(), function (value) { return value; }, "条云原生问题");
    renderBars("statusBars", s.status_count || countBy(state.findings, "status"));
    renderToolScores();
    renderDomainRadar(s.by_domain || []);
    renderNamespaceRisks();
    renderTools(s.tool_summary || s.tools || []);
    renderQuality(s.data_quality || (state.report && state.report.data_quality) || {});
    renderRemediationPriority(s.remediation_priority || []);
    renderProgress();
  }

  function renderBars(id, data) {
    var entries = Object.keys(data || {}).sort().map(function (k) { return [k, data[k]]; });
    var max = entries.reduce(function (m, e) { return Math.max(m, e[1]); }, 1);
    $(id).innerHTML = entries.length ? entries.map(function (e) {
      var label = id === "severityBars" ? severityLabel(e[0]) : id === "statusBars" ? statusLabel(e[0]) : e[0];
      return '<div class="bar-row"><span>' + escapeHtml(label) + '</span><div><i style="width:' + Math.max(5, e[1] / max * 100) + '%"></i></div><b>' + e[1] + '</b></div>';
    }).join("") : '<p class="muted">暂无数据</p>';
  }

  function cloudNativeRiskCounts() {
    var counts = {};
    state.findings.forEach(function (finding) {
      var info = cloudNativePresentation[finding.checkpoint_id];
      if (info && isCloudNativeModule(info.module)) counts[info.module] = (counts[info.module] || 0) + 1;
    });
    return counts;
  }

  function renderDonut(id, data, labeler, totalLabel) {
    var entries = Object.keys(data || {}).map(function (key) { return [key, Number(data[key]) || 0]; }).filter(function (entry) { return entry[1] > 0; });
    var total = entries.reduce(function (sum, entry) { return sum + entry[1]; }, 0);
    if (!entries.length || !total) { $(id).innerHTML = '<p class="muted">暂无数据</p>'; return; }
    var colors = ["#c33b4b", "#e8893d", "#246bce", "#0d9c8d", "#7565e8"];
    var cursor = 0;
    var stops = entries.map(function (entry, index) {
      var start = cursor;
      cursor += entry[1] / total * 360;
      return colors[index % colors.length] + " " + start + "deg " + cursor + "deg";
    });
    $(id).innerHTML = '<div class="donut-visual" style="background:conic-gradient(' + stops.join(",") + ')"><div class="donut-hole"><strong>' + total + '</strong><span>' + escapeHtml(totalLabel || "条问题") + '</span></div></div><div class="chart-legend">' + entries.map(function (entry, index) {
      return '<div><i style="background:' + colors[index % colors.length] + '"></i><span>' + escapeHtml(labeler(entry[0])) + '</span><b>' + entry[1] + ' · ' + Math.round(entry[1] / total * 100) + '%</b></div>';
    }).join("") + '</div>';
  }

  function renderTools(tools) {
    if (!tools.length) tools = Array.from(new Set(state.findings.map(function (f) { return f.tool_id; }).filter(function (id) { return id && id !== "platform"; }))).map(function (id) { return { tool_id: id }; });
    tools = tools.filter(function (tool) {
      var id = typeof tool === "string" ? tool : tool.tool_id || tool.id || tool.name;
      return id !== "platform";
    });
    $("toolList").innerHTML = tools.length ? tools.map(function (tool) {
      if (typeof tool === "string") tool = { tool_id: tool };
      var id = tool.tool_id || tool.id || tool.name;
      var health = state.report && state.report.adapter_health && state.report.adapter_health[id];
      var status = tool.status || (health && health.status) || "ready";
      var stub = tool.stub_mode || status === "stub";
      var label = stub ? "示例数据（待补充）" : status === "ready" ? "已就绪" : status === "error" ? "异常" : status;
      return '<div class="tool-item"><strong>' + escapeHtml(toolLabel(id)) + '</strong><span>' + escapeHtml(text(tool.finding_count, "0")) + ' 个问题</span><small>' + escapeHtml(label) + '</small></div>';
    }).join("") : '<p class="muted">暂无工具数据</p>';
  }

  function renderToolScores() {
    var tools = {};
    state.findings.filter(function (finding) { return finding.tool_id !== "platform"; }).forEach(function (finding) {
      var id = finding.tool_id || "unknown";
      tools[id] = tools[id] || { id: id, total: 0, fail: 0, warn: 0, unknown: 0 };
      tools[id].total += 1;
      if (finding.status === "FAIL") tools[id].fail += 1;
      if (finding.status === "WARN") tools[id].warn += 1;
      if (finding.status === "UNKNOWN") tools[id].unknown += 1;
    });
    var rows = Object.keys(tools).sort().map(function (id) {
      var row = tools[id];
      var risk = row.fail * 3 + row.warn + row.unknown;
      return Object.assign(row, { risk: risk });
    }).sort(function (a, b) { return b.risk - a.risk; });
    $("toolScoreGrid").innerHTML = rows.length ? rows.map(function (row) {
      return '<div class="score-row"><strong>' + escapeHtml(toolLabel(row.id)) + '</strong><span>' + row.total + ' 个问题</span><b>失败 ' + row.fail + ' · 警告 ' + row.warn + ' · 信息不足 ' + row.unknown + '</b></div>';
    }).join("") : '<p class="muted">暂无工具结果</p>';
  }

  function renderDomainRadar(domains) {
    var cloudDomains = (domains || []).filter(function (row) {
      return isCloudNativeModule(row.domain || "");
    });
    if (!cloudDomains.length) {
      var byDomain = {};
      checkpointScores().forEach(function (score) {
        var domain = score.domain || "unknown";
        byDomain[domain] = byDomain[domain] || { domain: domain, total: 0, sum: 0, unknown: 0 };
        if (Number.isFinite(Number(score.score))) {
          byDomain[domain].sum += Number(score.score);
          byDomain[domain].total += 1;
        }
        if (score.status === "UNKNOWN") byDomain[domain].unknown += 1;
      });
      cloudDomains = Object.keys(byDomain).map(function (domain) {
        var row = byDomain[domain];
        return { domain: domain, score: row.total ? Math.round(row.sum / row.total * 100) / 100 : 0, unknown_checkpoint_count: row.unknown };
      }).filter(function (row) { return isCloudNativeModule(row.domain || ""); });
    }
    $("moduleScoreBars").innerHTML = cloudDomains.length ? cloudDomains.map(function (row) {
      var score = Number(row.score) || 0;
      return '<div class="domain-row"><span>' + escapeHtml(text(row.domain)) + '</span><div><i style="width:' + Math.max(3, Math.min(100, score)) + '%"></i></div><b>' + escapeHtml(text(row.score)) + '</b><small>UNKNOWN ' + escapeHtml(text(row.unknown_checkpoint_count, "0")) + '</small></div>';
    }).join("") : '<p class="muted">暂无云原生模块数据</p>';
  }

  function renderNamespaceRisks() {
    var risks = {};
    state.findings.forEach(function (finding) {
      var asset = assetOf(finding);
      var ns = asset.namespace || "_cluster";
      risks[ns] = risks[ns] || { namespace: ns, fail: 0, critical: 0, high: 0, warn: 0, total: 0 };
      risks[ns].total += 1;
      if (finding.status === "FAIL") risks[ns].fail += 1;
      if (finding.status === "WARN") risks[ns].warn += 1;
      if (finding.status === "FAIL" && finding.severity === "critical") risks[ns].critical += 1;
      if (finding.status === "FAIL" && finding.severity === "high") risks[ns].high += 1;
    });
    var rows = Object.keys(risks).map(function (key) {
      var row = risks[key];
      row.risk = row.critical * 5 + row.high * 3 + row.fail + row.warn * 0.5;
      return row;
    }).sort(function (a, b) { return b.risk - a.risk; }).slice(0, 8);
    $("namespaceRisks").innerHTML = rows.length ? rows.map(function (row) {
      return '<div class="risk-row"><strong>' + escapeHtml(row.namespace) + '</strong><span>' + row.total + ' 个问题</span><b>严重 ' + row.critical + ' · 高风险 ' + row.high + ' · 失败 ' + row.fail + '</b></div>';
    }).join("") : '<p class="muted">暂无资源范围风险</p>';
  }

  function renderQuality(q) {
    var items = [["completeness", "完整性"], ["freshness", "新鲜度"], ["unknown_rate", "信息不足比例"], ["schema_error_count", "数据格式错误"], ["raw_snapshot_count", "原始结果"], ["normalized_finding_count", "统一问题"]];
    $("qualityGrid").innerHTML = items.map(function (item) { return '<div><span>' + item[1] + '</span><strong>' + escapeHtml(text(q[item[0]])) + '</strong></div>'; }).join("");
  }

  function renderRemediationPriority(items) {
    var rows = (items && items.length ? items : fallbackRemediationPriority());
    var visibleRows = rows.slice(0, 6);
    var counts = rows.reduce(function (acc, row) {
      var priority = row.priority || "P3";
      acc[priority] = (acc[priority] || 0) + 1;
      return acc;
    }, {});
    $("prioritySummary").innerHTML = ["P0", "P1", "P2", "P3"].map(function (priority) {
      return '<div><span>' + escapeHtml(priorityLabel(priority)) + '</span><strong>' + escapeHtml(text(counts[priority], "0")) + '</strong></div>';
    }).join("");
    $("priorityList").innerHTML = visibleRows.length ? visibleRows.map(function (row) {
      var title = checkpointRiskTitle(row.checkpoint_id) || text(row.title);
      return '<div class="priority-row ' + escapeHtml(text(row.priority, "P3").toLowerCase()) + '"><strong>' + escapeHtml(priorityLabel(row.priority, "P3")) + '</strong><span>' + escapeHtml(title) + '</span><small>' + escapeHtml(text(row.asset)) + '</small><p>' + escapeHtml(text(row.remediation)) + '</p></div>';
    }).join("") + (rows.length > visibleRows.length ? '<p class="muted">已优先显示最紧急的 6 项，完整问题请打开“风险问题”。</p>' : "") : '<p class="muted">暂无整改优先级</p>';
  }

  function priorityLabel(priority) {
    return ({ P0: "立即处理", P1: "优先处理", P2: "计划处理", P3: "持续观察" })[priority] || priority || "持续观察";
  }

  function fallbackRemediationPriority() {
    var severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    var statusRank = { FAIL: 4, WARN: 2, UNKNOWN: 1 };
    return state.findings.filter(function (finding) {
      return ["FAIL", "WARN", "UNKNOWN"].indexOf(finding.status) >= 0;
    }).map(function (finding) {
      var score = (severityRank[finding.severity] || 1) * (statusRank[finding.status] || 0);
      var priority = score >= 19 ? "P0" : score >= 13 ? "P1" : score >= 7 ? "P2" : "P3";
      if (finding.status === "UNKNOWN") priority = "P3";
      return {
        priority: priority,
        risk_score: score,
        checkpoint_id: finding.checkpoint_id,
        title: finding.title,
        asset: assetOf(finding).label,
        remediation: finding.remediation,
      };
    }).sort(function (a, b) { return (b.risk_score || 0) - (a.risk_score || 0); });
  }


  function renderProgress() {
    var events = state.taskEvents || [];
    $("progressTimeline").innerHTML = events.length ? events.map(function (event) {
      return '<div class="timeline-row ' + escapeHtml(text(event.status).toLowerCase()) + '"><span>' + escapeHtml(text(event.progress, "0")) + '%</span><strong>' + escapeHtml(text(event.stage)) + '</strong><p>' + escapeHtml(text(event.message)) + '</p><small>' + escapeHtml(text(event.created_at, "")) + '</small></div>';
    }).join("") : '<p class="muted">暂无任务进度事件</p>';
  }
  function statusLabel(status) {
    return status === "PASS" ? "已通过" : status === "WARN" ? "需关注" : status === "FAIL" ? "异常" : status === "UNKNOWN" ? "信息不足" : status === "NOT_APPLICABLE" ? "不适用" : "待接入";
  }

  function severityLabel(severity) {
    return ({ critical: "严重", high: "高风险", medium: "中风险", low: "低风险", info: "提示" })[String(severity || "").toLowerCase()] || severity || "未标记";
  }
  function modeLabel(mode) {
    return mode === "real" ? "已接入工具" : mode === "placeholder" ? "待接入工具" : "已实现";
  }

  function statCard(label, value, note, tone) {
    return '<div class="summary-stat ' + escapeHtml(tone || "") + '"><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(text(value)) + '</strong><small>' + escapeHtml(note || "") + '</small></div>';
  }




  function observabilityAssets() {
    var byLabel = {};
    state.findings.forEach(function (finding) {
      var asset = assetOf(finding);
      var label = asset.label || "_cluster";
      byLabel[label] = byLabel[label] || { label: label, kind: asset.kind || "资源", namespace: asset.namespace || "_cluster", name: asset.name || label, findings: [] };
      byLabel[label].findings.push(finding);
    });
    return Object.keys(byLabel).map(function (key) {
      var asset = byLabel[key];
      asset.fail = asset.findings.filter(function (finding) { return finding.status === "FAIL"; }).length;
      asset.warn = asset.findings.filter(function (finding) { return finding.status === "WARN"; }).length;
      asset.unknown = asset.findings.filter(function (finding) { return finding.status === "UNKNOWN"; }).length;
      asset.level = asset.fail ? "risk" : asset.warn ? "warn" : asset.unknown ? "unknown" : "safe";
      return asset;
    }).sort(function (a, b) { return (b.fail * 3 + b.warn) - (a.fail * 3 + a.warn) || a.label.localeCompare(b.label); });
  }

  function resourceKindLabel(kind) {
    return ({ Deployment: "应用服务", StatefulSet: "有状态服务", DaemonSet: "节点服务", Pod: "运行实例", Service: "服务入口", Ingress: "访问入口", Secret: "敏感配置", ConfigMap: "配置文件", PersistentVolumeClaim: "存储卷" })[kind] || kind || "资源";
  }

  function observabilityAssetCard(asset) {
    var label = asset.name && asset.name !== asset.label ? asset.name : asset.label;
    return '<article class="asset-overview-card ' + escapeHtml(asset.level) + '"><div><span>' + escapeHtml(resourceKindLabel(asset.kind)) + '</span><strong>' + escapeHtml(label) + '</strong></div><small>' + escapeHtml(asset.namespace) + ' · ' + escapeHtml(asset.findings.length) + ' 个相关结果</small><b>' + (asset.fail ? "高风险 " + asset.fail : asset.warn ? "需关注 " + asset.warn : asset.unknown ? "信息不足 " + asset.unknown : "暂未发现问题") + '</b></article>';
  }

  function topologyLane(label, assets, emptyText) {
    return '<div class="topology-lane"><h3>' + escapeHtml(label) + '</h3>' + (assets.length ? assets.slice(0, 4).map(function (asset) {
      return '<div class="topology-node ' + escapeHtml(asset.level) + '"><i></i><span>' + escapeHtml(resourceKindLabel(asset.kind)) + '</span><strong>' + escapeHtml(asset.name || asset.label) + '</strong><small>' + escapeHtml(asset.namespace) + '</small></div>';
    }).join("") : '<p class="topology-empty">' + escapeHtml(emptyText) + '</p>') + '</div>';
  }

  function renderObservability() {
    var assets = observabilityAssets();
    var riskyAssets = assets.filter(function (asset) { return asset.level === "risk" || asset.level === "warn"; });
    var namespaces = Array.from(new Set(assets.map(function (asset) { return asset.namespace; })));
    $("observabilityAssetCount").textContent = text(assets.length, "0");
    $("observabilityStats").innerHTML = [
      statCard("关联资源", assets.length, "与当前问题相关的资源", "blue"),
      statCard("需要关注", riskyAssets.length, "存在失败或警告", "orange"),
      statCard("资源范围", namespaces.length, "涉及命名空间", "green"),
      statCard("链路数据", "待接入", "OpenTelemetry / Jaeger / SkyWalking", "purple"),
    ].join("");
    var entry = assets.filter(function (asset) { return /Service|Ingress|Gateway|API/i.test(asset.kind); });
    var services = assets.filter(function (asset) { return /Deployment|StatefulSet|DaemonSet|Pod/i.test(asset.kind); });
    var data = assets.filter(function (asset) { return entry.indexOf(asset) < 0 && services.indexOf(asset) < 0; });
    $("serviceTopology").innerHTML = '<p class="topology-note">仅显示与当前问题关联的资源（共 ' + escapeHtml(assets.length) + ' 条），按资源类型分组；分组之间不是实际调用关系。</p><div class="topology-lanes">' +
      topologyLane("访问入口", entry, "暂未识别服务入口") +
      '<div class="topology-connector" aria-hidden="true"></div>' +
      topologyLane("运行服务", services, "暂未识别运行服务") +
      '<div class="topology-connector" aria-hidden="true"></div>' +
      topologyLane("配置与存储", data, "暂未识别配置或存储") +
      '</div>';
      $("traceWaterfall").innerHTML = '<div class="trace-empty"><div class="trace-skeleton"><i></i><i></i><i></i></div><h3>还没有调用链数据</h3><p>当前任务包含配置、权限和安全检查结果，但尚未接入请求链路数据，因此暂时无法展示耗时、错误传播或真实调用关系。</p><a class="ghost-button" href="#findings">查看风险问题</a></div>';
    $("assetOverview").innerHTML = assets.length ? assets.slice(0, 6).map(observabilityAssetCard).join("") : '<p class="empty">当前任务还没有可展示的资源。</p>';
    var matrix = state.rbacMatrix || {};
    var matrixSummary = matrix.summary || {};
    var dangerous = matrix.dangerous_rows || [];
    $("policyOverview").innerHTML = matrixSummary.matrix_row_count ? '<div class="policy-kpis"><div><span>权限主体</span><strong>' + escapeHtml(text(matrixSummary.subject_count, "0")) + '</strong></div><div><span>权限关系</span><strong>' + escapeHtml(text(matrixSummary.matrix_row_count, "0")) + '</strong></div><div><span>需要关注</span><strong class="danger-number">' + escapeHtml(text(matrixSummary.dangerous_row_count, "0")) + '</strong></div></div><div class="policy-list">' + dangerous.slice(0, 4).map(function (row) { return '<div><strong>' + escapeHtml(text(row.subject)) + '</strong><span>' + escapeHtml(text(row.scope, "集群范围")) + '</span><b>' + escapeHtml((row.danger_reasons || []).join("、") || "权限范围较大") + '</b></div>'; }).join("") + '</div>' : '<div class="trace-empty compact"><h3>暂未生成权限摘要</h3><p>完成一次云原生评估后，这里会显示需要关注的权限关系。</p></div>';
  }

  function renderTargets() {
    var options = state.targets.map(function (target) {
      return '<option value="' + escapeHtml(target.id) + '">' + escapeHtml(target.name || target.id) + '</option>';
    }).join("");
    $("targetSelect").innerHTML = options || '<option value="">暂无目标</option>';
    $("targetRows").innerHTML = state.targets.map(function (target) {
      var connection = target.connection_mode === "manifest" ? target.manifest : target.connection_mode === "pve_ssh" ? target.pve_ssh + " / " + target.control_plane_ip : target.kubeconfig;
      return '<tr><td><code>' + escapeHtml(target.id) + '</code></td><td>' + escapeHtml(text(target.name)) + '</td><td>' + escapeHtml(text(target.type)) + '</td><td>' + escapeHtml(text(target.connection_mode)) + '</td><td>' + escapeHtml(text(connection)) + '</td><td>' + escapeHtml(JSON.stringify(target.labels || {})) + '</td><td><button class="delete-target" data-target="' + escapeHtml(target.id) + '" type="button">删除</button></td></tr>';
    }).join("") || '<tr><td colspan="7" class="empty">暂无目标</td></tr>';
  }

  function parseLabels() {
    var raw = $("targetLabels").value || "{}";
    try { return JSON.parse(raw); } catch (_) { return { raw: raw }; }
  }

  function parseJsonInput(id, fallback) {
    var raw = $(id).value || "";
    if (!raw) return fallback;
    try { return JSON.parse(raw); } catch (_) { throw new Error(id + " 必须是合法 JSON"); }
  }

  function createTarget() {
    var mode = $("targetMode").value;
    var payload = {
      name: $("targetName").value || "demo-target",
      type: "kubernetes",
      connection_mode: mode,
      labels: parseLabels(),
      manifest: $("targetManifest").value || null,
      pve_ssh: $("targetPveSsh").value || null,
      control_plane_ip: $("targetControlPlane").value || "10.20.0.11",
      ssh_key: $("targetSshKey").value || "/root/.ssh/agent_lab",
      ssh_user: $("targetSshUser").value || "agent",
    };
    fetch("/api/targets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then(function (res) {
      if (!res.ok) throw new Error("保存目标失败: " + res.status);
      return loadTargets();
    }).catch(function (err) { alert(err.message); });
  }

  function createAssessment() {
    var payload = {
      task_id: $("newTaskId").value || ("dashboard-task-" + Date.now()),
      target_id: $("targetSelect").value,
      profile: $("newTaskProfile").value,
      options: { destructive_tests: false },
    };
    if (!payload.target_id) { alert("请先保存或选择目标"); return; }
    fetch("/api/assessments", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then(function (res) {
      if (!res.ok) throw new Error("创建任务失败: " + res.status);
      return res.json();
    }).then(function () {
      state.taskId = payload.task_id;
      return discoverTasks();
    }).then(function (tasks) {
      state.tasks = tasks;
      $("taskSelect").innerHTML = tasks.length ? tasks.map(function (t) { return '<option value="' + t.id + '">' + t.id + (t.status ? " · " + t.status : "") + '</option>'; }).join("") : '<option value="">无任务</option>';
      $("taskSelect").value = payload.task_id;
      return loadTask(payload.task_id);
    }).then(function () {
      setRoute("overview");
    }).catch(function (err) { alert(err.message); });
  }

  function deleteTarget(targetId) {
    fetch("/api/targets/" + encodeURIComponent(targetId), { method: "DELETE" }).then(function (res) {
      if (!res.ok) throw new Error("删除目标失败: " + res.status);
      return loadTargets();
    }).catch(function (err) { alert(err.message); });
  }

  function cancelCurrentTask() {
    if (!state.taskId) return;
    fetch("/api/assessments/" + encodeURIComponent(state.taskId) + "/cancel", { method: "POST" }).then(function (res) {
      if (!res.ok) throw new Error("取消任务失败: " + res.status);
      return loadTask(state.taskId);
    }).catch(function (err) {
      alert(err.message);
    });
  }

  function renderCheckpoints() {
    var term = ($("checkpointSearch").value || "").toLowerCase();
    var byScore = {};
    checkpointScores().forEach(function (s) { byScore[s.checkpoint_id || s.id] = s; });
    $("checkpointRows").innerHTML = state.checkpoints.filter(function (cp) {
      var info = checkpointInfo(cp.id);
      return /^CN-/.test(cp.id) && (!term || [cp.id, info.module, info.name, cp.rule_group].join(" ").toLowerCase().indexOf(term) >= 0);
    }).map(function (cp) {
      var info = checkpointInfo(cp.id);
      var sc = byScore[cp.id] || {};
      return '<tr><td>' + escapeHtml(info.module) + '</td><td>' + escapeHtml(info.name) + '</td><td>' + escapeHtml(text(cp.weight)) + '</td><td><span class="pill ' + escapeHtml(text(sc.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(statusLabel(sc.status)) + '</span></td><td>' + escapeHtml(text(sc.score)) + '</td><td>' + escapeHtml(text(sc.finding_count, "0")) + '</td></tr>';
    }).join("") || '<tr><td colspan="6" class="empty">暂无云原生检查项</td></tr>';
  }

  function renderRbacMatrix() {
    var matrix = state.rbacMatrix || {};
    var summary = matrix.summary || {};
    var rows = filteredRbacRows(matrix).slice(0, 80);
    $("rbacSummary").textContent = "权限主体 " + text(summary.subject_count, "0") + " · 权限关系 " + text(summary.matrix_row_count, "0") + " · 需关注 " + text(summary.dangerous_row_count, "0") + " · 当前显示 " + rows.length;
    $("rbacRows").innerHTML = rows.map(function (row) {
      return '<tr><td>' + escapeHtml(text(row.subject)) + '</td><td>' + escapeHtml(text(row.scope)) + '</td><td>' + escapeHtml(text(row.role_kind)) + '/' + escapeHtml(text(row.role_name)) + '</td><td>' + escapeHtml((row.resources || []).join(", ")) + '</td><td>' + escapeHtml((row.verbs || []).join(", ")) + '</td><td>' + escapeHtml((row.danger_reasons || []).join(", ") || "normal") + '</td></tr>';
    }).join("") || '<tr><td colspan="6" class="empty">暂无权限关系数据</td></tr>';
  }

  function filteredRbacRows(matrix) {
    var base = state.rbacFilters.dangerous_only ? (matrix.dangerous_rows || []) : (matrix.rows || []);
    return base.filter(function (row) {
      return (!state.rbacFilters.subject || text(row.subject).toLowerCase().indexOf(state.rbacFilters.subject.toLowerCase()) >= 0) &&
        (!state.rbacFilters.resource || (row.resources || []).join(" ").toLowerCase().indexOf(state.rbacFilters.resource.toLowerCase()) >= 0) &&
        (!state.rbacFilters.verb || (row.verbs || []).join(" ").toLowerCase().indexOf(state.rbacFilters.verb.toLowerCase()) >= 0) &&
        (!state.rbacFilters.scope || text(row.scope).toLowerCase().indexOf(state.rbacFilters.scope.toLowerCase()) >= 0);
    });
  }

  function toolLabel(toolId) {
    return ({
      cloud_native: "云原生安全检查工具",
      cloud_api_stub: "云上 API 安全工具（待接入）",
      smart_cloud_stub: "智算云安全工具（待接入）",
      registry_stub: "镜像仓库安全工具（待接入）",
      platform: "系统评估",
    })[toolId] || toolId || "未知来源工具";
  }

  function renderFilters() {
    fillSelect("toolFilter", state.findings.filter(function (f) { return f.tool_id !== "platform"; }).map(function (f) { return f.tool_id; }), "全部来源工具", toolLabel);
    fillSelect("domainFilter", checkpointScores().filter(function (s) { return isCloudNativeModule(s.domain); }).map(function (s) { return s.domain; }), "全部安全模块");
    fillSelect("severityFilter", state.findings.map(function (f) { return f.severity; }), "全部风险等级", severityLabel);
    fillSelect("statusFilter", state.findings.map(function (f) { return f.status; }), "全部问题状态", statusLabel);
  }

  function fillSelect(id, values, label, formatter) {
    var el = $(id), current = el.value;
    var options = Array.from(new Set(values.filter(Boolean))).sort();
    el.innerHTML = '<option value="">' + label + '</option>' + options.map(function (v) { return '<option value="' + escapeHtml(v) + '">' + escapeHtml(formatter ? formatter(v) : v) + '</option>'; }).join("");
    el.value = options.indexOf(current) >= 0 ? current : "";
  }


  function filteredFindings() {
    var domains = {};
    checkpointScores().forEach(function (score) { domains[score.checkpoint_id || score.id] = score.domain || ""; });
    return state.findings.filter(function (f) {
      var asset = assetOf(f);
      var haystack = [f.title, f.rule_id, f.checkpoint_id, f.remediation, asset.label, JSON.stringify(safeJson(f.evidence_json, f.evidence || []))].join(" ").toLowerCase();
      return (!state.filters.tool_id || f.tool_id === state.filters.tool_id) &&
        (!state.filters.domain || domains[f.checkpoint_id] === state.filters.domain) &&
        (!state.filters.severity || f.severity === state.filters.severity) &&
        (!state.filters.status || f.status === state.filters.status) &&
        (!state.filters.namespace || asset.namespace.toLowerCase().indexOf(state.filters.namespace.toLowerCase()) >= 0) &&
        (!state.filters.kind || asset.kind.toLowerCase().indexOf(state.filters.kind.toLowerCase()) >= 0) &&
        (!state.filters.name || asset.name.toLowerCase().indexOf(state.filters.name.toLowerCase()) >= 0) &&
        (!state.filters.keyword || haystack.indexOf(state.filters.keyword.toLowerCase()) >= 0);
    });
  }

  function renderFindings() {
    var rows = filteredFindings();
    $("findingRows").innerHTML = rows.map(function (f, index) {
      var asset = assetOf(f);
      return '<tr data-index="' + index + '"><td><span class="sev ' + escapeHtml(text(f.severity).toLowerCase()) + '">' + escapeHtml(severityLabel(f.severity)) + '</span></td><td><span class="pill ' + escapeHtml(text(f.status).toLowerCase()) + '">' + escapeHtml(statusLabel(f.status)) + '</span></td><td>' + escapeHtml(checkpointLabel(f.checkpoint_id)) + '</td><td>' + escapeHtml(toolLabel(f.tool_id)) + '</td><td>' + escapeHtml(userAssetLabel(asset)) + '</td><td>' + escapeHtml(findingTitle(f)) + '</td></tr>';
    }).join("") || '<tr><td colspan="6" class="empty">没有匹配的问题</td></tr>';
    document.querySelectorAll("#findingRows tr[data-index]").forEach(function (row) {
      row.addEventListener("click", function () { state.selectedFinding = rows[Number(row.dataset.index)]; renderFindingDetail(); });
    });
    if (!state.selectedFinding && rows[0]) state.selectedFinding = rows[0];
    renderFindingDetail();
  }

  function renderFindingDetail() {
    var f = state.selectedFinding;
    if (!f) { $("findingDetail").innerHTML = '<h2>问题详情</h2><p class="muted">暂无数据</p>'; return; }
    var evidence = safeJson(f.evidence_json, f.evidence || []);
    var asset = assetOf(f);
    var info = checkpointInfo(f.checkpoint_id);
    var related = relatedFindings(f).slice(0, 8);
    $("findingDetail").innerHTML = '<div class="detail-head"><h2>' + escapeHtml(findingTitle(f)) + '</h2><button id="copyRemediationBtn" type="button">复制处理建议</button></div>' +
      '<div class="detail-tags"><span class="sev ' + escapeHtml(text(f.severity).toLowerCase()) + '">' + escapeHtml(severityLabel(f.severity)) + '</span><span class="pill ' + escapeHtml(text(f.status).toLowerCase()) + '">' + escapeHtml(statusLabel(f.status)) + '</span><span>' + escapeHtml(info.name) + '</span></div>' +
      '<h3>所属安全模块</h3><div class="asset-card"><strong>' + escapeHtml(info.module || "通用检查") + '</strong><span>三级模块：' + escapeHtml(info.name) + '</span></div>' +
      '<h3>风险分析</h3><p>' + escapeHtml(findingAnalysis(f)) + '</p>' +
      '<h3>影响对象</h3><div class="asset-card"><strong>' + escapeHtml(asset.name || "整个评估范围") + '</strong><span>' + escapeHtml(asset.namespace ? "资源范围：" + asset.namespace : "未限定具体资源范围") + '</span></div>' +
      '<h3>发现依据</h3><details class="evidence-disclosure"><summary>查看原始技术证据</summary><pre>' + escapeHtml(JSON.stringify(evidence, null, 2)) + '</pre></details>' +
      '<h3>建议处理</h3><p id="remediationText">' + escapeHtml(text(f.remediation, "暂无处理建议")) + '</p>' +
      '<h3>同一对象的其他问题</h3><div class="related-findings">' + (related.length ? related.map(function (item) {
        return '<button class="related-finding" data-finding-id="' + escapeHtml(text(item.id)) + '" type="button"><span class="pill ' + escapeHtml(text(item.status).toLowerCase()) + '">' + escapeHtml(statusLabel(item.status)) + '</span><strong>' + escapeHtml(findingTitle(item)) + '</strong></button>';
      }).join("") : '<p class="muted">暂无其他问题</p>') + '</div>';
    $("copyRemediationBtn").addEventListener("click", function () { copyRemediation(f.remediation || ""); });
    document.querySelectorAll(".related-finding").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = state.findings.find(function (item) { return text(item.id) === button.dataset.findingId; });
        if (target) {
          state.selectedFinding = target;
          renderFindingDetail();
        }
      });
    });
  }

  function relatedFindings(finding) {
    var selectedAsset = assetOf(finding).label;
    return state.findings.filter(function (item) {
      return item !== finding && assetOf(item).label === selectedAsset;
    }).sort(function (a, b) {
      var rank = { FAIL: 0, WARN: 1, UNKNOWN: 2, PASS: 3, NOT_APPLICABLE: 4 };
      return (rank[a.status] || 9) - (rank[b.status] || 9) || text(a.checkpoint_id).localeCompare(text(b.checkpoint_id));
    });
  }

  function copyRemediation(textValue) {
    var value = text(textValue, "暂无修复建议");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).catch(function () {});
    }
  }

  function renderStubs() {
    renderStubSection("cloud_api_stub", "apiStubStats", "apiStubDetails", "API 工具示例问题");
    renderStubSection("smart_cloud_stub", "smartStubStats", "smartStubDetails", "智算云工具示例问题");
    renderStubSection("registry_stub", "registryStubStats", "registryStubDetails", "镜像仓库工具示例问题");
  }

  function renderStubSection(toolId, statsId, detailsId, label) {
    var findings = state.findings.filter(function (f) { return f.tool_id === toolId; });
    var snapshot = state.rawSnapshots.find(function (item) { return item.source === toolId; }) || {};
    var raw = snapshot.summary || {};
    $(statsId).innerHTML = stubCards(findings, snapshot, label);
    $(detailsId).innerHTML = stubDetails(toolId, findings, raw);
  }

  function stubCards(findings, snapshot, label) {
    var fail = findings.filter(function (f) { return f.status === "FAIL"; }).length;
    var warn = findings.filter(function (f) { return f.status === "WARN"; }).length;
    var unknown = findings.filter(function (f) { return f.status === "UNKNOWN"; }).length;
    var dataState = snapshot.summary && snapshot.summary.input_mode === "fixture" ? "示例数据（待补充）" : "已接入数据";
    return '<div><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(findings.length) + '</strong></div>' +
      '<div><span>失败 / 警告 / 信息不足</span><strong>' + fail + ' / ' + warn + ' / ' + unknown + '</strong></div>' +
      '<div><span>数据状态</span><strong>' + escapeHtml(dataState) + '</strong></div>' +
      '<div><span>数据版本</span><strong>' + escapeHtml(text(snapshot.schema_version, "stub/v1")) + '</strong></div>';
  }

  function stubDetails(toolId, findings, raw) {
    var params = raw.target_parameters || {};
    var input = raw.input || {};
    var capabilities = raw.capabilities || [];
    var title = toolId === "cloud_api_stub" ? "云上 API 安全工具" : toolId === "smart_cloud_stub" ? "智算云安全工具" : "镜像仓库安全工具";
    var rows = findings.map(function (finding) {
      return '<tr><td><span class="pill ' + escapeHtml(text(finding.status).toLowerCase()) + '">' + escapeHtml(statusLabel(finding.status)) + '</span></td><td><span class="sev ' + escapeHtml(text(finding.severity).toLowerCase()) + '">' + escapeHtml(severityLabel(finding.severity)) + '</span></td><td>' + escapeHtml(text(finding.title)) + '</td><td>' + escapeHtml(userAssetLabel(assetOf(finding))) + '</td></tr>';
    }).join("") || '<tr><td colspan="4" class="empty">暂无示例结果，等待部门补充真实数据。</td></tr>';
    return '<div class="stub-meta">' +
      '<div><h3>评估目标</h3><pre>' + escapeHtml(JSON.stringify(params, null, 2)) + '</pre></div>' +
      '<div><h3>处理能力</h3><div class="tag-list">' + (capabilities.length ? capabilities.map(function (item) { return '<span>' + escapeHtml(item) + '</span>'; }).join("") : '<span>待补充</span>') + '</div></div>' +
      '</div><details class="evidence-disclosure"><summary>查看示例输入数据</summary><pre>' + escapeHtml(JSON.stringify(input, null, 2)) + '</pre></details><p class="muted">' + escapeHtml(text(raw.replacement_note, "当前展示为示例数据，后续可替换为部门提供的真实工具数据。")) + '</p><h3>' + escapeHtml(title) + '</h3><div class="table-wrap"><table><thead><tr><th>状态</th><th>风险等级</th><th>问题描述</th><th>影响对象</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
  }

  function renderMetrics() {
    $("metricRows").innerHTML = state.checkpoints.map(function (cp) {
      return '<tr><td>' + escapeHtml(checkpointLabel(cp.id)) + '</td><td>' + escapeHtml(text(cp.domain)) + '</td><td><input class="enabled-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="checkbox" ' + (cp.enabled === false ? "" : "checked") + ' /></td><td>' + escapeHtml(text(cp.weight)) + '</td><td><input class="weight-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="number" value="' + escapeHtml(text(cp.weight, 1)) + '" step="0.1" min="0" /></td><td><input class="applicability-input wide-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="text" value="' + escapeHtml(JSON.stringify(cp.applicability || {})) + '" /></td><td><input class="rule-enabled-input wide-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="text" value="' + escapeHtml(JSON.stringify(cp.rule_enabled || {})) + '" /></td><td><button class="save-weight" data-checkpoint="' + escapeHtml(cp.id) + '" type="button">保存并重算</button><button class="save-checkpoint-meta" data-checkpoint="' + escapeHtml(cp.id) + '" type="button">保存元数据</button></td></tr>';
    }).join("") || '<tr><td colspan="8" class="empty">暂无指标</td></tr>';
  }

  function createCheckpoint() {
    var id = $("manualCheckpointId").value.trim();
    if (!id) { alert("指标 ID 必填"); return; }
    var payload;
    try {
      payload = {
        id: id,
        tender_no: Number($("manualTenderNo").value || 0),
        name: $("manualCheckpointName").value || id,
        rule_group: $("manualRuleGroup").value || id,
        domain: $("manualDomain").value || "人工补充指标",
        weight: Number($("manualWeight").value || 1),
        dimensions: parseJsonInput("manualDimensions", []),
        data_sources: parseJsonInput("manualDataSources", []),
        enabled: $("manualEnabled").checked,
        applicability: parseJsonInput("manualApplicability", {}),
        rule_enabled: parseJsonInput("manualRuleEnabled", {}),
      };
    } catch (err) {
      alert(err.message);
      return;
    }
    if (!Number.isFinite(payload.tender_no) || !Number.isFinite(payload.weight)) {
      alert("标书序号和权重必须是数字");
      return;
    }
    fetch("/api/checkpoints", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (res) {
      if (!res.ok) throw new Error("新增指标失败: " + res.status);
      return api("/api/checkpoints");
    }).then(function (checkpoints) {
      state.checkpoints = checkpoints || [];
      renderMetrics();
      renderCheckpoints();
      renderFilters();
    }).catch(function (err) {
      alert(err.message);
    });
  }

  function saveCheckpointMeta(checkpointId) {
    var enabled = document.querySelector('.enabled-input[data-checkpoint="' + CSS.escape(checkpointId) + '"]');
    var applicability = document.querySelector('.applicability-input[data-checkpoint="' + CSS.escape(checkpointId) + '"]');
    var ruleEnabled = document.querySelector('.rule-enabled-input[data-checkpoint="' + CSS.escape(checkpointId) + '"]');
    var payload;
    try {
      payload = {
        enabled: Boolean(enabled && enabled.checked),
        applicability: JSON.parse((applicability && applicability.value) || "{}"),
        rule_enabled: JSON.parse((ruleEnabled && ruleEnabled.value) || "{}"),
      };
    } catch (_) {
      alert("适用范围和规则启用必须是合法 JSON");
      return;
    }
    fetch("/api/checkpoints/" + encodeURIComponent(checkpointId), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (res) {
      if (!res.ok) throw new Error("保存指标元数据失败: " + res.status);
      return api("/api/checkpoints");
    }).then(function (checkpoints) {
      state.checkpoints = checkpoints || [];
      renderMetrics();
    }).catch(function (err) {
      alert(err.message);
    });
  }

  function renderReport() {
    var task = encodeURIComponent(state.taskId || "");
    $("jsonLink").href = "/api/reports/" + task;
    $("markdownLink").href = "/api/reports/" + task + ".md";
    $("htmlLink").href = "/api/reports/" + task + ".html";
    $("reportPreview").textContent = state.report ? JSON.stringify(state.report, null, 2).slice(0, 30000) : "暂无报告";
  }

  function saveWeight(checkpointId) {
    var input = document.querySelector('.weight-input[data-checkpoint="' + CSS.escape(checkpointId) + '"]');
    var weight = Number(input && input.value);
    if (!Number.isFinite(weight) || weight < 0) {
      alert("权重必须是非负数字");
      return;
    }
    fetch("/api/checkpoints/" + encodeURIComponent(checkpointId) + "/weight", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ weight: weight }),
    }).then(function (res) {
      if (!res.ok) throw new Error("保存权重失败: " + res.status);
      return fetch("/api/reports/" + encodeURIComponent(state.taskId) + "/recalculate", { method: "POST" });
    }).then(function (res) {
      if (!res.ok) throw new Error("重算报告失败: " + res.status);
      return loadTask(state.taskId);
    }).catch(function (err) {
      alert(err.message);
    });
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]; });
  }

  function wireEvents() {
    document.querySelectorAll(".tab").forEach(function (tab) { tab.addEventListener("click", function () { setRoute(tab.dataset.route); }); });
    window.addEventListener("hashchange", function () { setRoute(location.hash.replace("#", "")); });
    document.querySelectorAll("[data-route-jump]").forEach(function (button) {
      button.addEventListener("click", function () { setRoute(button.dataset.routeJump); });
    });
    $("taskSelect").addEventListener("change", function () { loadTask(this.value); });
    $("refreshBtn").addEventListener("click", init);
    $("cancelTaskBtn").addEventListener("click", cancelCurrentTask);
    $("createTargetBtn").addEventListener("click", createTarget);
    $("createAssessmentBtn").addEventListener("click", createAssessment);
    $("createCheckpointBtn").addEventListener("click", createCheckpoint);
    $("targetRows").addEventListener("click", function (event) {
      var target = event.target;
      if (target && target.classList && target.classList.contains("delete-target")) deleteTarget(target.dataset.target);
    });
    $("checkpointSearch").addEventListener("input", renderCheckpoints);
    [["rbacSubjectFilter", "subject"], ["rbacResourceFilter", "resource"], ["rbacVerbFilter", "verb"], ["rbacScopeFilter", "scope"]].forEach(function (pair) {
      $(pair[0]).addEventListener("input", function () { state.rbacFilters[pair[1]] = this.value; renderRbacMatrix(); });
    });
    $("rbacDangerousOnly").addEventListener("change", function () { state.rbacFilters.dangerous_only = this.checked; renderRbacMatrix(); });
    $("metricRows").addEventListener("click", function (event) {
      var target = event.target;
      if (target && target.classList && target.classList.contains("save-weight")) saveWeight(target.dataset.checkpoint);
      if (target && target.classList && target.classList.contains("save-checkpoint-meta")) saveCheckpointMeta(target.dataset.checkpoint);
    });
    [["toolFilter", "tool_id"], ["domainFilter", "domain"], ["severityFilter", "severity"], ["statusFilter", "status"], ["namespaceFilter", "namespace"], ["kindFilter", "kind"], ["nameFilter", "name"], ["keywordFilter", "keyword"]].forEach(function (pair) {
      $(pair[0]).addEventListener("input", function () { state.filters[pair[1]] = this.value; state.selectedFinding = null; renderFindings(); });
      $(pair[0]).addEventListener("change", function () { state.filters[pair[1]] = this.value; state.selectedFinding = null; renderFindings(); });
    });
  }

  function init() {
    loadTargets();
    discoverTasks().then(function (tasks) {
      state.tasks = tasks;
      $("taskSelect").innerHTML = tasks.length ? tasks.map(function (t) { return '<option value="' + t.id + '">' + t.id + (t.status ? " · " + t.status : "") + '</option>'; }).join("") : '<option value="">无任务</option>';
      var taskId = state.taskId || (tasks[0] && tasks[0].id) || "";
      if (!taskId) { renderAll(); return; }
      $("taskSelect").value = taskId;
      return loadTask(taskId);
    }).catch(function (err) {
      $("taskMeta").textContent = "加载失败: " + err.message;
    });
  }

  wireEvents();
  setRoute(location.hash.replace("#", "") || "overview");
  init();
})();

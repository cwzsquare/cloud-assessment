(function () {
  var state = {
    tasks: [],
    targets: [],
    taskId: "",
    report: null,
    findings: [],
    checkpoints: [],
    rawSnapshots: [],
    integration: null,
    rbacMatrix: null,
    taskEvents: [],
    selectedFinding: null,
    integrationGroup: "data_processing",
    integrationPoint: "",
    visualizationPoint: "",
    filters: { tool_id: "", checkpoint_id: "", domain: "", severity: "", status: "", namespace: "", kind: "", name: "", keyword: "" },
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

  function setRoute(route) {
    route = route || "overview";
    document.querySelectorAll(".tab").forEach(function (tab) { tab.classList.toggle("active", tab.dataset.route === route); });
    document.querySelectorAll(".view").forEach(function (view) { view.classList.toggle("active", view.id === route); });
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
    return Promise.all([
      api("/api/checkpoints").catch(function () { return []; }),
      api("/api/findings" + query).catch(function () { return []; }),
      api("/api/reports/" + encodeURIComponent(taskId)).catch(function () { return null; }),
      api("/api/raw-snapshots" + query).catch(function () { return []; }),
      api("/api/assessments/" + encodeURIComponent(taskId) + "/rbac-matrix").catch(function () { return null; }),
      api("/api/assessments/" + encodeURIComponent(taskId) + "/events").catch(function () { return []; }),
      api("/api/integration" + query).catch(function () { return null; }),
    ]).then(function (parts) {
      state.checkpoints = parts[0] || [];
      state.findings = parts[1] || [];
      state.report = parts[2];
      state.rawSnapshots = parts[3] || [];
      state.rbacMatrix = parts[4];
      state.taskEvents = parts[5] || [];
      state.integration = parts[6] || (state.report && state.report.summary && state.report.summary.integration_pipeline) || null;
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
    renderIntegration();
    renderVisualization();
  }

  function renderHeader() {
    var s = summary();
    $("taskMeta").textContent = state.taskId ? "当前任务 " + state.taskId + " · " + text(s.conclusion, "暂无结论") : "没有可用评估任务";
  }

  function renderOverview() {
    var s = summary();
    $("overallScore").textContent = text(s.overall_score);
    $("conclusion").textContent = text(s.conclusion, "等待报告");
    $("checkpointTotal").textContent = text(s.checkpoint_total || state.checkpoints.length);
    $("findingTotal").textContent = text(s.finding_total || state.findings.length);
    $("criticalHigh").textContent = "Critical/High FAIL: " + text((s.critical_fail_count || 0) + (s.high_fail_count || 0), "0");
    $("evidenceCoverage").textContent = s.evidence_coverage === undefined ? "--" : s.evidence_coverage + "%";
    $("scoredWeight").textContent = "Scored weight: " + text(s.scored_weight);
    renderBars("severityBars", s.severity_count || countBy(state.findings, "severity"));
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
      return '<div class="bar-row"><span>' + e[0] + '</span><div><i style="width:' + Math.max(5, e[1] / max * 100) + '%"></i></div><b>' + e[1] + '</b></div>';
    }).join("") : '<p class="muted">暂无数据</p>';
  }

  function renderTools(tools) {
    if (!tools.length) tools = Array.from(new Set(state.findings.map(function (f) { return f.tool_id; }).filter(Boolean))).map(function (id) { return { tool_id: id }; });
    $("toolList").innerHTML = tools.length ? tools.map(function (tool) {
      if (typeof tool === "string") tool = { tool_id: tool };
      var id = tool.tool_id || tool.id || tool.name;
      var health = state.report && state.report.adapter_health && state.report.adapter_health[id];
      var status = tool.status || (health && health.status) || "ready";
      var stub = tool.stub_mode || status === "stub";
      var label = (stub ? "stub/mock · " : "") + status;
      return '<div class="tool-item"><strong>' + escapeHtml(text(id)) + '</strong><span>' + escapeHtml(text(tool.finding_count, "")) + '</span><small>' + escapeHtml(label) + '</small></div>';
    }).join("") : '<p class="muted">暂无工具数据</p>';
  }

  function renderToolScores() {
    var tools = {};
    state.findings.forEach(function (finding) {
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
      return '<div class="score-row"><strong>' + escapeHtml(row.id) + '</strong><span>' + row.total + ' findings</span><b>F ' + row.fail + ' · W ' + row.warn + ' · U ' + row.unknown + '</b></div>';
    }).join("") : '<p class="muted">暂无工具态势</p>';
  }

  function renderDomainRadar(domains) {
    var cloudDomains = (domains || []).filter(function (row) {
      return /不可变|动态访问|持久化/.test(row.domain || "");
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
      }).filter(function (row) { return /不可变|动态访问|持久化/.test(row.domain || ""); });
    }
    $("domainRadar").innerHTML = cloudDomains.length ? cloudDomains.map(function (row) {
      var score = Number(row.score) || 0;
      return '<div class="domain-row"><span>' + escapeHtml(text(row.domain)) + '</span><div><i style="width:' + Math.max(3, Math.min(100, score)) + '%"></i></div><b>' + escapeHtml(text(row.score)) + '</b><small>UNKNOWN ' + escapeHtml(text(row.unknown_checkpoint_count, "0")) + '</small></div>';
    }).join("") : '<p class="muted">暂无云原生域数据</p>';
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
      return '<div class="risk-row"><strong>' + escapeHtml(row.namespace) + '</strong><span>' + row.total + ' findings</span><b>C ' + row.critical + ' · H ' + row.high + ' · F ' + row.fail + '</b></div>';
    }).join("") : '<p class="muted">暂无 namespace 风险</p>';
  }

  function renderQuality(q) {
    var items = [["completeness", "完整性"], ["freshness", "新鲜度"], ["unknown_rate", "Unknown 率"], ["schema_error_count", "Schema 错误"], ["raw_snapshot_count", "Raw Snapshots"], ["normalized_finding_count", "规范 Findings"]];
    $("qualityGrid").innerHTML = items.map(function (item) { return '<div><span>' + item[1] + '</span><strong>' + escapeHtml(text(q[item[0]])) + '</strong></div>'; }).join("");
  }

  function renderRemediationPriority(items) {
    var rows = (items && items.length ? items : fallbackRemediationPriority()).slice(0, 12);
    var counts = rows.reduce(function (acc, row) {
      var priority = row.priority || "P3";
      acc[priority] = (acc[priority] || 0) + 1;
      return acc;
    }, {});
    $("prioritySummary").innerHTML = ["P0", "P1", "P2", "P3"].map(function (priority) {
      return '<div><span>' + priority + '</span><strong>' + escapeHtml(text(counts[priority], "0")) + '</strong></div>';
    }).join("");
    $("priorityList").innerHTML = rows.length ? rows.map(function (row) {
      return '<div class="priority-row ' + escapeHtml(text(row.priority, "P3").toLowerCase()) + '"><strong>' + escapeHtml(text(row.priority, "P3")) + '</strong><span><code>' + escapeHtml(text(row.checkpoint_id)) + '</code> ' + escapeHtml(text(row.title)) + '</span><small>' + escapeHtml(text(row.asset)) + '</small><p>' + escapeHtml(text(row.remediation)) + '</p></div>';
    }).join("") : '<p class="muted">暂无整改优先级</p>';
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
  function integrationData() {
    return state.integration || (state.report && state.report.summary && state.report.summary.integration_pipeline) || { stats: {}, flow: [], points: [], adapters: [] };
  }

  function statusLabel(status) {
    return status === "PASS" ? "已实现" : status === "WARN" ? "需关注" : status === "FAIL" ? "异常" : "待接入";
  }

  function modeLabel(mode) {
    return mode === "real" ? "真实模块" : mode === "placeholder" ? "占位插槽" : "已实现";
  }

  function statCard(label, value, note, tone) {
    return '<div class="integration-stat ' + escapeHtml(tone || "") + '"><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(text(value)) + '</strong><small>' + escapeHtml(note || "") + '</small></div>';
  }

  function renderIntegration() {
    var pipeline = integrationData();
    var stats = pipeline.stats || {};
    $("integrationAdapterCount").textContent = text(stats.adapter_count, "0");
    $("integrationSchema").textContent = text(pipeline.schema_version, "integration/v1");
    $("integrationStats").innerHTML = [
      statCard("Raw snapshots", stats.raw_snapshot_count, "原始工具输出快照", "blue"),
      statCard("Normalized findings", stats.normalized_finding_count, "统一 Finding 结果", "green"),
      statCard("质量评分", stats.quality_score === undefined ? "--" : stats.quality_score + "%", "完整性 / 新鲜度 / Unknown", "purple"),
      statCard("真实接入", (pipeline.adapters || []).filter(function (item) { return item.mode === "real"; }).length, "云原生评估链路", "orange"),
    ].join("");
    $("integrationFlow").innerHTML = (pipeline.flow || []).map(function (item, index) {
      return '<div class="pipeline-step"><div class="pipeline-index">0' + (index + 1) + '</div><strong>' + escapeHtml(text(item.label)) + '</strong><span>' + escapeHtml(text(item.detail)) + '</span></div>' + (index < pipeline.flow.length - 1 ? '<div class="pipeline-arrow">→</div>' : "");
    }).join("") || '<p class="muted">暂无管线数据，请先运行评估任务。</p>';
    document.querySelectorAll(".integration-group").forEach(function (button) {
      button.classList.toggle("active", button.dataset.integrationGroup === state.integrationGroup);
    });
    var points = (pipeline.points || []).filter(function (point) { return point.group === state.integrationGroup; });
    if (!points.some(function (point) { return point.id === state.integrationPoint; })) state.integrationPoint = points[0] ? points[0].id : "";
    var groupLabel = state.integrationGroup === "visualization" ? "3.2 集成可视化展示" : "3.1 工具集成数据处理";
    $("integrationGroupHint").textContent = groupLabel + " · " + points.length + " 个验收小点";
    $("integrationCatalog").innerHTML = points.map(function (point) {
      return '<button class="integration-card ' + (point.id === state.integrationPoint ? "selected " : "") + 'mode-' + escapeHtml(point.mode) + '" data-integration-point="' + escapeHtml(point.id) + '" type="button">' +
        '<span class="card-code">' + escapeHtml(point.code) + '</span><strong>' + escapeHtml(point.name) + '</strong><small>' + escapeHtml(point.stage) + '</small><div><span class="pill ' + escapeHtml(text(point.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(statusLabel(point.status)) + '</span><em>' + escapeHtml(modeLabel(point.mode)) + '</em></div></button>';
    }).join("") || '<p class="empty">暂无验收小点数据</p>';
    var selected = points.find(function (point) { return point.id === state.integrationPoint; });
    renderIntegrationDetail(selected);
    $("integrationAdapters").innerHTML = (pipeline.adapters || []).map(function (adapter) {
      return '<div class="adapter-card ' + (adapter.mode === "real" ? "real" : "placeholder") + '"><div><strong>' + escapeHtml(adapter.tool_id) + '</strong><span class="adapter-status">' + escapeHtml(adapter.mode === "real" ? "REAL" : "PLACEHOLDER") + '</span></div><p>' + escapeHtml(text(adapter.schema_version)) + ' · ' + escapeHtml(text(adapter.finding_count, "0")) + ' findings</p><small>' + escapeHtml(text(adapter.raw_kind)) + '</small></div>';
    }).join("") || '<p class="muted">暂无适配器状态</p>';
  }

  function renderIntegrationDetail(point) {
    if (!point) {
      $("integrationDetail").innerHTML = '<div class="detail-empty"><span class="eyebrow">ACCEPTANCE EVIDENCE</span><h2>选择一个标书小点</h2><p>运行评估任务后，点击左侧能力卡片查看实现状态、数据证据与验收口径。</p></div>';
      return;
    }
    $("integrationDetail").innerHTML = '<div class="detail-kicker"><span class="card-code">' + escapeHtml(point.code) + '</span><span class="pill ' + escapeHtml(text(point.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(statusLabel(point.status)) + '</span></div>' +
      '<h2>' + escapeHtml(point.name) + '</h2><p class="detail-lead">' + escapeHtml(point.evidence) + '</p>' +
      '<div class="evidence-grid"><div><span>实现模式</span><strong>' + escapeHtml(modeLabel(point.mode)) + '</strong></div><div><span>实现指标</span><strong>' + escapeHtml(point.metric) + '</strong></div><div><span>Finding 证据</span><strong>' + escapeHtml(text(point.finding_count, "0")) + ' 条</strong></div><div><span>权重</span><strong>' + escapeHtml(text(point.weight)) + '</strong></div></div>' +
      '<div class="detail-callout"><span>数据处理链路</span><strong>' + escapeHtml(point.rule_group) + '</strong><p>结果进入统一评估报告，并可从 Findings 页面继续下钻原始证据和整改建议。</p></div>';
  }

  function renderVisualization() {
    var pipeline = integrationData();
    var stats = pipeline.stats || {};
    var summaryData = summary();
    $("visualizationScore").textContent = summaryData.evidence_coverage === undefined ? "--" : summaryData.evidence_coverage + "%";
    $("visualizationStats").innerHTML = [
      statCard("综合安全评分", summaryData.overall_score, text(summaryData.conclusion, "等待报告"), "blue"),
      statCard("覆盖检查点", summaryData.checkpoint_total, "指标体系覆盖", "green"),
      statCard("风险发现", summaryData.finding_total, "统一结果集", "orange"),
      statCard("筛选维度", "9", "工具 / 域 / 严重性 / 对象", "purple"),
    ].join("");
    $("vizPreview").innerHTML = '<div class="viz-score"><span>综合安全评分</span><strong>' + escapeHtml(text(summaryData.overall_score)) + '</strong><small>' + escapeHtml(text(summaryData.conclusion, "暂无结论")) + '</small></div>' +
      '<div class="viz-bars">' + Object.keys(summaryData.severity_count || {}).map(function (key) { return '<div><span>' + escapeHtml(key) + '</span><i style="width:' + Math.min(100, Number(summaryData.severity_count[key]) * 12 + 8) + '%"></i><b>' + escapeHtml(summaryData.severity_count[key]) + '</b></div>'; }).join("") + '</div>' +
      '<div class="viz-foot"><span>质量评分</span><strong>' + escapeHtml(text(stats.quality_score, "--")) + '%</strong><span>工具覆盖</span><strong>' + escapeHtml(text(stats.adapter_count, "0")) + ' adapters</strong></div>';
    var points = (pipeline.points || []).filter(function (point) { return point.group === "visualization"; });
    if (!points.some(function (point) { return point.id === state.visualizationPoint; })) state.visualizationPoint = points[0] ? points[0].id : "";
    $("visualizationCatalog").innerHTML = points.map(function (point) {
      return '<button class="viz-capability ' + (point.id === state.visualizationPoint ? "selected " : "") + 'mode-' + escapeHtml(point.mode) + '" data-viz-point="' + escapeHtml(point.id) + '" type="button"><span class="card-code">' + escapeHtml(point.code) + '</span><strong>' + escapeHtml(point.name) + '</strong><small>' + escapeHtml(point.metric) + '</small><span class="pill ' + escapeHtml(text(point.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(statusLabel(point.status)) + '</span></button>';
    }).join("") || '<p class="empty">暂无可视化能力数据</p>';
    var selected = points.find(function (point) { return point.id === state.visualizationPoint; });
    $("visualizationDetail").innerHTML = selected ? '<div class="detail-kicker"><span class="card-code">' + escapeHtml(selected.code) + '</span><span class="pill ' + escapeHtml(text(selected.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(statusLabel(selected.status)) + '</span></div><h2>' + escapeHtml(selected.name) + '</h2><p class="detail-lead">' + escapeHtml(selected.evidence) + '</p><div class="detail-callout"><span>截图佐证定位</span><strong>' + escapeHtml(selected.code + " · " + selected.name) + '</strong><p>该能力已在本工作台形成独立可见状态，可直接用于投标技术应答和现场演示。</p></div>' : '<p class="muted">选择能力查看验收证据。</p>';
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
      return !term || [cp.id, cp.name, cp.domain, cp.rule_group].join(" ").toLowerCase().indexOf(term) >= 0;
    }).map(function (cp) {
      var sc = byScore[cp.id] || {};
      return '<tr><td><code>' + escapeHtml(cp.id) + '</code></td><td>' + escapeHtml(text(cp.name)) + '</td><td>' + escapeHtml(text(cp.domain)) + '</td><td>' + escapeHtml(text(cp.weight)) + '</td><td><span class="pill ' + escapeHtml(text(sc.status, "UNKNOWN").toLowerCase()) + '">' + escapeHtml(text(sc.status, "UNKNOWN")) + '</span></td><td>' + escapeHtml(text(sc.score)) + '</td><td>' + escapeHtml(text(sc.finding_count, "0")) + '</td></tr>';
    }).join("") || '<tr><td colspan="7" class="empty">暂无检查点</td></tr>';
  }

  function renderRbacMatrix() {
    var matrix = state.rbacMatrix || {};
    var summary = matrix.summary || {};
    var rows = filteredRbacRows(matrix).slice(0, 80);
    $("rbacSummary").textContent = "Subjects " + text(summary.subject_count, "0") + " · Rows " + text(summary.matrix_row_count, "0") + " · Dangerous " + text(summary.dangerous_row_count, "0") + " · Matched " + rows.length;
    $("rbacRows").innerHTML = rows.map(function (row) {
      return '<tr><td>' + escapeHtml(text(row.subject)) + '</td><td>' + escapeHtml(text(row.scope)) + '</td><td>' + escapeHtml(text(row.role_kind)) + '/' + escapeHtml(text(row.role_name)) + '</td><td>' + escapeHtml((row.resources || []).join(", ")) + '</td><td>' + escapeHtml((row.verbs || []).join(", ")) + '</td><td>' + escapeHtml((row.danger_reasons || []).join(", ") || "normal") + '</td></tr>';
    }).join("") || '<tr><td colspan="6" class="empty">暂无 RBAC 矩阵数据</td></tr>';
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

  function renderFilters() {
    fillSelect("toolFilter", state.findings.map(function (f) { return f.tool_id; }), "全部工具");
    fillSelect("checkpointFilter", state.findings.map(function (f) { return f.checkpoint_id; }), "全部检查点");
    fillSelect("domainFilter", checkpointScores().map(function (s) { return s.domain; }), "全部域");
    fillSelect("severityFilter", state.findings.map(function (f) { return f.severity; }), "全部严重性");
    fillSelect("statusFilter", state.findings.map(function (f) { return f.status; }), "全部状态");
  }

  function fillSelect(id, values, label) {
    var el = $(id), current = el.value;
    var options = Array.from(new Set(values.filter(Boolean))).sort();
    el.innerHTML = '<option value="">' + label + '</option>' + options.map(function (v) { return '<option value="' + escapeHtml(v) + '">' + escapeHtml(v) + '</option>'; }).join("");
    el.value = options.indexOf(current) >= 0 ? current : "";
  }

  function filteredFindings() {
    var domains = {};
    checkpointScores().forEach(function (score) { domains[score.checkpoint_id || score.id] = score.domain || ""; });
    return state.findings.filter(function (f) {
      var asset = assetOf(f);
      var haystack = [f.title, f.rule_id, f.checkpoint_id, f.remediation, asset.label, JSON.stringify(safeJson(f.evidence_json, f.evidence || []))].join(" ").toLowerCase();
      return (!state.filters.tool_id || f.tool_id === state.filters.tool_id) &&
        (!state.filters.checkpoint_id || f.checkpoint_id === state.filters.checkpoint_id) &&
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
      return '<tr data-index="' + index + '"><td><span class="sev ' + escapeHtml(text(f.severity).toLowerCase()) + '">' + escapeHtml(text(f.severity)) + '</span></td><td><span class="pill ' + escapeHtml(text(f.status).toLowerCase()) + '">' + escapeHtml(text(f.status)) + '</span></td><td><code>' + escapeHtml(text(f.checkpoint_id)) + '</code></td><td>' + escapeHtml(text(f.tool_id)) + '</td><td>' + escapeHtml(asset.label) + '</td><td>' + escapeHtml(text(f.title)) + '</td></tr>';
    }).join("") || '<tr><td colspan="6" class="empty">没有匹配的 finding</td></tr>';
    document.querySelectorAll("#findingRows tr[data-index]").forEach(function (row) {
      row.addEventListener("click", function () { state.selectedFinding = rows[Number(row.dataset.index)]; renderFindingDetail(); });
    });
    if (!state.selectedFinding && rows[0]) state.selectedFinding = rows[0];
    renderFindingDetail();
  }

  function renderFindingDetail() {
    var f = state.selectedFinding;
    if (!f) { $("findingDetail").innerHTML = '<h2>Finding 详情</h2><p class="muted">暂无数据</p>'; return; }
    var evidence = safeJson(f.evidence_json, f.evidence || []);
    var asset = assetOf(f);
    var related = relatedFindings(f).slice(0, 8);
    $("findingDetail").innerHTML = '<div class="detail-head"><h2>' + escapeHtml(text(f.title)) + '</h2><button id="copyRemediationBtn" type="button">复制整改</button></div>' +
      '<div class="detail-tags"><span class="sev ' + escapeHtml(text(f.severity).toLowerCase()) + '">' + escapeHtml(text(f.severity)) + '</span><span class="pill ' + escapeHtml(text(f.status).toLowerCase()) + '">' + escapeHtml(text(f.status)) + '</span><code>' + escapeHtml(text(f.checkpoint_id)) + '</code><code>' + escapeHtml(text(f.rule_id)) + '</code></div>' +
      '<h3>Asset</h3><div class="asset-card"><strong>' + escapeHtml(asset.label) + '</strong><span>' + escapeHtml([asset.namespace, asset.kind, asset.name].filter(Boolean).join(" / ") || "_cluster") + '</span></div>' +
      '<h3>Evidence</h3><pre>' + escapeHtml(JSON.stringify(evidence, null, 2)) + '</pre>' +
      '<h3>Remediation</h3><p id="remediationText">' + escapeHtml(text(f.remediation, "暂无修复建议")) + '</p>' +
      '<h3>同资产 Findings</h3><div class="related-findings">' + (related.length ? related.map(function (item) {
        return '<button class="related-finding" data-finding-id="' + escapeHtml(text(item.id)) + '" type="button"><span class="pill ' + escapeHtml(text(item.status).toLowerCase()) + '">' + escapeHtml(text(item.status)) + '</span><code>' + escapeHtml(text(item.checkpoint_id)) + '</code><strong>' + escapeHtml(text(item.title)) + '</strong></button>';
      }).join("") : '<p class="muted">暂无同资产 finding</p>') + '</div>';
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
    renderStubSection("cloud_api_stub", "apiStubStats", "apiStubDetails", "API findings");
    renderStubSection("smart_cloud_stub", "smartStubStats", "smartStubDetails", "智算 findings");
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
    return '<div><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(findings.length) + '</strong></div>' +
      '<div><span>F/W/U</span><strong>' + fail + '/' + warn + '/' + unknown + '</strong></div>' +
      '<div><span>Schema</span><strong>' + escapeHtml(text(snapshot.schema_version, "stub/v1")) + '</strong></div>';
  }

  function stubDetails(toolId, findings, raw) {
    var params = raw.target_parameters || {};
    var capabilities = raw.capabilities || [];
    var rows = findings.map(function (finding) {
      return '<tr><td><span class="pill ' + escapeHtml(text(finding.status).toLowerCase()) + '">' + escapeHtml(text(finding.status)) + '</span></td><td><span class="sev ' + escapeHtml(text(finding.severity).toLowerCase()) + '">' + escapeHtml(text(finding.severity)) + '</span></td><td><code>' + escapeHtml(text(finding.rule_id)) + '</code></td><td>' + escapeHtml(text(finding.title)) + '</td></tr>';
    }).join("") || '<tr><td colspan="4" class="empty">暂无 stub finding</td></tr>';
    return '<div class="stub-meta">' +
      '<div><h3>Parameters</h3><pre>' + escapeHtml(JSON.stringify(params, null, 2)) + '</pre></div>' +
      '<div><h3>Capabilities</h3><div class="tag-list">' + (capabilities.length ? capabilities.map(function (item) { return '<span>' + escapeHtml(item) + '</span>'; }).join("") : '<span>stub</span>') + '</div></div>' +
      '</div><h3>' + escapeHtml(toolId) + '</h3><div class="table-wrap"><table><thead><tr><th>Status</th><th>Severity</th><th>Rule</th><th>Title</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
  }

  function renderMetrics() {
    $("metricRows").innerHTML = state.checkpoints.map(function (cp) {
      return '<tr><td><code>' + escapeHtml(cp.id) + '</code> ' + escapeHtml(text(cp.name)) + '</td><td>' + escapeHtml(text(cp.domain)) + '</td><td><input class="enabled-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="checkbox" ' + (cp.enabled === false ? "" : "checked") + ' /></td><td>' + escapeHtml(text(cp.weight)) + '</td><td><input class="weight-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="number" value="' + escapeHtml(text(cp.weight, 1)) + '" step="0.1" min="0" /></td><td><input class="applicability-input wide-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="text" value="' + escapeHtml(JSON.stringify(cp.applicability || {})) + '" /></td><td><input class="rule-enabled-input wide-input" data-checkpoint="' + escapeHtml(cp.id) + '" type="text" value="' + escapeHtml(JSON.stringify(cp.rule_enabled || {})) + '" /></td><td><button class="save-weight" data-checkpoint="' + escapeHtml(cp.id) + '" type="button">保存并重算</button><button class="save-checkpoint-meta" data-checkpoint="' + escapeHtml(cp.id) + '" type="button">保存元数据</button></td></tr>';
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
    document.querySelectorAll(".integration-group").forEach(function (button) {
      button.addEventListener("click", function () {
        state.integrationGroup = button.dataset.integrationGroup;
        state.integrationPoint = "";
        renderIntegration();
      });
    });
    $("integrationCatalog").addEventListener("click", function (event) {
      var card = event.target.closest("[data-integration-point]");
      if (!card) return;
      state.integrationPoint = card.dataset.integrationPoint;
      renderIntegration();
    });
    $("visualizationCatalog").addEventListener("click", function (event) {
      var card = event.target.closest("[data-viz-point]");
      if (!card) return;
      state.visualizationPoint = card.dataset.vizPoint;
      renderVisualization();
    });
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
    [["toolFilter", "tool_id"], ["checkpointFilter", "checkpoint_id"], ["domainFilter", "domain"], ["severityFilter", "severity"], ["statusFilter", "status"], ["namespaceFilter", "namespace"], ["kindFilter", "kind"], ["nameFilter", "name"], ["keywordFilter", "keyword"]].forEach(function (pair) {
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

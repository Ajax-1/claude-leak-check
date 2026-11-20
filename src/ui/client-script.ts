export const CLIENT_SCRIPT = String.raw`
(function () {
  var state = {
    report: window.__AUDIT_REPORT__,
    brand: window.__BRAND_CONFIG__,
    token: window.__INTERACTIVE_TOKEN__ || "",
    lang: "zh",
    theme: "dark",
    masked: true,
    domainFilter: "all",
    liveTunActive: null,
    drillLoading: false,
    restoreLoading: false,
    posterRatio: "16:9"
  };

  var I18N = {
    zh: {
      eyebrow: "100% 纯只读本地审计 · 0 凭证读取 · 0 配置修改",
      heroTitle: "Claude 防封号与分流泄漏本地体检报告",
      heroSub: "专抓网页检测站测不到的「桌面端与终端分流盲区、{N} 个遥测/反欺诈暗桩域名、OAuth 登录双 IP 横跳、npm 进程裸奔与断代理瞬间泄漏」。",
      privacyLocked: "IP 已打码",
      privacyUnlocked: "显示原 IP",
      shareBtn: "导出体检卡",
      redlineHeader: "存在高危泄漏项（总分上限锁定 45 分）",
      scoreDenom: "综合安全分 / 100",
      gradeLabels: {
        "S+": "S+ · 断网零泄漏金盾认证",
        "A+": "A+ · 常态防漏极佳（演练可升 S+）",
        "A": "A · 防护良好（演练可升 S+）",
        "B": "B · 存在次要分流隐患",
        "C": "C · 存在明显配置漏洞",
        "D": "D · 高风险环境",
        "F": "F · 极高危（存在封号红线漏洞）"
      },
      primaryExit: "终端 / 桌面端主出口",
      oauthSync: "浏览器 vs 桌面端 OAuth",
      webrtcStatus: "浏览器 WebRTC UDP",
      tunAdapter: "活跃虚拟网卡 (TUN)",
      timezoneLabel: "本机系统时区",
      syncMatched: "100% 同源一致 ✓",
      syncMismatch: "双 IP 横跳高危 ✕",
      syncChecking: "正在本地比对...",
      syncStaticOnly: "静态模式",
      webrtcClean: "0 公网泄漏 ✓",
      webrtcLeak: "暴露公网 IP ✕",
      drillTitle: "离线交互式「断网防漏演练」",
      drillSub: "无需管理员权限改配置——手动关闭 TUN 或退出代理软件 3 秒后点击下方测试，实测断代理瞬间是否会被系统防火墙拦截（仅请求 1.1.1.1 公共回显，不访问 Anthropic）。",
      step1Num: "STEP 01 · 基准锁定",
      step1Title: "记录常态代理出口",
      step1Desc: "已锁定当前常态出口基准，准备测试断网兜底能力。",
      step2Num: "STEP 02 · 人工断梯",
      step2Title: "手动关闭 TUN 或退出代理",
      step2DescOn: "当前检测到 TUN 仍开启，请先手动关闭代理再测。",
      step2DescOff: "已检测到 TUN 虚拟网卡断开！现在可点击下方发射探针。",
      step3Num: "STEP 03 · 发射探针",
      step3Title: "无账号公共接口探测",
      step3Desc: "2.5 秒超时测试物理网卡是否会直连漏出真实宽带 IP。",
      step4Num: "STEP 04 · 恢复防呆",
      step4Title: "重开代理并复检绿灯",
      step4Desc: "演练结束后务必重开代理点复检，防止忘开梯子误点 Claude！",
      runDrillBtn: "发射无账号防漏探针",
      runningDrillBtn: "正在探测拦截延迟...",
      verifyRestoreBtn: "我已重开代理，点此复检绿灯",
      offlineStaticDrillNote: "当前为导出的静态离线 HTML 副本；如需运行实时断网演练，请在终端执行 npx claude-leak-check。",
      restoreBannerText: "[提醒] 断网演练已完成，请立即重新开启代理软件与 TUN，并点击右侧按钮确认海外出口恢复后再打开 Claude。",
      restoreBannerBtn: "立即复检恢复状态",
      secModulesTitle: "五大核心防封维度评分明细",
      secModulesCap: "每一分扣除均有据可查 · 纯本地静态与无凭证探测",
      secMatrixTitle: "{N} 个核心与第三方风控暗桩域名矩阵",
      secMatrixCap: "官方域名默认采用「纯本地零发包核验」（系统 DNS + 内核路由表 + 分流规则静态审计）",
      filterAll: "全部",
      filterCore: "Anthropic 核心",
      filterGate: "Statsig 灰度开关",
      filterTel: "Sentry & Datadog 遥测",
      filterFraud: "Sift 反欺诈 & 支付客服",
      filterAuth: "OAuth / 验证 / 纯 IP",
      secBinTitle: "本机 Claude 全家桶入口与防火墙焊死清单",
      secBinCap: "覆盖桌面端主程序、Chromium Helpers、ShipIt 更新器、后台内置 CLI、IDE 扩展与全局命令",
      fwLocked: "防火墙已焊死 ✓",
      fwUnlocked: "未锁定 / 可直连",
      npmDanger: "npm node 进程盲区 ✕",
      modalTitle: "导出脱敏体检卡",
      modalSub: "真实 IP、系统用户名与节点信息已在画布层自动打码（如 198.51.*.*），可直接截图或保存图片分享。",
      ratio169: "16:9 横版",
      ratio34: "3:4 竖版",
      copyImgBtn: "复制图片",
      downloadPngBtn: "下载 PNG",
      copyTextBtn: "复制文本摘要",
      exportHtmlBtn: "下载单文件离线 HTML",
      closeBtn: "关闭",
      toastCopiedImg: "已将高清脱敏海报复制到剪贴板！可直接粘贴发送",
      toastCopiedText: "已复制分享配文到剪贴板！",
      toastRestoreOk: "绿灯复检通过！TUN 与安全海外出口已恢复，可以放心使用 Claude。",
      toastRestoreFail: "尚未检测到 TUN 与受支持海外出口恢复，请确认代理已开启并连接成功！"
    },
    en: {
      eyebrow: "100% Read-Only Local Audit · Zero Credential Access · Zero System Modification",
      heroTitle: "Claude Anti-Ban & Split-Tunnel Leak Diagnostic",
      heroSub: "Catches local blindspots invisible to web checkers: CLI/Desktop TUN bypasses, {N} stealth telemetry & anti-fraud domains, browser OAuth dual-IP hops, npm 'node' firewall blindspots, and kill-switch gaps.",
      privacyLocked: "IP Redacted",
      privacyUnlocked: "Local Raw IP",
      shareBtn: "Share Poster",
      redlineHeader: "Fatal Redline Triggered (Score Capped ≤ 45 / 100)",
      scoreDenom: "Security Score / 100",
      gradeLabels: {
        "S+": "S+ · Kill-Switch Verified Gold Shield",
        "A+": "A+ · Strong Protection (Run Drill for S+)",
        "A": "A · Good Posture (Run Drill for S+)",
        "B": "B · Minor Split-Routing Risks",
        "C": "C · Notable Configuration Gaps",
        "D": "D · High Risk Posture",
        "F": "F · Critical Ban Risk (Redline Triggered)"
      },
      primaryExit: "CLI / Desktop Primary Exit",
      oauthSync: "Browser vs CLI OAuth Sync",
      webrtcStatus: "Browser WebRTC UDP",
      tunAdapter: "Active Virtual TUN",
      timezoneLabel: "Host OS Timezone",
      syncMatched: "100% Identical Exit ✓",
      syncMismatch: "Dual-IP Hop Detected ✕",
      syncChecking: "Comparing locally...",
      syncStaticOnly: "Static Snapshot",
      webrtcClean: "0 Public Leak ✓",
      webrtcLeak: "Public IP Leaked ✕",
      drillTitle: "Interactive Offline Kill-Switch Drill",
      drillSub: "Without touching your settings: manually toggle TUN off or quit your proxy for 3s, then fire a zero-account probe to public echo 1.1.1.1 (never touches Anthropic) to verify firewall lockdown.",
      step1Num: "STEP 01 · BASELINE",
      step1Title: "Safe Baseline Recorded",
      step1Desc: "Normal overseas proxy exit snapshot locked.",
      step2Num: "STEP 02 · CUT PROXY",
      step2Title: "Turn Off TUN / Quit Proxy",
      step2DescOn: "TUN is currently ON. Toggle it off manually before testing.",
      step2DescOff: "TUN disconnect detected! Ready to fire probe below.",
      step3Num: "STEP 03 · FIRE PROBE",
      step3Title: "Zero-Account Public Probe",
      step3Desc: "Tests whether traffic falls back to your real ISP broadband.",
      step4Num: "STEP 04 · RESTORE GUARD",
      step4Title: "Re-Enable Proxy & Verify",
      step4Desc: "Verify green status after testing so you never launch Claude naked!",
      runDrillBtn: "Fire Kill-Switch Probe",
      runningDrillBtn: "Probing Firewall...",
      verifyRestoreBtn: "Proxy Re-Enabled, Verify Green",
      offlineStaticDrillNote: "Viewing exported static HTML snapshot. Run 'npx claude-leak-check' locally to use the live Kill-Switch Drill.",
      restoreBannerText: "[Notice] Kill-Switch Drill completed. Re-enable your proxy/TUN and click Verify before opening Claude.",
      restoreBannerBtn: "Verify Proxy Restored",
      secModulesTitle: "5-Pillar Security Score Breakdown",
      secModulesCap: "Every point deduction is explainable · 100% read-only local diagnostics",
      secMatrixTitle: "{N} Core & Stealth Telemetry Domain Matrix",
      secMatrixCap: "Official Anthropic domains use Zero-Packet local verification (OS DNS + kernel route + static rule audit)",
      filterAll: "All",
      filterCore: "Anthropic Core",
      filterGate: "Statsig Gates",
      filterTel: "Sentry & Datadog",
      filterFraud: "Sift, Stripe & Intercom",
      filterAuth: "OAuth, Turnstile & Raw IP",
      secBinTitle: "Local Claude Binary Footprint & Firewall Lockdown",
      secBinCap: "Covers Claude.app, Chromium Helpers, ShipIt updater, bundled claude-code, IDE extensions & global CLI",
      fwLocked: "Firewall Locked ✓",
      fwUnlocked: "Unprotected",
      npmDanger: "npm 'node' Blindspot ✕",
      modalTitle: "Export Redacted Diagnostic Card",
      modalSub: "Real IPs, usernames, and node names are strictly masked on canvas (e.g. 198.51.*.*), ready for X, Reddit, or Discord.",
      ratio169: "16:9 Landscape (X / GitHub)",
      ratio34: "3:4 Portrait (Social / Mobile)",
      copyImgBtn: "Copy Retina PNG",
      downloadPngBtn: "Download PNG",
      copyTextBtn: "Copy Share Caption",
      exportHtmlBtn: "Download Standalone HTML",
      closeBtn: "Close",
      toastCopiedImg: "Copied Retina PNG card to clipboard!",
      toastCopiedText: "Copied share caption to clipboard!",
      toastRestoreOk: "Verified! TUN and safe overseas exit are back online.",
      toastRestoreFail: "TUN or safe overseas exit is not yet active. Check your proxy client!"
    }
  };

  function t(key) {
    return I18N[state.lang][key] || key;
  }

  function pick(bi) {
    if (!bi) return "";
    return state.lang === "zh" ? bi.zh : bi.en;
  }

  function esc(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatExitIp(exitObj) {
    if (!exitObj) return "—";
    if (!state.masked && exitObj.ipRawForLocalToggle) {
      return exitObj.ipRawForLocalToggle;
    }
    return exitObj.ipMasked || "—";
  }

  function showToast(msg) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(function () {
      el.classList.remove("show");
    }, 3200);
  }

  function scoreColor(score, redline, splus) {
    if (redline || score <= 45) return "var(--crit)";
    if (splus) return "var(--gold)";
    if (score >= 80) return "var(--pass)";
    return "var(--warn)";
  }

  function renderAll() {
    var r = state.report;
    document.documentElement.setAttribute("data-theme", state.theme);
    document.documentElement.setAttribute("lang", state.lang === "zh" ? "zh-CN" : "en");

    // Sticky safety banner if drill ran and proxy not restored yet
    var banner = document.getElementById("restoreBanner");
    if (r.killSwitchDrill && r.killSwitchDrill.executed && !r.killSwitchDrill.proxyRestoredVerified) {
      banner.classList.add("visible");
      document.getElementById("restoreBannerMsg").textContent = t("restoreBannerText");
      document.getElementById("restoreBannerBtn").textContent = t("restoreBannerBtn");
    } else {
      banner.classList.remove("visible");
    }

    // Navbar controls
    document.getElementById("navEyebrow").textContent = r.demoMode
      ? "DEMO (" + r.demoMode.toUpperCase() + ") · " + t("eyebrow")
      : t("eyebrow");
    document.getElementById("maskBtnLabel").textContent = state.masked
      ? t("privacyLocked")
      : t("privacyUnlocked");
    document.getElementById("langBtn").textContent = state.lang === "zh" ? "EN / 中文" : "中文 / EN";
    document.getElementById("themeBtn").textContent = state.theme === "dark" ? "Light" : "Dark";
    document.getElementById("shareBtnText").textContent = t("shareBtn");

    // Hero
    document.getElementById("heroTitle").textContent = t("heroTitle");
    document.getElementById("heroSub").textContent = t("heroSub").replace("{N}", String(r.domainMatrix.length));

    // Redline Banner
    var rlWrap = document.getElementById("redlineWrap");
    if (r.redlineTriggered && r.redlineReasons.length > 0) {
      rlWrap.style.display = "block";
      document.getElementById("redlineTitleText").textContent = t("redlineHeader");
      document.getElementById("redlineList").innerHTML = r.redlineReasons
        .map(function (item) {
          return "<li>" + esc(pick(item)) + "</li>";
        })
        .join("");
    } else {
      rlWrap.style.display = "none";
    }

    // Score Ring
    var ringCircumference = 2 * Math.PI * 52; // r=52 -> 326.72
    var pct = Math.max(0, Math.min(100, r.finalScore)) / 100;
    var ringFg = document.getElementById("scoreRingFg");
    ringFg.style.strokeDasharray = String(ringCircumference);
    ringFg.style.strokeDashoffset = String(ringCircumference * (1 - pct));
    ringFg.style.stroke = scoreColor(r.finalScore, r.redlineTriggered, r.killSwitchVerifiedBadge);

    document.getElementById("scoreNum").textContent = String(r.finalScore);
    document.getElementById("scoreDenom").textContent = t("scoreDenom");

    var gradeEl = document.getElementById("gradePill");
    gradeEl.textContent = t("gradeLabels")[r.grade] || r.grade;
    gradeEl.className =
      "grade-pill " +
      (r.grade === "S+"
        ? "grade-splus"
        : r.redlineTriggered || r.grade === "F"
          ? "grade-crit"
          : r.finalScore >= 80
            ? "grade-pass"
            : "grade-warn");

    // Primary Exit & OAuth Sync KV rows
    var exitText = r.primaryExit
      ? r.primaryExit.countryCode +
        " · " +
        formatExitIp(r.primaryExit) +
        (r.primaryExit.asnType !== "unknown" ? " (" + r.primaryExit.asnType.toUpperCase() + ")" : "")
      : "Offline / Unreachable";

    var syncBadgeHtml = "";
    if (r.browserSync && r.browserSync.completed) {
      if (r.browserSync.matchesCliExit === true) {
        syncBadgeHtml = '<span class="status-badge st-pass">' + esc(t("syncMatched")) + "</span>";
      } else if (r.browserSync.matchesCliExit === false) {
        syncBadgeHtml = '<span class="status-badge st-crit">' + esc(t("syncMismatch")) + "</span>";
      } else {
        syncBadgeHtml = '<span class="status-badge st-info">' + esc(r.browserSync.browserExitIpMasked || "—") + "</span>";
      }
    } else if (state.token) {
      syncBadgeHtml = '<span class="status-badge st-info">' + esc(t("syncChecking")) + "</span>";
    } else {
      syncBadgeHtml = '<span class="status-badge st-info">' + esc(t("syncStaticOnly")) + "</span>";
    }

    var webrtcHtml = "";
    if (r.browserSync && r.browserSync.webrtcTested) {
      webrtcHtml = r.browserSync.webrtcHasDomesticOrMismatchLeak
        ? '<span class="status-badge st-crit">' + esc(t("webrtcLeak")) + "</span>"
        : '<span class="status-badge st-pass">' + esc(t("webrtcClean")) + "</span>";
    } else {
      webrtcHtml = '<span class="status-badge st-info">' + esc(state.token ? t("syncChecking") : t("syncStaticOnly")) + "</span>";
    }

    var tunList = r.environmentSummary.activeUtunInterfaces;
    var tunHtml =
      tunList && tunList.length > 0
        ? '<span class="status-badge st-pass tabular">' + esc(tunList.join(", ")) + "</span>"
        : '<span class="status-badge st-crit">OFF (裸奔风险)</span>';

    var tzClass = r.environmentSummary.isMainlandTimezone ? "st-warn" : "st-pass";
    var passCount = r.domainMatrix.filter(function (d) { return d.status === "pass"; }).length;
    var fwLockedAll = r.firewallAudit.claudeAppFullyLocked && r.firewallAudit.claudeCliLocked;
    var nonRawTotal = r.domainMatrix.filter(function (d) { return d.category !== "raw_ip"; }).length;
    var fakeIpCount = r.domainMatrix.filter(function (d) { return d.isFakeIp; }).length;

    document.getElementById("postureMiniGrid").innerHTML =
      '<div class="posture-mini-card">' +
        '<span class="posture-mini-k">' + (state.lang === "zh" ? "暗桩矩阵同源" : "STEALTH MATRIX") + "</span>" +
        '<span class="posture-mini-v tabular" style="color:' + (passCount === r.domainMatrix.length ? "var(--pass)" : "var(--crit)") + '">' + passCount + " / " + r.domainMatrix.length + " PASS</span>" +
      "</div>" +
      '<div class="posture-mini-card">' +
        '<span class="posture-mini-k">' + (state.lang === "zh" ? "Fake-IP 劫持" : "FAKE-IP DNS") + "</span>" +
        '<span class="posture-mini-v tabular" style="color:' + (fakeIpCount === nonRawTotal && nonRawTotal > 0 ? "var(--pass)" : "var(--warn)") + '">' + (fakeIpCount === nonRawTotal && nonRawTotal > 0 ? "ACTIVE ✓" : fakeIpCount + "/" + nonRawTotal) + "</span>" +
      "</div>" +
      '<div class="posture-mini-card">' +
        '<span class="posture-mini-k">' + (state.lang === "zh" ? "防火墙焊死" : "APP FIREWALL") + "</span>" +
        '<span class="posture-mini-v tabular" style="color:' + (fwLockedAll ? "var(--pass)" : "var(--warn)") + '">' + (fwLockedAll ? "LuLu LOCKED ✓" : (state.lang === "zh" ? "未全量锁定" : "UNLOCKED")) + "</span>" +
      "</div>" +
      '<div class="posture-mini-card">' +
        '<span class="posture-mini-k">' + (state.lang === "zh" ? "官方零发包保护" : "ANTHROPIC PROBE") + "</span>" +
        '<span class="posture-mini-v tabular" style="color:var(--pass)">0 PACKET ✓</span>' +
      "</div>";

    document.getElementById("scoreKvStack").innerHTML =
      '<div class="kv-row"><span class="kv-label">' + esc(t("primaryExit")) + '</span><span class="kv-val tabular">' + esc(exitText) + "</span></div>" +
      '<div class="kv-row"><span class="kv-label">' + esc(t("oauthSync")) + '</span><span class="kv-val">' + syncBadgeHtml + "</span></div>" +
      '<div class="kv-row"><span class="kv-label">' + esc(t("webrtcStatus")) + '</span><span class="kv-val">' + webrtcHtml + "</span></div>" +
      '<div class="kv-row"><span class="kv-label">' + esc(t("tunAdapter")) + '</span><span class="kv-val">' + tunHtml + "</span></div>" +
      '<div class="kv-row"><span class="kv-label">' + esc(t("timezoneLabel")) + '</span><span class="kv-val"><span class="status-badge ' + tzClass + ' tabular">' + esc(r.environmentSummary.systemTimezone) + "</span></span></div>";

    // Kill-Switch Drill Cabin
    document.getElementById("drillTitle").textContent = t("drillTitle");
    document.getElementById("drillSub").textContent = t("drillSub");

    var tunCurrentlyOn =
      state.liveTunActive !== null
        ? state.liveTunActive
        : r.environmentSummary.activeUtunInterfaces.length > 0;
    var drill = r.killSwitchDrill;
    var drillPassed =
      drill.executed &&
      (drill.verdict === "global_blocked" || drill.verdict === "app_firewall_locked");

    document.getElementById("drillSteps").innerHTML =
      '<div class="drill-step-card done">' +
        '<span class="step-num tabular">' + esc(t("step1Num")) + "</span>" +
        '<span class="step-title">' + esc(t("step1Title")) + "</span>" +
        '<span class="step-desc">' + esc(t("step1Desc")) + "</span>" +
      "</div>" +
      '<div class="drill-step-card ' + (!tunCurrentlyOn || drill.executed ? "done" : "active") + '">' +
        '<span class="step-num tabular">' + esc(t("step2Num")) + "</span>" +
        '<span class="step-title">' + esc(t("step2Title")) + "</span>" +
        '<span class="step-desc">' + esc(tunCurrentlyOn ? t("step2DescOn") : t("step2DescOff")) + "</span>" +
      "</div>" +
      '<div class="drill-step-card ' + (drillPassed ? "done" : !tunCurrentlyOn ? "active" : "") + '">' +
        '<span class="step-num tabular">' + esc(t("step3Num")) + "</span>" +
        '<span class="step-title">' + esc(t("step3Title")) + "</span>" +
        '<span class="step-desc">' + esc(t("step3Desc")) + "</span>" +
      "</div>" +
      '<div class="drill-step-card ' + (drill.executed && drill.proxyRestoredVerified ? "done" : drill.executed ? "active" : "") + '">' +
        '<span class="step-num tabular">' + esc(t("step4Num")) + "</span>" +
        '<span class="step-title">' + esc(t("step4Title")) + "</span>" +
        '<span class="step-desc">' + esc(t("step4Desc")) + "</span>" +
      "</div>";

    var drillResBox = document.getElementById("drillResultBox");
    drillResBox.innerHTML =
      "<strong>" + esc(pick(drill.verdictTitle)) + "</strong><br/><span>" + esc(pick(drill.verdictDetail)) + "</span>";
    drillResBox.style.borderColor =
      drill.verdict === "leaked"
        ? "var(--crit)"
        : drillPassed
          ? "var(--pass)"
          : drill.verdict === "proxy_still_on"
            ? "var(--warn)"
            : "var(--core-border)";

    var drillActions = document.getElementById("drillActions");
    if (!state.token) {
      drillActions.innerHTML = '<span class="step-desc">' + esc(t("offlineStaticDrillNote")) + "</span>";
    } else {
      var restoreBtnHtml =
        drill.executed && !drill.proxyRestoredVerified
          ? '<button class="chip-btn" id="btnVerifyRestore">' + esc(t("verifyRestoreBtn")) + "</button>"
          : "";
      drillActions.innerHTML =
        '<button class="cta-island-btn cta-accent" id="btnRunDrill"' + (state.drillLoading ? " disabled" : "") + ">" +
          "<span>" + esc(state.drillLoading ? t("runningDrillBtn") : t("runDrillBtn")) + "</span>" +
          '<span class="btn-icon-circle">→</span>' +
        "</button>" +
        restoreBtnHtml;

      var btnRun = document.getElementById("btnRunDrill");
      if (btnRun) btnRun.onclick = handleRunDrill;
      var btnRest = document.getElementById("btnVerifyRestore");
      if (btnRest) btnRest.onclick = handleVerifyRestore;
    }

    // 5 Modules Breakdown
    document.getElementById("secModulesTitle").textContent = t("secModulesTitle");
    document.getElementById("secModulesCap").textContent = t("secModulesCap");

    document.getElementById("modulesGrid").innerHTML = r.modules
      .map(function (mod, idx) {
        var spanClass = idx < 2 ? "mod-card-wide" : "mod-card-third";
        var barPct = Math.round((mod.earnedPoints / mod.maxPoints) * 100);
        var barColor =
          mod.status === "critical"
            ? "var(--crit)"
            : mod.status === "warn"
              ? "var(--warn)"
              : "var(--pass)";
        var findingsHtml = mod.findings
          .map(function (f) {
            var badgeCls =
              f.severity === "critical" || f.severity === "fail"
                ? "st-crit"
                : f.severity === "warn"
                  ? "st-warn"
                  : f.severity === "info"
                    ? "st-info"
                    : "st-pass";
            var ptsTag =
              f.pointsDeducted > 0
                ? "-" + f.pointsDeducted + " pts"
                : f.severity === "info"
                  ? "INFO"
                  : "PASS";
            return (
              '<div class="finding-item">' +
                '<div class="finding-top">' +
                  "<span>" + esc(pick(f.title)) + "</span>" +
                  '<span class="status-badge ' + badgeCls + ' tabular">' + esc(ptsTag) + "</span>" +
                "</div>" +
                '<div class="finding-detail">' + esc(pick(f.detail)) + "</div>" +
                (f.pointsDeducted > 0 || f.severity === "info"
                  ? '<div class="finding-fix">→ ' + esc(pick(f.remediation)) + "</div>"
                  : "") +
              "</div>"
            );
          })
          .join("");

        return (
          '<div class="bezel-shell ' + spanClass + '">' +
            '<div class="bezel-core">' +
              '<div class="mod-head">' +
                '<span class="card-title">' + esc(pick(mod.name)) + "</span>" +
                '<span class="mod-score-pill tabular">' + mod.earnedPoints + " / " + mod.maxPoints + "</span>" +
              "</div>" +
              '<div class="mod-bar-track"><div class="mod-bar-fill" style="width:' + barPct + "%;background:" + barColor + '"></div></div>' +
              '<div class="finding-list">' + findingsHtml + "</div>" +
            "</div>" +
          "</div>"
        );
      })
      .join("");

    // Dynamic Domain Matrix
    var totalDoms = r.domainMatrix.length;
    var countCat = function (cat) {
      return r.domainMatrix.filter(function (d) {
        if (cat === "auth_raw") return d.category === "auth_infra" || d.category === "raw_ip";
        return d.category === cat;
      }).length;
    };
    document.getElementById("secMatrixTitle").textContent = t("secMatrixTitle").replace("{N}", String(totalDoms));
    document.getElementById("secMatrixCap").textContent = t("secMatrixCap");

    var filters = [
      { id: "all", label: t("filterAll") + " (" + totalDoms + ")" },
      { id: "core", label: t("filterCore") + " (" + countCat("core") + ")" },
      { id: "feature_gate", label: t("filterGate") + " (" + countCat("feature_gate") + ")" },
      { id: "telemetry", label: t("filterTel") + " (" + countCat("telemetry") + ")" },
      { id: "antifraud_billing", label: t("filterFraud") + " (" + countCat("antifraud_billing") + ")" },
      { id: "auth_raw", label: t("filterAuth") + " (" + countCat("auth_raw") + ")" }
    ];
    document.getElementById("domainFilterBar").innerHTML = filters
      .map(function (f) {
        var activeStyle =
          state.domainFilter === f.id
            ? 'style="border-color:var(--accent);background:var(--accent-soft);color:var(--accent)"'
            : "";
        return (
          '<button class="chip-btn" data-filter="' + f.id + '" ' + activeStyle + ">" +
            esc(f.label) +
          "</button>"
        );
      })
      .join("");

    Array.prototype.forEach.call(
      document.querySelectorAll("#domainFilterBar [data-filter]"),
      function (btn) {
        btn.onclick = function () {
          state.domainFilter = btn.getAttribute("data-filter");
          renderAll();
        };
      }
    );

    var filteredDomains = r.domainMatrix.filter(function (d) {
      if (state.domainFilter === "all") return true;
      if (state.domainFilter === "auth_raw") {
        return d.category === "auth_infra" || d.category === "raw_ip";
      }
      return d.category === state.domainFilter;
    });

    document.getElementById("domainGrid").innerHTML = filteredDomains
      .map(function (d) {
        var cls = d.status === "critical" ? "dom-crit" : d.status === "warn" ? "dom-warn" : "";
        var dotColor =
          d.status === "critical"
            ? "var(--crit)"
            : d.status === "warn"
              ? "var(--warn)"
              : "var(--pass)";
        return (
          '<div class="domain-cell ' + cls + '" title="' + esc(pick(d.riskNote)) + '">' +
            '<div class="dom-host-row">' +
              '<span class="dom-host tabular">' + esc(d.host) + "</span>" +
              '<span class="dom-dot" style="background:' + dotColor + '"></span>' +
            "</div>" +
            '<div class="dom-label">' + esc(pick(d.label)) + "</div>" +
            '<div class="dom-meta-row tabular">' +
              "<span>NIC: " + esc(d.routeInterface) + (d.isFakeIp ? " · Fake-IP" : "") + "</span>" +
              "<span>" + esc(d.edgeCountry || "—") + "</span>" +
            "</div>" +
          "</div>"
        );
      })
      .join("");

    // Binaries & Firewall Section
    document.getElementById("secBinTitle").textContent = t("secBinTitle");
    document.getElementById("secBinCap").textContent = t("secBinCap");

    document.getElementById("binList").innerHTML =
      r.binaries.length === 0
        ? '<div class="finding-item"><div class="finding-detail">未在默认目录扫描到 Claude 桌面端或全局 CLI。 / No local Claude Desktop or global CLI detected in standard paths.</div></div>'
        : r.binaries
            .map(function (b) {
              var badge =
                b.kind === "global-cli-npm-node"
                  ? '<span class="status-badge st-crit">' + esc(t("npmDanger")) + "</span>"
                  : b.firewallCovered
                    ? '<span class="status-badge st-pass">' + esc(t("fwLocked")) + "</span>"
                    : '<span class="status-badge st-warn">' + esc(t("fwUnlocked")) + "</span>";
              return (
                '<div class="bin-row">' +
                  '<div style="flex:1;min-width:240px">' +
                    '<div style="font-weight:700;font-size:13.5px">' + esc(b.name) + "</div>" +
                    '<div class="bin-path tabular">' + esc(b.displayPath) + "</div>" +
                    '<div class="bin-note">' + esc(pick(b.note)) + "</div>" +
                  "</div>" +
                  "<div>" + badge + "</div>" +
                "</div>"
              );
            })
            .join("");

    // Modal labels
    document.getElementById("modalTitle").textContent = t("modalTitle");
    document.getElementById("modalSub").textContent = t("modalSub");
    document.getElementById("btnRatio169").textContent = t("ratio169");
    document.getElementById("btnRatio34").textContent = t("ratio34");
    document.getElementById("btnCopyImgText").textContent = t("copyImgBtn");
    document.getElementById("btnDownloadPng").textContent = t("downloadPngBtn");
    document.getElementById("btnCopyText").textContent = t("copyTextBtn");
    document.getElementById("btnExportHtml").textContent = t("exportHtmlBtn");
    document.getElementById("btnCloseModal").textContent = t("closeBtn");
  }

  // Live Browser OAuth Sync + WebRTC STUN Probe
  async function runBrowserLiveProbes() {
    if (!state.token || state.report.demoMode) return;

    var browserIp = "";
    var browserCountry = "";

    try {
      var res = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
      if (res.ok) {
        var txt = await res.text();
        txt.split(/\r?\n/).forEach(function (line) {
          var idx = line.indexOf("=");
          if (idx > 0) {
            var k = line.slice(0, idx).trim();
            var v = line.slice(idx + 1).trim();
            if (k === "ip") browserIp = v;
            if (k === "loc") browserCountry = v;
          }
        });
      }
    } catch (_e) {
      try {
        var res2 = await fetch("https://api.ipify.org?format=json", { cache: "no-store" });
        if (res2.ok) {
          var j = await res2.json();
          if (j && j.ip) browserIp = j.ip;
        }
      } catch (_e2) {}
    }

    // Native WebRTC STUN candidate check
    var webrtcIps = [];
    var webrtcTested = false;
    if (typeof RTCPeerConnection !== "undefined") {
      webrtcTested = true;
      try {
        webrtcIps = await new Promise(function (resolve) {
          var found = [];
          var pc = new RTCPeerConnection({
            iceServers: [
              { urls: "stun:stun.cloudflare.com:3478" },
              { urls: "stun:stun.l.google.com:19302" }
            ]
          });
          pc.createDataChannel("probe");
          pc.onicecandidate = function (ev) {
            if (!ev || !ev.candidate || !ev.candidate.candidate) {
              return;
            }
            var cand = ev.candidate.candidate;
            var ipMatches = cand.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(?::[a-f0-9]{0,4}){2,7})/gi);
            if (ipMatches) {
              ipMatches.forEach(function (ip) {
                if (found.indexOf(ip) === -1 && ip !== "0.0.0.0") found.push(ip);
              });
            }
          };
          pc.createOffer()
            .then(function (offer) {
              return pc.setLocalDescription(offer);
            })
            .catch(function () {});
          setTimeout(function () {
            try {
              pc.close();
            } catch (_e) {}
            resolve(found);
          }, 1700);
        });
      } catch (_e) {}
    }

    try {
      var syncResp = await fetch("/api/browser-sync?token=" + encodeURIComponent(state.token), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          browserIp: browserIp,
          browserCountry: browserCountry,
          webrtcTested: webrtcTested,
          webrtcIps: webrtcIps,
          browserTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          browserLanguages: navigator.languages || [navigator.language]
        })
      });
      if (syncResp.ok) {
        state.report = await syncResp.json();
        renderAll();
      }
    } catch (_e) {}
  }

  async function handleRunDrill() {
    if (!state.token || state.drillLoading) return;
    state.drillLoading = true;
    renderAll();
    try {
      var resp = await fetch("/api/drill?token=" + encodeURIComponent(state.token), {
        method: "POST"
      });
      if (resp.ok) {
        state.report = await resp.json();
      }
    } catch (_e) {}
    state.drillLoading = false;
    renderAll();
  }

  async function handleVerifyRestore() {
    if (!state.token || state.restoreLoading) return;
    state.restoreLoading = true;
    try {
      var resp = await fetch("/api/verify-restore?token=" + encodeURIComponent(state.token), {
        method: "POST"
      });
      if (resp.ok) {
        var data = await resp.json();
        if (data.report) state.report = data.report;
        if (data.restoredOk) {
          showToast(t("toastRestoreOk"));
        } else {
          showToast(t("toastRestoreFail"));
        }
      }
    } catch (_e) {}
    state.restoreLoading = false;
    renderAll();
  }

  // Poll /api/net-status softly so user sees instant feedback when turning off TUN
  function startNetStatusWatcher() {
    if (!state.token || state.report.demoMode) return;
    setInterval(async function () {
      if (document.hidden) return;
      try {
        var resp = await fetch("/api/net-status?token=" + encodeURIComponent(state.token));
        if (resp.ok) {
          var st = await resp.json();
          if (state.liveTunActive !== st.tunActive) {
            state.liveTunActive = st.tunActive;
            renderAll();
          }
        }
      } catch (_e) {}
    }, 2200);
  }

  // =========================================================================
  // 2x Retina Shareable Poster Canvas Renderer (Always 100% Masked!)
  // =========================================================================
  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function renderPosterCanvas() {
    var canvas = document.getElementById("posterCanvas");
    if (!canvas) return;
    var r = state.report;
    var isLandscape = state.posterRatio === "16:9";
    var W = isLandscape ? 1600 : 1080;
    var H = isLandscape ? 920 : 1420;
    canvas.width = W;
    canvas.height = H;

    var ctx = canvas.getContext("2d");
    var dark = state.theme === "dark";

    var bg = dark ? "#09090B" : "#F6F3EC";
    var cardShell = dark ? "rgba(255,250,244,0.045)" : "rgba(24,20,16,0.045)";
    var cardCore = dark ? "#121217" : "#FFFFFF";
    var cardBorder = dark ? "rgba(255,255,255,0.09)" : "rgba(24,20,16,0.1)";
    var fgPrimary = dark ? "#F5F2EB" : "#171512";
    var fgSec = dark ? "#A6A097" : "#57524A";
    var fgMuted = dark ? "#6E6A63" : "#8A8379";
    var accent = "#D97757";
    var colPass = "#10B981";
    var colWarn = "#F59E0B";
    var colCrit = "#EF4444";
    var colGold = "#EAB308";

    // Canvas Background + Ambient Glow
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, W, H);

    var grad1 = ctx.createRadialGradient(W * 0.18, H * 0.12, 10, W * 0.18, H * 0.12, W * 0.5);
    grad1.addColorStop(0, "rgba(217, 119, 87, 0.14)");
    grad1.addColorStop(1, "rgba(217, 119, 87, 0)");
    ctx.fillStyle = grad1;
    ctx.fillRect(0, 0, W, H);

    var mainTone = r.redlineTriggered || r.finalScore <= 45 ? colCrit : r.killSwitchVerifiedBadge ? colGold : r.finalScore >= 80 ? colPass : colWarn;
    var grad2 = ctx.createRadialGradient(W * 0.85, H * 0.2, 10, W * 0.85, H * 0.2, W * 0.45);
    grad2.addColorStop(0, r.redlineTriggered ? "rgba(239,68,68,0.12)" : "rgba(16,185,129,0.10)");
    grad2.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = grad2;
    ctx.fillRect(0, 0, W, H);

    // Outer Machined Frame
    var pad = 48;
    roundRect(ctx, pad, pad, W - pad * 2, H - pad * 2, 36);
    ctx.fillStyle = cardShell;
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = cardBorder;
    ctx.stroke();

    roundRect(ctx, pad + 10, pad + 10, W - (pad + 10) * 2, H - (pad + 10) * 2, 28);
    ctx.fillStyle = cardCore;
    ctx.fill();
    ctx.strokeStyle = cardBorder;
    ctx.stroke();

    var ix = pad + 52;
    var iy = pad + 52;
    var iw = W - (pad + 52) * 2;

    // Header Row
    ctx.fillStyle = accent;
    ctx.beginPath();
    ctx.arc(ix + 10, iy + 14, 8, 0, Math.PI * 2);
    ctx.fill();

    ctx.font = "700 24px -apple-system, 'PingFang SC', sans-serif";
    ctx.fillStyle = fgPrimary;
    ctx.fillText("CLAUDE LEAK CHECK", ix + 30, iy + 22);

    ctx.font = "500 18px 'SF Mono', Menlo, monospace";
    ctx.fillStyle = fgMuted;
    var rightTag = "100% READ-ONLY · AUTO-REDACTED · " + r.platform.toUpperCase();
    var tw = ctx.measureText(rightTag).width;
    ctx.fillText(rightTag, ix + iw - tw, iy + 21);

    // Title
    ctx.font = "800 38px -apple-system, 'PingFang SC', sans-serif";
    ctx.fillStyle = fgPrimary;
    ctx.fillText(
      state.lang === "zh" ? "Claude 防封号与分流泄漏体检卡" : "Claude Anti-Ban & Egress Security Card",
      ix,
      iy + 80
    );

    if (isLandscape) {
      // Landscape 2-column layout
      var leftW = 520;
      var rightX = ix + leftW + 44;
      var rightW = iw - leftW - 44;
      var bodyY = iy + 118;

      // Score Subcard
      roundRect(ctx, ix, bodyY, leftW, 520, 24);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      // Score Ring
      var cx = ix + 135;
      var cy = bodyY + 145;
      ctx.lineWidth = 16;
      ctx.strokeStyle = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)";
      ctx.beginPath();
      ctx.arc(cx, cy, 86, 0, Math.PI * 2);
      ctx.stroke();

      ctx.strokeStyle = mainTone;
      ctx.lineCap = "round";
      ctx.beginPath();
      ctx.arc(cx, cy, 86, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * (r.finalScore / 100));
      ctx.stroke();

      ctx.fillStyle = fgPrimary;
      ctx.font = "800 64px 'SF Mono', Menlo, monospace";
      var scStr = String(r.finalScore);
      ctx.fillText(scStr, cx - ctx.measureText(scStr).width / 2, cy + 20);
      ctx.fillStyle = fgMuted;
      ctx.font = "600 16px 'SF Mono', Menlo, monospace";
      ctx.fillText("/ 100", cx - 24, cy + 48);

      // Grade & Masked Exit Info
      ctx.fillStyle = mainTone;
      ctx.font = "800 34px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText("GRADE  " + r.grade, ix + 250, bodyY + 118);

      ctx.fillStyle = fgSec;
      ctx.font = "600 20px -apple-system, 'PingFang SC', sans-serif";
      var verdictShort = r.killSwitchVerifiedBadge
        ? (state.lang === "zh" ? "断网零泄漏金盾认证" : "Kill-Switch Verified")
        : r.redlineTriggered
          ? (state.lang === "zh" ? "命中高危封号红线" : "Fatal Leak Redline")
          : (state.lang === "zh" ? "常态分流体检结果" : "Routine Audit Result");
      ctx.fillText(verdictShort, ix + 250, bodyY + 156);

      var maskedExitStr = r.primaryExit
        ? r.primaryExit.countryCode + " · " + r.primaryExit.ipMasked + " (" + r.primaryExit.asnType.toUpperCase() + ")"
        : "Offline";
      ctx.fillStyle = fgMuted;
      ctx.font = "500 17px 'SF Mono', Menlo, monospace";
      ctx.fillText(maskedExitStr, ix + 250, bodyY + 194);

      // 4 Key Pill Rows inside Left Card
      var rows = [
        [
          state.lang === "zh" ? r.domainMatrix.length + " 暗桩域名同源" : r.domainMatrix.length + " Stealth Domains",
          r.domainMatrix.filter(function (d) { return d.status === "pass"; }).length + " / " + r.domainMatrix.length + " PASS"
        ],
        [
          state.lang === "zh" ? "浏览器 vs CLI 出口" : "OAuth Dual-End Sync",
          r.browserSync.matchesCliExit === true ? "SYNCED ✓" : r.browserSync.matchesCliExit === false ? "MISMATCH ✕" : "CHECKED"
        ],
        [
          state.lang === "zh" ? "WebRTC UDP 防穿透" : "WebRTC UDP Shield",
          r.browserSync.webrtcHasDomesticOrMismatchLeak ? "LEAKED ✕" : "0 LEAK ✓"
        ],
        [
          state.lang === "zh" ? "断网防漏真机演练" : "Kill-Switch Drill",
          r.killSwitchVerifiedBadge ? "VERIFIED S+ ✓" : r.killSwitchDrill.verdict === "leaked" ? "FAILED ✕" : "UNTESTED"
        ]
      ];
      rows.forEach(function (pair, i) {
        var ry = bodyY + 275 + i * 56;
        roundRect(ctx, ix + 28, ry, leftW - 56, 44, 12);
        ctx.fillStyle = dark ? "rgba(255,255,255,0.035)" : "rgba(0,0,0,0.035)";
        ctx.fill();
        ctx.fillStyle = fgSec;
        ctx.font = "600 18px -apple-system, 'PingFang SC', sans-serif";
        ctx.fillText(pair[0], ix + 46, ry + 29);
        ctx.fillStyle = pair[1].indexOf("✕") >= 0 ? colCrit : pair[1].indexOf("✓") >= 0 ? colPass : fgPrimary;
        ctx.font = "700 17px 'SF Mono', Menlo, monospace";
        var vw = ctx.measureText(pair[1]).width;
        ctx.fillText(pair[1], ix + leftW - 46 - vw, ry + 29);
      });

      // Right Column: 5 Modules Bars + 25 Domain Matrix Mini Dots
      roundRect(ctx, rightX, bodyY, rightW, 355, 24);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      ctx.fillStyle = fgPrimary;
      ctx.font = "700 21px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText(state.lang === "zh" ? "五维防漏体检得分" : "5-Pillar Diagnostic Breakdown", rightX + 30, bodyY + 42);

      r.modules.forEach(function (m, idx) {
        var my = bodyY + 76 + idx * 54;
        ctx.fillStyle = fgSec;
        ctx.font = "600 18px -apple-system, 'PingFang SC', sans-serif";
        ctx.fillText(pick(m.name), rightX + 30, my + 16);

        var scoreTxt = m.earnedPoints + "/" + m.maxPoints;
        ctx.font = "700 17px 'SF Mono', Menlo, monospace";
        ctx.fillStyle = fgPrimary;
        ctx.fillText(scoreTxt, rightX + rightW - 95, my + 16);

        var bx = rightX + 30;
        var by = my + 26;
        var bw = rightW - 60;
        roundRect(ctx, bx, by, bw, 9, 5);
        ctx.fillStyle = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)";
        ctx.fill();

        var fillW = Math.max(8, bw * (m.earnedPoints / m.maxPoints));
        roundRect(ctx, bx, by, fillW, 9, 5);
        ctx.fillStyle = m.status === "critical" ? colCrit : m.status === "warn" ? colWarn : colPass;
        ctx.fill();
      });

      // Bottom-Right: 25 Stealth Domain Matrix Capsule Strip
      var matY = bodyY + 375;
      roundRect(ctx, rightX, matY, rightW, 145, 24);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      ctx.fillStyle = fgPrimary;
      ctx.font = "700 19px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText(
        state.lang === "zh"
          ? "暗桩遥测矩阵 (" + r.domainMatrix.length + " 项: Claude / Statsig / Sentry / Datadog / Sift)"
          : "Stealth Telemetry Matrix (" + r.domainMatrix.length + " Endpoints)",
        rightX + 30,
        matY + 38
      );

      var lCols = Math.max(13, Math.ceil(r.domainMatrix.length / 2));
      var lGap = 6;
      var lCellW = Math.floor((rightW - 60 - lGap * (lCols - 1)) / lCols);
      r.domainMatrix.forEach(function (d, i) {
        var col = i % lCols;
        var row = Math.floor(i / lCols);
        var dx = rightX + 30 + col * (lCellW + lGap);
        var dy = matY + 58 + row * 36;
        roundRect(ctx, dx, dy, lCellW, 24, 7);
        ctx.fillStyle = d.status === "critical" ? colCrit : d.status === "warn" ? colWarn : colPass;
        ctx.globalAlpha = 0.22;
        ctx.fill();
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(dx + 10, dy + 12, 4.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fgPrimary;
        ctx.font = "600 10px 'SF Mono', Menlo, monospace";
        ctx.fillText(d.host.slice(0, 4), dx + 17, dy + 16);
      });
    } else {
      // 3:4 Portrait Layout (1080 x 1420) for Xiaohongshu / Mobile
      var py = iy + 116;
      var pw = iw;

      roundRect(ctx, ix, py, pw, 360, 26);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      var pcx = ix + 150;
      var pcy = py + 180;
      ctx.lineWidth = 18;
      ctx.strokeStyle = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)";
      ctx.beginPath();
      ctx.arc(pcx, pcy, 96, 0, Math.PI * 2);
      ctx.stroke();

      ctx.strokeStyle = mainTone;
      ctx.lineCap = "round";
      ctx.beginPath();
      ctx.arc(pcx, pcy, 96, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * (r.finalScore / 100));
      ctx.stroke();

      ctx.fillStyle = fgPrimary;
      ctx.font = "800 68px 'SF Mono', Menlo, monospace";
      var psc = String(r.finalScore);
      ctx.fillText(psc, pcx - ctx.measureText(psc).width / 2, pcy + 22);

      ctx.fillStyle = mainTone;
      ctx.font = "800 42px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText("GRADE " + r.grade, ix + 295, py + 125);

      var pMasked = r.primaryExit
        ? r.primaryExit.countryCode + " · " + r.primaryExit.ipMasked + " (" + r.primaryExit.asnType.toUpperCase() + ")"
        : "Offline";
      ctx.fillStyle = fgSec;
      ctx.font = "600 24px 'SF Mono', Menlo, monospace";
      ctx.fillText("EXIT: " + pMasked, ix + 295, py + 178);

      ctx.fillStyle = fgMuted;
      ctx.font = "600 21px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText(
        "TUN: " + (r.environmentSummary.activeUtunInterfaces.join(",") || "OFF") +
        "  |  TZ: " + r.environmentSummary.systemTimezone,
        ix + 295,
        py + 225
      );
      ctx.fillText(
        "OAuth Sync: " + (r.browserSync.matchesCliExit ? "PASS ✓" : "CHECK") +
        "  |  WebRTC: " + (r.browserSync.webrtcHasDomesticOrMismatchLeak ? "LEAK ✕" : "PASS ✓"),
        ix + 295,
        py + 268
      );

      // Modules Box
      var mBoxY = py + 390;
      roundRect(ctx, ix, mBoxY, pw, 470, 26);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      r.modules.forEach(function (m, idx) {
        var my = mBoxY + 48 + idx * 84;
        ctx.fillStyle = fgPrimary;
        ctx.font = "700 24px -apple-system, 'PingFang SC', sans-serif";
        ctx.fillText(pick(m.name), ix + 36, my + 20);

        var stxt = m.earnedPoints + " / " + m.maxPoints;
        ctx.font = "700 23px 'SF Mono', Menlo, monospace";
        ctx.fillText(stxt, ix + pw - 145, my + 20);

        var bx = ix + 36;
        var by = my + 36;
        var bw = pw - 72;
        roundRect(ctx, bx, by, bw, 12, 6);
        ctx.fillStyle = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)";
        ctx.fill();

        roundRect(ctx, bx, by, Math.max(10, bw * (m.earnedPoints / m.maxPoints)), 12, 6);
        ctx.fillStyle = m.status === "critical" ? colCrit : m.status === "warn" ? colWarn : colPass;
        ctx.fill();
      });

      // Domain Matrix Summary Strip
      var dBoxY = mBoxY + 495;
      roundRect(ctx, ix, dBoxY, pw, 175, 26);
      ctx.fillStyle = dark ? "#18181F" : "#FAF8F4";
      ctx.fill();
      ctx.strokeStyle = cardBorder;
      ctx.stroke();

      ctx.fillStyle = fgPrimary;
      ctx.font = "700 23px -apple-system, 'PingFang SC', sans-serif";
      ctx.fillText(
        state.lang === "zh"
          ? r.domainMatrix.length + " 个暗桩与遥测域名全矩阵核验：" +
            r.domainMatrix.filter(function (d) { return d.status === "pass"; }).length + "/" + r.domainMatrix.length + " 同源通过"
          : r.domainMatrix.length + " Stealth Telemetry Domains Audited",
        ix + 36,
        dBoxY + 48
      );

      var pCols = Math.max(13, Math.ceil(r.domainMatrix.length / 2));
      var pGap = 6;
      var pCellW = Math.floor((pw - 72 - pGap * (pCols - 1)) / pCols);
      r.domainMatrix.forEach(function (d, i) {
        var col = i % pCols;
        var row = Math.floor(i / pCols);
        var dx = ix + 36 + col * (pCellW + pGap);
        var dy = dBoxY + 74 + row * 40;
        roundRect(ctx, dx, dy, pCellW, 26, 7);
        ctx.fillStyle = d.status === "critical" ? colCrit : d.status === "warn" ? colWarn : colPass;
        ctx.fill();
      });
    }

    // Footer Command Pill
    var fy = H - pad - 44;
    ctx.fillStyle = accent;
    ctx.font = (isLandscape ? "700 22px" : "700 20px") + " 'SF Mono', Menlo, monospace";
    ctx.fillText("$ " + state.brand.cliCommand, ix, fy);

    ctx.fillStyle = fgMuted;
    ctx.font = (isLandscape ? "500 18px" : "500 16px") + " 'SF Mono', Menlo, monospace";
    var repoTxt = isLandscape
      ? state.brand.repoShort + "  ·  Zero-Sudo Local Diagnostic"
      : state.brand.repoShort;
    ctx.fillText(repoTxt, ix + iw - ctx.measureText(repoTxt).width, fy);
  }

  // Bind Topbar & Modal Actions
  document.getElementById("maskBtn").onclick = function () {
    state.masked = !state.masked;
    renderAll();
  };
  document.getElementById("langBtn").onclick = function () {
    state.lang = state.lang === "zh" ? "en" : "zh";
    renderAll();
    if (document.getElementById("posterModal").classList.contains("open")) {
      renderPosterCanvas();
    }
  };
  document.getElementById("themeBtn").onclick = function () {
    state.theme = state.theme === "dark" ? "light" : "dark";
    renderAll();
    if (document.getElementById("posterModal").classList.contains("open")) {
      renderPosterCanvas();
    }
  };
  document.getElementById("restoreBannerBtn").onclick = handleVerifyRestore;

  var modal = document.getElementById("posterModal");
  document.getElementById("shareBtn").onclick = function () {
    modal.classList.add("open");
    renderPosterCanvas();
  };
  document.getElementById("btnCloseModal").onclick = function () {
    modal.classList.remove("open");
  };
  modal.onclick = function (ev) {
    if (ev.target === modal) modal.classList.remove("open");
  };

  document.getElementById("btnRatio169").onclick = function () {
    state.posterRatio = "16:9";
    renderPosterCanvas();
  };
  document.getElementById("btnRatio34").onclick = function () {
    state.posterRatio = "3:4";
    renderPosterCanvas();
  };

  document.getElementById("btnDownloadPng").onclick = function () {
    var canvas = document.getElementById("posterCanvas");
    var link = document.createElement("a");
    link.download = "claude-leak-check-" + state.report.grade + "-" + state.report.reportId + ".png";
    link.href = canvas.toDataURL("image/png");
    link.click();
  };

  document.getElementById("btnCopyImg").onclick = function () {
    var canvas = document.getElementById("posterCanvas");
    canvas.toBlob(function (blob) {
      if (!blob || !navigator.clipboard || typeof ClipboardItem === "undefined") {
        document.getElementById("btnDownloadPng").click();
        return;
      }
      navigator.clipboard
        .write([new ClipboardItem({ "image/png": blob })])
        .then(function () {
          showToast(t("toastCopiedImg"));
        })
        .catch(function () {
          document.getElementById("btnDownloadPng").click();
        });
    }, "image/png");
  };

  document.getElementById("btnCopyText").onclick = function () {
    var r = state.report;
    var passCount = r.domainMatrix.filter(function (d) { return d.status === "pass"; }).length;
    var shareText =
      state.lang === "zh"
        ? "本地 Claude 分流与防泄漏体检结果：\n" +
          "- 综合得分：" + r.finalScore + "/100 (" + r.grade + ")\n" +
          "- 关联域名同源：" + passCount + "/" + r.domainMatrix.length + "\n" +
          "- 出口(已打码)：" + (r.primaryExit ? r.primaryExit.countryCode + " · " + r.primaryExit.ipMasked : "N/A") + "\n\n" +
          "本地只读自查：npx claude-leak-check\n" +
          state.brand.repoUrl
        : "Local Claude routing & leak diagnostic:\n" +
          "- Score: " + r.finalScore + "/100 (" + r.grade + ")\n" +
          "- Telemetry Matrix: " + passCount + "/" + r.domainMatrix.length + "\n\n" +
          "npx claude-leak-check\n" +
          state.brand.repoUrl;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(shareText).then(function () {
        showToast(t("toastCopiedText"));
      });
    }
  };

  document.getElementById("btnExportHtml").onclick = function () {
    if (state.token) {
      window.location.href = "/api/export-html?token=" + encodeURIComponent(state.token);
    } else {
      var blob = new Blob([document.documentElement.outerHTML], { type: "text/html;charset=utf-8" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "claude-leak-report-" + state.report.reportId + ".html";
      a.click();
    }
  };

  // Scroll Entry Reveal via IntersectionObserver
  var io = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          io.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.06 }
  );
  Array.prototype.forEach.call(document.querySelectorAll(".reveal"), function (el) {
    io.observe(el);
  });

  renderAll();
  runBrowserLiveProbes();
  startNetStatusWatcher();
})();
`;

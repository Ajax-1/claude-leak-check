import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { runFullAudit } from "../src/core/engine.js";
import { MockPlatformAdapter } from "../src/platforms/mock.js";
import { startLocalReportServer } from "../src/server/local-server.js";
import { CLIENT_SCRIPT } from "../src/ui/client-script.js";

test("Local loopback server enforces session token, serves zero-CDN HTML, and upgrades to S+ on global Kill-Switch Drill", async () => {
  const { report, adapter, sessionSalt } = await runFullAudit({ demo: "safe" });
  const srv = await startLocalReportServer(report, adapter, sessionSalt);

  try {
    const unauth = await fetch(`http://127.0.0.1:${srv.port}/api/report`);
    assert.equal(unauth.status, 401);

    const htmlRes = await fetch(srv.url);
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.equal(/<script[^>]+src=["']https?:/i.test(html), false);
    assert.equal(/<link[^>]+href=["']https?:/i.test(html), false);
    assert.ok(html.includes("claude-leak-check"));

    const drillRes = await fetch(`http://127.0.0.1:${srv.port}/api/drill?token=${srv.token}`, {
      method: "POST",
    });
    assert.equal(drillRes.status, 200);
    const updatedReport = (await drillRes.json()) as {
      grade: string;
      killSwitchVerifiedBadge: boolean;
      killSwitchDrill: { verdict: string; systemProbeLatencyMs: number };
    };
    assert.equal(updatedReport.killSwitchDrill.verdict, "global_blocked");
    assert.equal(updatedReport.killSwitchVerifiedBadge, true);
    assert.equal(updatedReport.grade, "S+");

    const exportRes = await fetch(`http://127.0.0.1:${srv.port}/api/export-html?token=${srv.token}`);
    assert.equal(exportRes.status, 200);
    const exportedHtml = await exportRes.text();
    assert.equal(exportedHtml.includes("198.51.100.42"), false);
    assert.equal(exportedHtml.includes("198.51.*.*"), true);
  } finally {
    await srv.close();
  }
});

test("/api/drill refreshes LuLu firewall state live and awards app_firewall_locked (S+) without false leaked redline", async () => {
  // 模拟真机场景：初始体检时防火墙未开，用户在打开报告页后导入了 LuLu 规则并关闭了 TUN：
  // 此时普通 curl 探针回落到国内宽带 (blocked: false, country: CN)，但因 LuLu 已锁死 Claude 全家桶，
  // /api/drill 重新调用 scanBinariesAndFirewall() 后应准确给出 app_firewall_locked (S+)，绝不误触发 leaked 红线！
  const baseMock = new MockPlatformAdapter("safe");
  let luluEnabledNow = false;

  const dynamicLuLuAdapter: typeof baseMock = Object.assign(
    Object.create(Object.getPrototypeOf(baseMock)),
    baseMock,
    {
      async scanBinariesAndFirewall() {
        const res = await baseMock.scanBinariesAndFirewall();
        if (!luluEnabledNow) {
          return {
            binaries: res.binaries.map((b) => ({ ...b, firewallCovered: false })),
            firewall: {
              ...res.firewall,
              luluActive: false,
              luluCoveredRuleCount: 0,
              claudeAppFullyLocked: false,
              claudeCliLocked: false,
            },
          };
        }
        return res;
      },
      async runKillSwitchProbe() {
        // 普通非 Claude 进程回落到了本地宽带（验证应用级精准锁场景）
        return {
          tunActive: false,
          blocked: false,
          latencyMs: 27,
          leakedIpMasked: "203.0.*.*",
          leakedCountry: "CN",
        };
      },
    }
  );

  const { report, adapter, sessionSalt } = await runFullAudit({
    customAdapter: dynamicLuLuAdapter,
  });
  report.browserSync = {
    completed: true,
    browserExitIpMasked: "198.51.*.*",
    matchesCliExit: true,
    webrtcTested: true,
    webrtcPublicIpsMasked: [],
    webrtcHasDomesticOrMismatchLeak: false,
    webrtcHasLanIpOnly: false,
  };

  assert.equal(report.firewallAudit.claudeAppFullyLocked, false);

  const srv = await startLocalReportServer(report, adapter, sessionSalt);
  try {
    // 用户在演练前开启/导入了 LuLu 规则
    luluEnabledNow = true;

    const drillRes = await fetch(`http://127.0.0.1:${srv.port}/api/drill?token=${srv.token}`, {
      method: "POST",
    });
    assert.equal(drillRes.status, 200);
    const updated = (await drillRes.json()) as {
      finalScore: number;
      grade: string;
      redlineTriggered: boolean;
      killSwitchVerifiedBadge: boolean;
      firewallAudit: { claudeAppFullyLocked: boolean; luluCoveredRuleCount: number };
      killSwitchDrill: { verdict: string };
    };

    assert.equal(updated.firewallAudit.claudeAppFullyLocked, true);
    assert.equal(updated.firewallAudit.luluCoveredRuleCount, 30);
    assert.equal(updated.killSwitchDrill.verdict, "app_firewall_locked");
    assert.equal(updated.redlineTriggered, false);
    assert.equal(updated.killSwitchVerifiedBadge, true);
    assert.equal(updated.finalScore, 100);
    assert.equal(updated.grade, "S+");
  } finally {
    await srv.close();
  }
});

test("/api/browser-sync handles blocked echo (browserIp='') cleanly, supports retry to matched IP, and flags mismatched IP", async () => {
  const customMock = new MockPlatformAdapter("safe");
  const { report, adapter, sessionSalt } = await runFullAudit({ customAdapter: customMock });
  // 确保非 demo 实时模式下测试 /api/browser-sync
  delete report.demoMode;

  const srv = await startLocalReportServer(report, adapter, sessionSalt);
  try {
    // 1. 复现用户反馈场景：WebRTC 检测已完成，但浏览器跨域回显请求被防追踪盾拦截 (browserIp === "")
    const blockedRes = await fetch(`http://127.0.0.1:${srv.port}/api/browser-sync?token=${srv.token}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        browserIp: "",
        browserCountry: "",
        probeSource: "",
        webrtcTested: true,
        webrtcIps: [],
      }),
    });
    assert.equal(blockedRes.status, 200);
    const blockedReport = (await blockedRes.json()) as {
      finalScore: number;
      browserSync: {
        completed: boolean;
        probeBlockedOrFailed?: boolean;
        matchesCliExit?: boolean;
        webrtcTested: boolean;
      };
      modules: { id: string; findings: { id: string; pointsDeducted: number }[] }[];
    };
    assert.equal(blockedReport.browserSync.completed, true);
    assert.equal(blockedReport.browserSync.probeBlockedOrFailed, true);
    assert.equal(blockedReport.browserSync.matchesCliExit, undefined);
    const m3Blocked = blockedReport.modules.find((m) => m.id === "browser_sync")!;
    assert.ok(m3Blocked.findings.some((f) => f.id === "browser-echo-blocked" && f.pointsDeducted === 0));
    assert.ok(m3Blocked.findings.some((f) => f.id === "webrtc-clean"));

    // 2. 用户放行回显或切到备用源后重试：拿到与 CLI 相同的出口 IP (198.51.100.42)
    const matchedRes = await fetch(`http://127.0.0.1:${srv.port}/api/browser-sync?token=${srv.token}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        browserIp: "198.51.100.42",
        browserCountry: "US",
        probeSource: "ipinfo-json",
        webrtcTested: true,
        webrtcIps: [],
      }),
    });
    assert.equal(matchedRes.status, 200);
    const matchedReport = (await matchedRes.json()) as {
      finalScore: number;
      redlineTriggered: boolean;
      browserSync: {
        probeBlockedOrFailed?: boolean;
        probeSource?: string;
        matchesCliExit?: boolean;
        browserExitIpMasked?: string;
      };
      modules: { id: string; findings: { id: string }[] }[];
    };
    assert.equal(matchedReport.browserSync.probeBlockedOrFailed, false);
    assert.equal(matchedReport.browserSync.probeSource, "ipinfo-json");
    assert.equal(matchedReport.browserSync.matchesCliExit, true);
    assert.equal(matchedReport.browserSync.browserExitIpMasked, "198.51.*.*");
    assert.equal(matchedReport.redlineTriggered, false);
    const m3Matched = matchedReport.modules.find((m) => m.id === "browser_sync")!;
    assert.ok(m3Matched.findings.some((f) => f.id === "browser-cli-matched"));

    // 3. 若浏览器挂了独立插件走到不同出口 IP (203.0.113.99)，立即触发双 IP 横跳红线
    const mismatchRes = await fetch(`http://127.0.0.1:${srv.port}/api/browser-sync?token=${srv.token}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        browserIp: "203.0.113.99",
        browserCountry: "SG",
        probeSource: "1.1.1.1-trace",
        webrtcTested: true,
        webrtcIps: [],
      }),
    });
    const mismatchReport = (await mismatchRes.json()) as {
      finalScore: number;
      grade: string;
      redlineTriggered: boolean;
      browserSync: { matchesCliExit?: boolean };
    };
    assert.equal(mismatchReport.browserSync.matchesCliExit, false);
    assert.equal(mismatchReport.redlineTriggered, true);
    assert.ok(mismatchReport.finalScore <= 45);
    assert.equal(mismatchReport.grade, "F");
  } finally {
    await srv.close();
  }
});

test("CLIENT_SCRIPT executes multi-source echo fallback (403 + blocked -> fallback) and retry button against live server", async () => {
  // 1. 静态语法与关键标记检查
  assert.doesNotThrow(() => {
    new vm.Script(CLIENT_SCRIPT);
  });
  assert.equal(CLIENT_SCRIPT.includes('browserExitIpMasked || "—"'), false);

  // 2. 启动真实本地报告服务，并在沙箱 DOM 中运行完整 CLIENT_SCRIPT 验证端到端行为
  const customMock = new MockPlatformAdapter("safe");
  const { report, adapter, sessionSalt } = await runFullAudit({ customAdapter: customMock });
  delete report.demoMode;
  const srv = await startLocalReportServer(report, adapter, sessionSalt);

  try {
    const elements = new Map<string, Record<string, unknown>>();
    const getEl = (id: string): Record<string, unknown> => {
      if (!elements.has(id)) {
        elements.set(id, {
          id,
          textContent: "",
          innerHTML: "",
          className: "",
          style: {},
          classList: {
            add() {},
            remove() {},
            contains() {
              return false;
            },
          },
          onclick: null,
          click() {},
        });
      }
      return elements.get(id)!;
    };

    let blockAllExternalEcho = true;
    const fetchCalls: string[] = [];

    const mockFetch = async (input: string, init?: RequestInit): Promise<unknown> => {
      fetchCalls.push(input);
      if (input.startsWith("/api/")) {
        return fetch(`http://127.0.0.1:${srv.port}${input}`, init);
      }
      if (blockAllExternalEcho) {
        // 模拟前两个源返回 403 非抛错响应，其余源被防追踪扩展拦截抛异常
        if (input.includes("cdn-cgi/trace")) {
          return { ok: false, status: 403, text: async () => "Forbidden" };
        }
        throw new TypeError("ERR_BLOCKED_BY_CLIENT");
      }
      // 放行后：模拟第 1 源 403、第 2 源抛错、第 3 源 ipinfo.io 成功返回与 CLI 一致的 IP
      if (input.includes("1.1.1.1")) {
        return { ok: false, status: 403, text: async () => "Challenge" };
      }
      if (input.includes("1.0.0.1")) {
        throw new TypeError("Failed to fetch");
      }
      if (input.includes("ipinfo.io/json")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ ip: "198.51.100.42", country: "US" }),
        };
      }
      throw new TypeError("Unexpected URL");
    };

    const docStub = {
      documentElement: {
        setAttribute() {},
        outerHTML: "<html></html>",
      },
      hidden: true,
      getElementById: (id: string) => getEl(id),
      querySelectorAll: () => [],
      createElement: () => ({ click() {}, style: {} }),
    };

    const sandbox: Record<string, unknown> = {
      window: {
        __AUDIT_REPORT__: structuredClone(report),
        __BRAND_CONFIG__: {
          packageName: "claude-leak-check",
          cliCommand: "npx claude-leak-check",
          repoUrl: "https://github.com/Ajax-1/claude-leak-check",
          repoShort: "github.com/Ajax-1/claude-leak-check",
          authorHandle: "@Ajax-1",
          version: "0.1.3",
        },
        __INTERACTIVE_TOKEN__: srv.token,
        location: { href: srv.url },
      },
      document: docStub,
      navigator: { language: "zh-CN", languages: ["zh-CN", "en-US"] },
      Intl,
      AbortController,
      setTimeout,
      clearTimeout,
      setInterval: () => {
        const fakeTimer = { unref() {} };
        return fakeTimer;
      },
      IntersectionObserver: function () {
        return { observe() {}, unobserve() {} };
      },
      fetch: mockFetch,
    };

    vm.runInNewContext(CLIENT_SCRIPT, sandbox);

    // 等待首次自动探测完成（全部外部回显源均被拦截/403）
    await new Promise((r) => setTimeout(r, 80));

    const kvAfterBlocked = String(getEl("scoreKvStack").innerHTML);
    // 确认：6 个备用源全部被依次尝试（没有因为 403 漏掉备用源），且首屏显示可点击重试按钮而非 `—`
    assert.ok(fetchCalls.some((u) => u.includes("1.1.1.1/cdn-cgi/trace")));
    assert.ok(fetchCalls.some((u) => u.includes("ipinfo.io/json")));
    assert.ok(fetchCalls.some((u) => u.includes("ipv4.icanhazip.com")));
    assert.ok(fetchCalls.some((u) => u.includes("v4.ident.me")));
    assert.ok(kvAfterBlocked.includes("回显被拦截 · 点此重试"));
    assert.equal(kvAfterBlocked.includes(">—<"), false);

    // 模拟用户关闭对 127.0.0.1 的防追踪拦截并点击「点此重试」按钮
    blockAllExternalEcho = false;
    const retryBtn = getEl("retrySyncBtn");
    assert.equal(typeof retryBtn.onclick, "function");
    (retryBtn.onclick as () => void)();

    await new Promise((r) => setTimeout(r, 80));

    const kvAfterRetry = String(getEl("scoreKvStack").innerHTML);
    assert.ok(kvAfterRetry.includes("100% 同源一致 ✓"));
  } finally {
    await srv.close();
  }
});

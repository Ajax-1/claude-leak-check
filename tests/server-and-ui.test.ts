import assert from "node:assert/strict";
import test from "node:test";
import { runFullAudit } from "../src/core/engine.js";
import { MockPlatformAdapter } from "../src/platforms/mock.js";
import { startLocalReportServer } from "../src/server/local-server.js";

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

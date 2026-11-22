import assert from "node:assert/strict";
import test from "node:test";
import { REGION_NAMES } from "../src/core/domains.js";
import { resolveProxyTopology, runFullAudit } from "../src/core/engine.js";
import { hashIpForComparison, maskIp } from "../src/core/privacy.js";
import { evaluateAuditScores } from "../src/core/scorer.js";
import { MockPlatformAdapter } from "../src/platforms/mock.js";
import type { AuditOptions, PlatformAdapter } from "../src/platforms/types.js";
import { startLocalReportServer } from "../src/server/local-server.js";

test("Auto-detects compliant OpenWrt / OpenClash router gateway without false utun redline (--demo router & custom adapter)", async () => {
  const { report } = await runFullAudit({ demo: "router" });
  assert.equal(report.resolvedTopology, "router-gateway");
  assert.equal(report.routerAutoDetected, true);
  assert.equal(report.redlineTriggered, false);
  assert.equal(report.finalScore, 100);
  assert.equal(report.grade, "A+");
  assert.equal(report.domainMatrix.every((d) => d.status === "pass"), true);

  const m1 = report.modules.find((m) => m.id === "egress_matrix")!;
  const m2 = report.modules.find((m) => m.id === "network_stack")!;
  assert.ok(m1.findings.some((f) => f.id === "router-nongfw-consistent"));
  assert.ok(m2.findings.some((f) => f.id === "router-gateway-active"));
  assert.equal(m2.findings.some((f) => f.id === "tun-disabled"), false);

  // 验证无本机代理客户端、物理网卡 en0 经局域网网关走美国出口时，resolveProxyTopology 自动识别为 router-gateway；
  // 而国内直连裸奔 (CN) 用户绝不会被误判为软路由！
  const baseMock = new MockPlatformAdapter("router");
  const netSnap = await baseMock.getNetworkSnapshot();
  const proxyAudit = await baseMock.auditProxyConfigSafely();

  const autoUs = resolveProxyTopology({
    preference: "auto",
    netSnap,
    proxyAudit,
    primaryExit: report.primaryExit,
  });
  assert.equal(autoUs.resolvedTopology, "router-gateway");
  assert.equal(autoUs.routerAutoDetected, true);

  const nakedCn = resolveProxyTopology({
    preference: "auto",
    netSnap,
    proxyAudit,
    primaryExit: {
      ...report.primaryExit!,
      countryCode: "CN",
      countryName: REGION_NAMES.CN,
      isSupportedRegion: false,
      isRestrictedRegion: true,
    },
  });
  assert.equal(nakedCn.resolvedTopology, "host-tun");
  assert.equal(nakedCn.routerAutoDetected, false);
});

test("Router Gateway mode catches GFWList-only split-routing leak when AWS non-GFW echo differs from 1.1.1.1", async () => {
  const baseRouter = new MockPlatformAdapter("router");
  const gfwListLeakAdapter: PlatformAdapter = {
    platform: "darwin",
    getNetworkSnapshot: () => baseRouter.getNetworkSnapshot(),
    auditProxyConfigSafely: (opts) => baseRouter.auditProxyConfigSafely(),
    scanBinariesAndFirewall: () => baseRouter.scanBinariesAndFirewall(),
    inspectEnvironmentHygiene: () => baseRouter.inspectEnvironmentHygiene(),
    runKillSwitchProbe: (salt) => baseRouter.runKillSwitchProbe(salt),
    async probePublicExits(_netSnap, options: AuditOptions) {
      const usIp = "198.51.100.42";
      const cnBroadbandIp = "203.0.113.77";
      return {
        cliExitIpHash: hashIpForComparison(usIp, options.sessionSalt),
        primaryExit: {
          source: "cloudflare-1.1.1.1",
          ipMasked: maskIp(usIp),
          ipRawForLocalToggle: usIp,
          countryCode: "US",
          countryName: REGION_NAMES.US,
          asnType: "isp",
          isSupportedRegion: true,
          isRestrictedRegion: false,
          viaMode: "direct-socket-noproxy",
          latencyMs: 145,
        },
        nonGfwExitIpHash: hashIpForComparison(cnBroadbandIp, options.sessionSalt),
        nonGfwExit: {
          source: "aws-checkip",
          ipMasked: maskIp(cnBroadbandIp),
          ipRawForLocalToggle: cnBroadbandIp,
          countryCode: "CN",
          countryName: REGION_NAMES.CN,
          asnType: "isp",
          isSupportedRegion: false,
          isRestrictedRegion: true,
          viaMode: "non-gfw-echo",
          latencyMs: 36,
        },
      };
    },
    async probeDomainMatrix(targets, _proxyAudit, primaryExit, options) {
      return targets.map((t) => {
        const splitLeaked =
          options.resolvedTopology === "router-gateway" &&
          options.nonGfwMatchesPrimary === false &&
          !t.officialAnthropic &&
          t.host !== "accounts.google.com";
        return {
          host: t.host,
          category: t.category,
          officialAnthropic: t.officialAnthropic,
          label: t.label,
          riskNote: t.riskNote,
          resolvedIps: [],
          maskedResolvedIps: ["203.0.*.*"],
          isFakeIp: false,
          hasIpv6Resolution: false,
          routeInterface: "en0 (GW)",
          isTunRouted: true,
          staticRuleDecision: "unknown",
          edgeExitIpMasked: primaryExit?.ipMasked,
          edgeCountry: splitLeaked ? "CN" : "US",
          probeMode: "local-zero-packet",
          status: splitLeaked ? "critical" : "pass",
          statusReason: splitLeaked
            ? { zh: "GFWList 漏分流", en: "GFWList split leak" }
            : { zh: "经透明网关转发", en: "Via router gateway" },
        };
      });
    },
  };

  const { report } = await runFullAudit({
    customAdapter: gfwListLeakAdapter,
    topologyPreference: "router-gateway",
  });

  assert.equal(report.resolvedTopology, "router-gateway");
  assert.equal(report.nonGfwMatchesPrimary, false);
  assert.equal(report.redlineTriggered, true);
  assert.ok(report.finalScore <= 45);
  assert.equal(report.grade, "F");
  const m1 = report.modules.find((m) => m.id === "egress_matrix")!;
  assert.ok(m1.findings.some((f) => f.id === "router-gfwlist-split-leak" && f.triggersRedline));
});

test("Router Gateway mode flags side-router gateway/DNS mismatch (.2 vs .1), domestic DNS, and unverified host firewall gently", async () => {
  const { report: base } = await runFullAudit({ demo: "router" });

  const scored = evaluateAuditScores({
    resolvedTopology: "router-gateway",
    routerAutoDetected: true,
    netSnap: {
      activeUtunInterfaces: [],
      defaultRouteInterface: "en0",
      defaultGatewayIp: "192.168.31.2",
      defaultGatewayMasked: "192.168.*.* (LAN)",
      dnsServers: ["192.168.31.1", "114.114.114.114"],
      dnsServersMasked: ["192.168.*.* (LAN)", "114.114.*.*"],
      tailscaleMagicDns: false,
      icloudPrivateRelaySuspected: false,
      competingVpns: [],
      systemProxy: { httpEnabled: false, httpsEnabled: false, socksEnabled: false },
      publicIpv6Interfaces: [
        { iface: "en0", addressMasked: "240e:3b7:*:*::*", isMainlandCarrier: true },
      ],
    },
    primaryExit: base.primaryExit,
    nonGfwExit: base.nonGfwExit,
    nonGfwMatchesPrimary: true,
    // 模拟实 IP 旁路由模式（未启用 Fake-IP）且本机未装 LuLu
    domainMatrix: base.domainMatrix.map((d) => ({ ...d, isFakeIp: false })),
    binaries: base.binaries.map((b) => ({ ...b, firewallCovered: false })),
    proxyAudit: base.proxyAudit,
    firewallAudit: {
      ...base.firewallAudit,
      luluInstalled: false,
      luluActive: false,
      claudeAppFullyLocked: false,
      claudeCliLocked: false,
    },
    envSnap: {
      systemTimezone: "Asia/Taipei",
      isMainlandTimezone: false,
      systemLocale: "en_US.UTF-8",
      defaultBrowser: "Brave Browser",
      hasAnthropicBaseUrl: false,
      anthropicBaseUrlIsCustomThirdParty: false,
      settingsHasCustomBaseUrl: false,
      proxyEnvVarsPresent: [],
      proxyEnvConflictsWithSystem: false,
      dedicatedLoopbackProxyPorts: [],
      deadLoopbackProxyPorts: [],
      riskyReverseProxies: [],
      mcpServerCount: 0,
      mcpCommands: [],
      suspiciousSettingsEnvKeys: [],
    },
    browserSync: base.browserSync,
    killSwitchDrill: base.killSwitchDrill,
  });

  const m2 = scored.modules.find((m) => m.id === "network_stack")!;
  const m4 = scored.modules.find((m) => m.id === "app_footprint")!;
  assert.ok(m2.findings.some((f) => f.id === "router-domestic-dns-leak" && f.pointsDeducted === 8));
  assert.ok(m2.findings.some((f) => f.id === "side-router-dns-mismatch" && f.pointsDeducted === 6));
  assert.ok(m2.findings.some((f) => f.id === "ipv6-carrier-assigned" && f.pointsDeducted === 8));
  assert.ok(m4.findings.some((f) => f.id === "router-killswitch-unverified" && f.pointsDeducted === 4));
  assert.equal(scored.redlineTriggered, false);
});

test("/api/topology-mode switches live and /api/drill + /api/verify-restore work accurately for Router Gateway users", async () => {
  const baseRouter = new MockPlatformAdapter("router");
  let routerPaused = false;

  const interactiveRouterAdapter: PlatformAdapter = {
    platform: "darwin",
    getNetworkSnapshot: () => baseRouter.getNetworkSnapshot(),
    probePublicExits: (net, opts) => baseRouter.probePublicExits(net, opts),
    probeDomainMatrix: (t, p, e, o) => baseRouter.probeDomainMatrix(t, p, e, o),
    auditProxyConfigSafely: (o) => baseRouter.auditProxyConfigSafely(),
    async scanBinariesAndFirewall() {
      const res = await baseRouter.scanBinariesAndFirewall();
      // 模拟软路由用户本机未装 LuLu，靠路由器侧防火墙实现 Kill-Switch
      return {
        binaries: res.binaries.map((b) => ({ ...b, firewallCovered: false })),
        firewall: {
          ...res.firewall,
          luluInstalled: false,
          luluActive: false,
          claudeAppFullyLocked: false,
          claudeCliLocked: false,
        },
      };
    },
    inspectEnvironmentHygiene: () => baseRouter.inspectEnvironmentHygiene(),
    async runKillSwitchProbe(sessionSalt?: string) {
      if (!routerPaused) {
        // 用户还没在软路由后台暂停 OpenClash，出口依然是原来的美国代理 IP (198.51.100.42)
        return {
          tunActive: false,
          blocked: false,
          latencyMs: 140,
          leakedIpMasked: "198.51.*.*",
          leakedIpHash: sessionSalt ? hashIpForComparison("198.51.100.42", sessionSalt) : undefined,
          leakedCountry: "US",
        };
      }
      // 用户在软路由后台暂停了 OpenClash，OpenWrt 防火墙阻断了 LAN->WAN 直连回退
      return {
        tunActive: false,
        blocked: true,
        latencyMs: 22,
      };
    },
  };

  const { report, adapter, sessionSalt } = await runFullAudit({
    customAdapter: interactiveRouterAdapter,
    topologyPreference: "host-tun",
  });
  delete report.demoMode;
  report.browserSync = {
    completed: true,
    browserExitIpMasked: "198.51.*.*",
    browserExitIpHash: report.cliExitIpHash,
    matchesCliExit: true,
    webrtcTested: true,
    webrtcPublicIpsMasked: [],
    webrtcHasDomesticOrMismatchLeak: false,
    webrtcHasLanIpOnly: false,
  };

  // 强制 host-tun 时因无 utun 会触发红线
  assert.equal(report.resolvedTopology, "host-tun");
  assert.equal(report.redlineTriggered, true);

  const srv = await startLocalReportServer(report, adapter, sessionSalt);
  try {
    // 1. 用户在页面顶部点击切换为「软路由 / 透明网关」模式
    const switchRes = await fetch(`http://127.0.0.1:${srv.port}/api/topology-mode?token=${srv.token}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "router-gateway" }),
    });
    assert.equal(switchRes.status, 200);
    const switched = (await switchRes.json()) as {
      resolvedTopology: string;
      redlineTriggered: boolean;
      finalScore: number;
      grade: string;
    };
    assert.equal(switched.resolvedTopology, "router-gateway");
    assert.equal(switched.redlineTriggered, false);
    assert.equal(switched.finalScore, 96); // 仅扣 4 分待验证软路由 Kill-Switch
    assert.equal(switched.grade, "A+");

    // 2. 用户未暂停软路由插件直接点演练 -> 精准识别 proxy_still_on，绝不把美国代理 IP 误判成泄漏！
    const drillBeforePause = await fetch(`http://127.0.0.1:${srv.port}/api/drill?token=${srv.token}`, {
      method: "POST",
    });
    const beforeData = (await drillBeforePause.json()) as {
      killSwitchDrill: { verdict: string };
    };
    assert.equal(beforeData.killSwitchDrill.verdict, "proxy_still_on");

    // 3. 用户暂停软路由插件后再点演练 -> 路由器防火墙阻断通过，满分 100 解锁 S+！
    routerPaused = true;
    const drillAfterPause = await fetch(`http://127.0.0.1:${srv.port}/api/drill?token=${srv.token}`, {
      method: "POST",
    });
    const afterData = (await drillAfterPause.json()) as {
      finalScore: number;
      grade: string;
      killSwitchVerifiedBadge: boolean;
      killSwitchDrill: { verdict: string };
    };
    assert.equal(afterData.killSwitchDrill.verdict, "global_blocked");
    assert.equal(afterData.killSwitchVerifiedBadge, true);
    assert.equal(afterData.finalScore, 100);
    assert.equal(afterData.grade, "S+");

    // 4. 用户恢复软路由插件后点击「点此复检绿灯」 -> 无需本机 utun 也能通过恢复校验！
    routerPaused = false;
    const restoreRes = await fetch(`http://127.0.0.1:${srv.port}/api/verify-restore?token=${srv.token}`, {
      method: "POST",
    });
    const restoreData = (await restoreRes.json()) as { restoredOk: boolean };
    assert.equal(restoreData.restoredOk, true);
  } finally {
    await srv.close();
  }
});

import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hashIpForComparison, isPrivateOrLoopbackIpv4, maskIp } from "../core/privacy.js";
import { evaluateAuditScores } from "../core/scorer.js";
import { stripLocalToggleRawFields } from "../core/engine.js";
import type { PlatformAdapter } from "../platforms/types.js";
import type { AuditReport } from "../types/report.js";
import { renderReportHtml } from "../ui/render-html.js";

export interface LocalServerHandle {
  url: string;
  port: number;
  token: string;
  close: () => Promise<void>;
}

export async function startLocalReportServer(
  initialReport: AuditReport,
  adapter: PlatformAdapter,
  sessionSalt: string,
  options: { idleTimeoutMs?: number } = {}
): Promise<LocalServerHandle> {
  const token = randomBytes(16).toString("hex");
  let currentReport: AuditReport = initialReport;
  let cachedNetSnap = await adapter.getNetworkSnapshot();
  let cachedEnvSnap = await adapter.inspectEnvironmentHygiene(cachedNetSnap, currentReport.proxyAudit);
  let idleTimer: NodeJS.Timeout | undefined;

  const idleTimeoutMs = options.idleTimeoutMs ?? 30 * 60 * 1000; // 默认 30 分钟无操作自动安全退出

  const resetIdle = (srv: Server): void => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      srv.close();
    }, idleTimeoutMs);
    idleTimer.unref?.();
  };

  const recomputeScores = (): void => {
    const scored = evaluateAuditScores({
      netSnap: cachedNetSnap,
      primaryExit: currentReport.primaryExit,
      systemProxyExit: currentReport.systemProxyExit,
      ipv6Exit: currentReport.ipv6Exit,
      domainMatrix: currentReport.domainMatrix,
      binaries: currentReport.binaries,
      proxyAudit: currentReport.proxyAudit,
      firewallAudit: currentReport.firewallAudit,
      envSnap: cachedEnvSnap,
      browserSync: currentReport.browserSync,
      killSwitchDrill: currentReport.killSwitchDrill,
    });

    currentReport = {
      ...currentReport,
      rawScore: scored.rawScore,
      finalScore: scored.finalScore,
      grade: scored.grade,
      redlineTriggered: scored.redlineTriggered,
      redlineReasons: scored.redlineReasons,
      killSwitchVerifiedBadge: scored.killSwitchVerifiedBadge,
      modules: scored.modules,
    };
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    resetIdle(server);

    // 严格校验 Host 必须为本地回环，阻止 DNS Rebinding 攻击
    const hostHeader = (req.headers.host || "").toLowerCase();
    if (!/^127\.0\.0\.1(:\d+)?$|^localhost(:\d+)?$/.test(hostHeader)) {
      res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Forbidden: Loopback access only");
      return;
    }

    const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const queryToken = reqUrl.searchParams.get("token");
    const headerToken = req.headers["x-audit-token"];
    const authorized = queryToken === token || headerToken === token;

    if (!authorized) {
      res.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Unauthorized session token");
      return;
    }

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    if (req.method === "GET" && reqUrl.pathname === "/") {
      const html = renderReportHtml(currentReport, { interactiveToken: token });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
      return;
    }

    if (req.method === "GET" && reqUrl.pathname === "/api/report") {
      sendJson(res, 200, currentReport);
      return;
    }

    if (req.method === "GET" && reqUrl.pathname === "/api/export-html") {
      const safeReport = stripLocalToggleRawFields(currentReport);
      const staticHtml = renderReportHtml(safeReport, { interactiveToken: "" });
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": `attachment; filename="claude-leak-report-${safeReport.reportId}.html"`,
      });
      res.end(staticHtml);
      return;
    }

    if (req.method === "GET" && reqUrl.pathname === "/api/net-status") {
      cachedNetSnap = await adapter.getNetworkSnapshot();
      const tunActive =
        cachedNetSnap.activeUtunInterfaces.length > 0 &&
        (cachedNetSnap.defaultRouteInterface.startsWith("utun") ||
          cachedNetSnap.defaultRouteInterface === "WinTUN");
      sendJson(res, 200, {
        tunActive,
        utunInterfaces: cachedNetSnap.activeUtunInterfaces,
        defaultRouteInterface: cachedNetSnap.defaultRouteInterface,
      });
      return;
    }

    if (req.method === "POST" && reqUrl.pathname === "/api/browser-sync") {
      if (currentReport.demoMode) {
        sendJson(res, 200, currentReport);
        return;
      }

      const body = await readJsonBody(req);
      const rawBrowserIp = typeof body.browserIp === "string" ? body.browserIp.trim() : "";
      const browserCountry =
        typeof body.browserCountry === "string" ? body.browserCountry.trim().toUpperCase() : undefined;
      const rawWebrtcIps = Array.isArray(body.webrtcIps)
        ? body.webrtcIps.filter((x): x is string => typeof x === "string")
        : [];

      const browserExitIpHash = rawBrowserIp ? hashIpForComparison(rawBrowserIp, sessionSalt) : undefined;
      const matchesCliExit =
        browserExitIpHash && currentReport.cliExitIpHash
          ? browserExitIpHash === currentReport.cliExitIpHash
          : undefined;

      // 分析 WebRTC STUN 抓到的候选 IP 是否包含非代理真实公网地址
      const publicWebrtcIps: string[] = [];
      let hasLanOnly = false;
      let hasMismatchPublic = false;

      for (const candidateIp of rawWebrtcIps) {
        const clean = candidateIp.trim();
        if (!clean || clean.endsWith(".local")) continue;
        if (!clean.includes(":") && isPrivateOrLoopbackIpv4(clean)) {
          hasLanOnly = true;
          continue;
        }
        if (clean.startsWith("fe80:") || clean === "::1") {
          hasLanOnly = true;
          continue;
        }
        const masked = maskIp(clean);
        if (!publicWebrtcIps.includes(masked)) {
          publicWebrtcIps.push(masked);
        }
        const candHash = hashIpForComparison(clean, sessionSalt);
        if (currentReport.cliExitIpHash && candHash !== currentReport.cliExitIpHash) {
          hasMismatchPublic = true;
        }
      }

      currentReport.browserSync = {
        completed: Boolean(rawBrowserIp) || Boolean(body.webrtcTested),
        browserExitIpMasked: rawBrowserIp ? maskIp(rawBrowserIp) : undefined,
        browserExitIpHash,
        browserCountryCode: browserCountry,
        matchesCliExit,
        webrtcTested: Boolean(body.webrtcTested),
        webrtcPublicIpsMasked: publicWebrtcIps,
        webrtcHasDomesticOrMismatchLeak: hasMismatchPublic,
        webrtcHasLanIpOnly: hasLanOnly && publicWebrtcIps.length === 0,
        browserTimezone: typeof body.browserTimezone === "string" ? body.browserTimezone : undefined,
        browserLanguages: Array.isArray(body.browserLanguages)
          ? body.browserLanguages.filter((x): x is string => typeof x === "string").slice(0, 5)
          : undefined,
      };

      recomputeScores();
      sendJson(res, 200, currentReport);
      return;
    }

    if (req.method === "POST" && reqUrl.pathname === "/api/drill") {
      // 演练判定前实时重新扫描本机二进制与 LuLu 防火墙规则状态，确保刚开启或刚导入规则的用户立即获得准确 S+ 判定
      const [probe, freshBinFw] = await Promise.all([
        adapter.runKillSwitchProbe(),
        adapter.scanBinariesAndFirewall(),
      ]);
      currentReport.binaries = freshBinFw.binaries;
      currentReport.firewallAudit = freshBinFw.firewall;

      if (probe.tunActive && !currentReport.demoMode) {
        currentReport.killSwitchDrill = {
          ...currentReport.killSwitchDrill,
          executed: false,
          tunActiveDuringDrill: true,
          verdict: "proxy_still_on",
          verdictTitle: {
            zh: "检测到 TUN 虚拟网卡仍在运行中，请先手动关闭代理再测！",
            en: "TUN virtual adapter is still active! Please disable TUN or quit proxy first.",
          },
          verdictDetail: {
            zh: "本工具遵守 100% 只读承诺，不会越权关停你的代理软件。请手动关掉 Clash TUN 开关（或退出代理软件）3 秒后再点此按钮。",
            en: "We never modify or stop your proxy automatically. Toggle TUN off manually for 3 seconds, then click test again.",
          },
        };
        sendJson(res, 200, currentReport);
        return;
      }

      const appFirewallLocked =
        currentReport.firewallAudit.claudeAppFullyLocked &&
        currentReport.firewallAudit.claudeCliLocked;

      if (probe.blocked) {
        currentReport.killSwitchDrill = {
          executed: true,
          executedAt: new Date().toISOString(),
          tunActiveDuringDrill: false,
          systemProbeBlocked: true,
          systemProbeLatencyMs: probe.latencyMs,
          perAppFirewallVerified: appFirewallLocked,
          verdict: "global_blocked",
          verdictTitle: {
            zh: `S+ 物理级全局阻断通过！无代理状态下探针在 ${probe.latencyMs}ms 被当场拦截`,
            en: `S+ Global Kill-Switch Passed! Outbound probe rejected in ${probe.latencyMs}ms`,
          },
          verdictDetail: {
            zh: "即使代理完全退出，系统级防火墙也死死拦住了所有非 TUN 外网连接（测试全程仅访问 1.1.1.1 公共回显，0 接触 Anthropic）。请立即重新开启代理并点下方恢复复检！",
            en: "All non-TUN outbound traffic was blocked at the OS firewall layer. Now re-enable your proxy and click Verify Restore below!",
          },
          proxyRestoredVerified: Boolean(currentReport.demoMode),
        };
      } else if (appFirewallLocked) {
        currentReport.killSwitchDrill = {
          executed: true,
          executedAt: new Date().toISOString(),
          tunActiveDuringDrill: false,
          systemProbeBlocked: false,
          systemProbeLatencyMs: probe.latencyMs,
          systemProbeLeakedIpMasked: probe.leakedIpMasked,
          systemProbeLeakedCountry: probe.leakedCountry,
          perAppFirewallVerified: true,
          verdict: "app_firewall_locked",
          verdictTitle: {
            zh: "S+ 应用级精准焊死验证通过！（日常软件不断网 + Claude 全家桶已锁死）",
            en: "S+ Per-App Firewall Verified! (Daily apps stay online while Claude binaries are locked)",
          },
          verdictDetail: {
            zh: `关闭代理后普通进程正常回落本地网络 (${probe.leakedIpMasked || "ISP"}) 不耽误微信/办公，同时已核实 LuLu 规则 100% 锁死 Claude 全家桶与原生 CLI（禁止非 Fake-IP 通信）。请记得重新开启代理并点击恢复复检！`,
            en: "Standard non-Claude apps fall back normally while LuLu rules keep all Claude binaries strictly locked to Fake-IP/TUN. Re-enable your proxy now!",
          },
          proxyRestoredVerified: false,
        };
      } else {
        currentReport.killSwitchDrill = {
          executed: true,
          executedAt: new Date().toISOString(),
          tunActiveDuringDrill: false,
          systemProbeBlocked: false,
          systemProbeLatencyMs: probe.latencyMs,
          systemProbeLeakedIpMasked: probe.leakedIpMasked,
          systemProbeLeakedCountry: probe.leakedCountry,
          perAppFirewallVerified: false,
          verdict: "leaked",
          verdictTitle: {
            zh: `高危裸奔预警！关闭代理后 ${probe.latencyMs}ms 即直连暴露真实网络 (${probe.leakedIpMasked || "ISP"} · ${probe.leakedCountry || "?"})`,
            en: `Kill-Switch Failed! Traffic leaked directly in ${probe.latencyMs}ms via ${probe.leakedIpMasked || "ISP"} (${probe.leakedCountry || "?"})`,
          },
          verdictDetail: {
            zh: "实测表明：一旦你的代理软件崩溃、更新重启或合盖休眠唤醒慢了 2 秒，电脑会自动切回本地宽带直连，而 Sentry / Datadog 等风控暗桩国内未被墙，将瞬间上报真实宽带 IP！",
            en: "If your proxy crashes or wakes up 2s late from sleep, Sentry/Datadog telemetry will immediately connect over your real ISP IP.",
          },
          proxyRestoredVerified: false,
        };
      }

      recomputeScores();
      sendJson(res, 200, currentReport);
      return;
    }

    if (req.method === "POST" && reqUrl.pathname === "/api/verify-restore") {
      if (currentReport.demoMode) {
        currentReport.killSwitchDrill.proxyRestoredVerified = true;
        sendJson(res, 200, currentReport);
        return;
      }

      cachedNetSnap = await adapter.getNetworkSnapshot();
      const exits = await adapter.probePublicExits(cachedNetSnap, { sessionSalt });
      const restoredOk =
        cachedNetSnap.activeUtunInterfaces.length > 0 &&
        Boolean(exits.primaryExit?.isSupportedRegion);

      if (restoredOk) {
        currentReport.primaryExit = exits.primaryExit;
        currentReport.killSwitchDrill.proxyRestoredVerified = true;
        cachedEnvSnap = await adapter.inspectEnvironmentHygiene(cachedNetSnap, currentReport.proxyAudit);
        recomputeScores();
      }

      sendJson(res, 200, {
        restoredOk,
        report: currentReport,
      });
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  resetIdle(server);
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const url = `http://127.0.0.1:${port}/?token=${token}`;

  return {
    url,
    port,
    token,
    close: () =>
      new Promise<void>((resolve) => {
        if (idleTimer) clearTimeout(idleTimer);
        server.close(() => resolve());
      }),
  };
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => {
      if (raw.length < 64 * 1024) raw += String(chunk);
    });
    req.on("end", () => {
      try {
        const parsed = JSON.parse(raw);
        resolve(parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

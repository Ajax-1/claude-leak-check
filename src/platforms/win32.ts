import { execFile } from "node:child_process";
import https from "node:https";
import { lookup } from "node:dns/promises";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir, networkInterfaces } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { REGION_NAMES, RESTRICTED_REGIONS } from "../core/domains.js";
import {
  hashIpForComparison,
  isFakeIpv4,
  isGlobalUnicastIpv6,
  isMainlandCarrierIpv6,
  maskIp,
  parseClashYamlMetadataSafely,
  sanitizePath,
} from "../core/privacy.js";
import { inspectClaudeSettingsAndProxyEnv } from "../core/settings-env-inspector.js";
import type {
  ClaudeBinaryItem,
  DomainProbeResult,
  DomainTarget,
  FirewallAudit,
  ProxyStaticAudit,
  PublicExitSnapshot,
} from "../types/report.js";
import { classifyAsnOrg } from "./darwin.js";
import type {
  AuditOptions,
  EnvironmentHygieneSnapshot,
  KillSwitchProbeSnapshot,
  NetworkStackSnapshot,
  PlatformAdapter,
} from "./types.js";

const execFileAsync = promisify(execFile);

function httpsGetText(
  url: string,
  family: 4 | 6 = 4,
  timeoutMs = 3200
): Promise<{ ok: boolean; body: string; latencyMs: number }> {
  const start = Date.now();
  return new Promise((resolve) => {
    const req = https.get(url, { family, timeout: timeoutMs, agent: false }, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        if (data.length < 128 * 1024) data += String(chunk);
      });
      res.on("end", () => {
        resolve({ ok: (res.statusCode || 500) < 400, body: data, latencyMs: Date.now() - start });
      });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, body: "", latencyMs: Date.now() - start });
    });
    req.on("error", () => {
      resolve({ ok: false, body: "", latencyMs: Date.now() - start });
    });
  });
}

export class Win32PlatformAdapter implements PlatformAdapter {
  readonly platform = "win32" as const;

  async getNetworkSnapshot(): Promise<NetworkStackSnapshot> {
    const ifaces = networkInterfaces();
    const activeUtunInterfaces: string[] = [];
    const publicIpv6Interfaces: { iface: string; addressMasked: string; isMainlandCarrier: boolean }[] = [];

    for (const [name, addrs] of Object.entries(ifaces)) {
      if (!addrs) continue;
      if (/(meta|mihomo|clash|wintun|sing-box|tun)/i.test(name)) {
        if (addrs.some((a) => a.family === "IPv4" && !a.internal)) {
          activeUtunInterfaces.push(name);
        }
      }
      for (const a of addrs) {
        if (a.family === "IPv6" && !a.internal && isGlobalUnicastIpv6(a.address)) {
          publicIpv6Interfaces.push({
            iface: name,
            addressMasked: maskIp(a.address),
            isMainlandCarrier: isMainlandCarrierIpv6(a.address),
          });
        }
      }
    }

    return {
      activeUtunInterfaces,
      defaultRouteInterface: activeUtunInterfaces[0] || "Ethernet/Wi-Fi",
      dnsServers: [],
      dnsServersMasked: [],
      tailscaleMagicDns: false,
      icloudPrivateRelaySuspected: false,
      competingVpns: [],
      systemProxy: {
        httpEnabled: false,
        httpsEnabled: false,
        socksEnabled: false,
      },
      publicIpv6Interfaces,
    };
  }

  async probePublicExits(
    netSnap: NetworkStackSnapshot,
    options: AuditOptions
  ): Promise<{
    primaryExit?: PublicExitSnapshot;
    nonGfwExit?: PublicExitSnapshot;
    nonGfwExitIpHash?: string;
    systemProxyExit?: PublicExitSnapshot;
    ipv6Exit?: PublicExitSnapshot;
    cliExitIpHash?: string;
  }> {
    const shouldProbeNonGfw =
      netSnap.activeUtunInterfaces.length === 0 || options.topologyPreference === "router-gateway";
    const [trace, ipinfo, awsRes] = await Promise.all([
      httpsGetText("https://1.1.1.1/cdn-cgi/trace", 4, 3200),
      httpsGetText("https://ipinfo.io/json", 4, 3200),
      shouldProbeNonGfw
        ? httpsGetText("https://checkip.amazonaws.com", 4, 2800)
        : Promise.resolve(null),
    ]);
    let primaryExit: PublicExitSnapshot | undefined;
    let cliExitIpHash: string | undefined;

    let ipinfoJson: Record<string, unknown> = {};
    if (ipinfo.ok) {
      try {
        ipinfoJson = JSON.parse(ipinfo.body) as Record<string, unknown>;
      } catch {
        // ignore
      }
    }

    if (trace.ok) {
      const lines = Object.fromEntries(
        trace.body
          .split(/\r?\n/)
          .filter((l) => l.includes("="))
          .map((l) => l.split("=", 2))
      ) as Record<string, string>;
      if (lines.ip) {
        const cc = (lines.loc || "UNKNOWN").toUpperCase();
        const orgStr = typeof ipinfoJson.org === "string" ? ipinfoJson.org : undefined;
        const asnMatch = orgStr ? /^(AS\d+)\s*(.*)$/.exec(orgStr) : null;
        cliExitIpHash = hashIpForComparison(lines.ip, options.sessionSalt);
        primaryExit = {
          source: "cloudflare-1.1.1.1",
          ipMasked: maskIp(lines.ip),
          ipRawForLocalToggle: lines.ip,
          countryCode: cc,
          countryName: REGION_NAMES[cc] || { zh: cc, en: cc },
          asn: asnMatch ? asnMatch[1] : undefined,
          org: asnMatch ? asnMatch[2] : orgStr,
          asnType: classifyAsnOrg(orgStr),
          isSupportedRegion: !RESTRICTED_REGIONS.has(cc) && cc !== "UNKNOWN",
          isRestrictedRegion: RESTRICTED_REGIONS.has(cc),
          viaMode: "direct-socket-noproxy",
          latencyMs: trace.latencyMs,
        };
      }
    }

    let ipv6Exit: PublicExitSnapshot | undefined;
    if (netSnap.publicIpv6Interfaces.length > 0) {
      const v6 = await httpsGetText("https://[2606:4700:4700::1111]/cdn-cgi/trace", 6, 2600);
      if (v6.ok && v6.body.includes("ip=")) {
        const lines = Object.fromEntries(
          v6.body
            .split(/\r?\n/)
            .filter((l) => l.includes("="))
            .map((l) => l.split("=", 2))
        ) as Record<string, string>;
        if (lines.ip) {
          const cc = (lines.loc || "UNKNOWN").toUpperCase();
          ipv6Exit = {
            source: "cloudflare-ipv6",
            ipMasked: maskIp(lines.ip),
            ipRawForLocalToggle: lines.ip,
            countryCode: cc,
            countryName: REGION_NAMES[cc] || { zh: cc, en: cc },
            asnType: "unknown",
            isSupportedRegion: !RESTRICTED_REGIONS.has(cc),
            isRestrictedRegion: RESTRICTED_REGIONS.has(cc),
            viaMode: "ipv6",
            latencyMs: v6.latencyMs,
          };
        }
      }
    }

    let nonGfwExit: PublicExitSnapshot | undefined;
    let nonGfwExitIpHash: string | undefined;
    const awsIp = awsRes?.ok && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(awsRes.body.trim()) ? awsRes.body.trim() : undefined;
    const ipinfoIp = typeof ipinfoJson.ip === "string" && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ipinfoJson.ip.trim())
      ? ipinfoJson.ip.trim()
      : undefined;
    const nonGfwRawIp = awsIp || ipinfoIp;
    if (nonGfwRawIp) {
      nonGfwExitIpHash = hashIpForComparison(nonGfwRawIp, options.sessionSalt);
      const sameAsPrimary = Boolean(cliExitIpHash && nonGfwExitIpHash === cliExitIpHash);
      const cc = (
        (ipinfoIp === nonGfwRawIp && typeof ipinfoJson.country === "string"
          ? ipinfoJson.country
          : sameAsPrimary && primaryExit
            ? primaryExit.countryCode
            : "UNKNOWN") || "UNKNOWN"
      ).toUpperCase();
      nonGfwExit = {
        source: awsIp ? "aws-checkip" : "ipinfo-direct",
        ipMasked: maskIp(nonGfwRawIp),
        ipRawForLocalToggle: nonGfwRawIp,
        countryCode: cc,
        countryName: REGION_NAMES[cc] || { zh: cc, en: cc },
        asnType: sameAsPrimary && primaryExit ? primaryExit.asnType : "unknown",
        isSupportedRegion: !RESTRICTED_REGIONS.has(cc) && cc !== "UNKNOWN",
        isRestrictedRegion: RESTRICTED_REGIONS.has(cc),
        viaMode: "non-gfw-echo",
        latencyMs: awsRes?.latencyMs ?? ipinfo.latencyMs,
      };
    }

    return { primaryExit, nonGfwExit, nonGfwExitIpHash, ipv6Exit, cliExitIpHash };
  }

  async probeDomainMatrix(
    targets: DomainTarget[],
    _proxyAudit: ProxyStaticAudit,
    primaryExit: PublicExitSnapshot | undefined,
    options: AuditOptions
  ): Promise<DomainProbeResult[]> {
    const netSnap = await this.getNetworkSnapshot();
    const hasTun = netSnap.activeUtunInterfaces.length > 0;
    const isRouterMode = options.resolvedTopology === "router-gateway";

    return Promise.all(
      targets.map(async (target) => {
        let resolvedIps: string[] = [];
        let hasIpv6Resolution = false;
        if (target.category === "raw_ip") {
          resolvedIps = [target.host];
        } else {
          try {
            const addrs = await lookup(target.host, { all: true });
            resolvedIps = addrs.map((a) => a.address);
            hasIpv6Resolution = addrs.some((a) => a.family === 6 && isGlobalUnicastIpv6(a.address));
          } catch {
            resolvedIps = [];
          }
        }
        const firstIpv4 = resolvedIps.find((ip) => !ip.includes(":")) || "";
        const fakeIp = firstIpv4 ? isFakeIpv4(firstIpv4) : false;
        const isPoisoned = firstIpv4 === "0.0.0.0" || firstIpv4.startsWith("127.");
        const isTunRouted = isRouterMode ? Boolean(firstIpv4 && !isPoisoned) : hasTun || fakeIp;
        const gfwSplitLeak =
          isRouterMode &&
          options.nonGfwMatchesPrimary === false &&
          !target.officialAnthropic &&
          target.host !== "accounts.google.com";

        return {
          host: target.host,
          category: target.category,
          officialAnthropic: target.officialAnthropic,
          label: target.label,
          riskNote: target.riskNote,
          resolvedIps: [],
          maskedResolvedIps: resolvedIps.slice(0, 3).map((ip) => maskIp(ip)),
          isFakeIp: fakeIp,
          hasIpv6Resolution,
          routeInterface: isRouterMode
            ? "Ethernet/Wi-Fi (GW)"
            : isTunRouted
              ? netSnap.activeUtunInterfaces[0] || "WinTUN"
              : "Physical NIC",
          isTunRouted,
          staticRuleDecision: "unknown",
          edgeExitIpMasked: primaryExit?.ipMasked,
          edgeCountry: primaryExit?.countryCode,
          probeMode: "local-zero-packet",
          status:
            !isTunRouted || isPoisoned || gfwSplitLeak || primaryExit?.isRestrictedRegion
              ? "critical"
              : isRouterMode || fakeIp || target.category === "raw_ip"
                ? "pass"
                : "warn",
          statusReason: gfwSplitLeak
            ? {
                zh: "软路由疑似开启 GFWList 绕过模式，未被墙风控域名将直连暴露宽带",
                en: "Router appears in GFWList mode; unblocked telemetry bypasses proxy",
              }
            : isRouterMode
              ? {
                  zh: "经局域网透明网关转发，与海外主出口同源",
                  en: "Routed via LAN transparent gateway aligned with primary exit",
                }
              : isTunRouted
                ? { zh: "已由虚拟网卡接管", en: "Intercepted by virtual TUN adapter" }
                : { zh: "未检测到活跃 WinTUN 虚拟网卡接管", en: "No active WinTUN adapter detected" },
        };
      })
    );
  }

  async auditProxyConfigSafely(options: AuditOptions): Promise<ProxyStaticAudit> {
    const empty: ProxyStaticAudit = {
      detectedClients: [],
      configInspected: false,
      localListenerPorts: [],
      claudeTargetGroups: [],
      autoFallbackRiskGroups: [],
      manualSelectCautionGroups: [],
      hasDirectInProxyGroups: false,
      hasRestrictedRegionInGroups: false,
      hasStealthDomainDirectRule: false,
      finalMatchIsDirect: false,
      ruleCount: 0,
    };
    if (options.skipProxyFileRead) return empty;
    const appData = process.env.APPDATA || join(homedir(), "AppData/Roaming");
    const candidate = join(appData, "io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml");
    try {
      if (existsSync(candidate) && statSync(candidate).size < 10 * 1024 * 1024) {
        return parseClashYamlMetadataSafely(readFileSync(candidate, "utf8"), ["Clash Verge Rev"]);
      }
    } catch {
      // ignore
    }
    return empty;
  }

  async scanBinariesAndFirewall(): Promise<{ binaries: ClaudeBinaryItem[]; firewall: FirewallAudit }> {
    const localAppData = process.env.LOCALAPPDATA || join(homedir(), "AppData/Local");
    const claudeExe = join(localAppData, "AnthropicClaude/claude.exe");
    const binaries: ClaudeBinaryItem[] = [];
    if (existsSync(claudeExe)) {
      binaries.push({
        id: "win-desktop",
        name: "Claude Desktop (Windows)",
        displayPath: sanitizePath(claudeExe),
        kind: "desktop-main",
        exists: true,
        signedByAnthropic: true,
        firewallCovered: false,
        riskLevel: "warn",
        note: {
          zh: "Windows 深度 WFP 防火墙规则审计将在后续版本完善",
          en: "Windows WFP firewall audit support is in preview",
        },
      });
    }
    return {
      binaries,
      firewall: {
        luluInstalled: false,
        luluActive: false,
        luluCoveredRuleCount: 0,
        luluCidrMisconfiguredRules: [],
        claudeAppFullyLocked: false,
        claudeCliLocked: false,
        littleSnitchDetected: false,
        pfDeadlockRiskDetected: false,
        pfDeadlockFiles: [],
        pfDeadlockResidualFiles: [],
        bootRaceRisk: false,
      },
    };
  }

  async inspectEnvironmentHygiene(
    netSnap: NetworkStackSnapshot,
    proxyAudit?: ProxyStaticAudit
  ): Promise<EnvironmentHygieneSnapshot> {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
    const home = homedir();
    let settingsJsonRaw: string | undefined;
    const settingsPath = join(home, ".claude/settings.json");
    try {
      if (existsSync(settingsPath) && statSync(settingsPath).size < 1024 * 1024) {
        settingsJsonRaw = readFileSync(settingsPath, "utf8");
      }
    } catch {
      // ignore
    }

    const activeListeningLoopbackPorts: number[] = [];
    try {
      const { stdout } = await execFileAsync("netstat", ["-an", "-p", "tcp"], { timeout: 1800 });
      for (const line of stdout.split(/\r?\n/)) {
        if (!/LISTENING/i.test(line)) continue;
        const m = /\b(?:127\.0\.0\.1|0\.0\.0\.0):(\d{1,5})\s/.exec(line);
        if (m) {
          const p = Number(m[1]);
          if (p > 0 && p <= 65535) activeListeningLoopbackPorts.push(p);
        }
      }
    } catch {
      // ignore
    }

    const settingsInspection = inspectClaudeSettingsAndProxyEnv({
      settingsJsonRaw,
      processEnv: process.env,
      systemProxyPort: netSnap.systemProxy.proxyPort,
      proxyConfigListenerPorts: proxyAudit?.localListenerPorts ?? [],
      activeListeningLoopbackPorts,
    });

    return {
      systemTimezone: tz,
      isMainlandTimezone: /^(Asia\/Shanghai|Asia\/Urumqi)$/i.test(tz),
      systemLocale: Intl.DateTimeFormat().resolvedOptions().locale,
      defaultBrowser: "System Browser",
      hasAnthropicBaseUrl: settingsInspection.hasAnthropicBaseUrl,
      anthropicBaseUrlIsCustomThirdParty: settingsInspection.anthropicBaseUrlIsCustomThirdParty,
      settingsHasCustomBaseUrl: settingsInspection.settingsHasCustomBaseUrl,
      proxyEnvVarsPresent: settingsInspection.proxyEnvVarsPresent,
      proxyEnvConflictsWithSystem: settingsInspection.proxyEnvConflictsWithSystem,
      dedicatedLoopbackProxyPorts: settingsInspection.dedicatedLoopbackProxyPorts,
      deadLoopbackProxyPorts: settingsInspection.deadLoopbackProxyPorts,
      riskyReverseProxies: [],
      mcpServerCount: 0,
      mcpCommands: [],
      suspiciousSettingsEnvKeys: settingsInspection.suspiciousSettingsEnvKeys,
    };
  }

  async runKillSwitchProbe(sessionSalt?: string): Promise<KillSwitchProbeSnapshot> {
    const netSnap = await this.getNetworkSnapshot();
    const probe = await httpsGetText("https://1.1.1.1/cdn-cgi/trace", 4, 2500);
    if (!probe.ok) {
      return {
        tunActive: netSnap.activeUtunInterfaces.length > 0,
        blocked: true,
        latencyMs: probe.latencyMs,
      };
    }
    const lines = Object.fromEntries(
      probe.body
        .split(/\r?\n/)
        .filter((l) => l.includes("="))
        .map((l) => l.split("=", 2))
    ) as Record<string, string>;
    return {
      tunActive: netSnap.activeUtunInterfaces.length > 0,
      blocked: false,
      latencyMs: probe.latencyMs,
      leakedIpMasked: lines.ip ? maskIp(lines.ip) : undefined,
      leakedIpHash: lines.ip && sessionSalt ? hashIpForComparison(lines.ip, sessionSalt) : undefined,
      leakedCountry: lines.loc?.toUpperCase(),
    };
  }
}

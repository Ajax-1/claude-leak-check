import { execFile } from "node:child_process";
import { lookup } from "node:dns/promises";
import {
  closeSync,
  existsSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  readSync,
  statSync,
} from "node:fs";
import { homedir, networkInterfaces } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { REGION_NAMES, RESTRICTED_REGIONS } from "../core/domains.js";
import {
  hashIpForComparison,
  isFakeIpv4,
  isGlobalUnicastIpv6,
  isMainlandCarrierIpv6,
  isPrivateOrLoopbackIpv4,
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
import {
  extractLaunchDaemonLabelAndScripts,
  hasMacosPfDeadlockPattern,
  isLaunchDaemonActive,
  parseAppleXmlPlist,
  parseLuluRules,
} from "./lulu-parser.js";
import type {
  AuditOptions,
  EnvironmentHygieneSnapshot,
  KillSwitchProbeSnapshot,
  NetworkStackSnapshot,
  PlatformAdapter,
} from "./types.js";

const execFileAsync = promisify(execFile);

async function runCmd(cmd: string, args: string[], timeoutMs = 2500): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, {
      timeout: timeoutMs,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, LC_ALL: "C" },
    });
    return stdout || "";
  } catch {
    return "";
  }
}

/**
 * 合并读取 stdout 与 stderr（macOS 的 `/usr/bin/codesign -dv` 全部签名元数据均输出在 stderr）
 */
async function runCmdCombined(cmd: string, args: string[], timeoutMs = 2500): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      timeout: timeoutMs,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, LC_ALL: "C" },
    });
    return `${stdout || ""}\n${stderr || ""}`.trim();
  } catch (err) {
    if (err && typeof err === "object") {
      const rec = err as { stdout?: unknown; stderr?: unknown };
      const out = typeof rec.stdout === "string" ? rec.stdout : "";
      const errOut = typeof rec.stderr === "string" ? rec.stderr : "";
      return `${out}\n${errOut}`.trim();
    }
    return "";
  }
}

export function verifyAnthropicCodesignOutput(codesignCombinedOutput: string): {
  signedByAnthropic: boolean;
  identifier?: string;
  teamId?: string;
} {
  if (!codesignCombinedOutput || /not signed at all/i.test(codesignCombinedOutput)) {
    return { signedByAnthropic: false };
  }
  const idMatch = /^Identifier=(\S+)/m.exec(codesignCombinedOutput);
  const teamMatch = /^TeamIdentifier=(\S+)/m.exec(codesignCombinedOutput);
  const identifier = idMatch?.[1];
  const teamId = teamMatch?.[1];

  const signedByAnthropic =
    teamId === "Q6L2SF6YDW" ||
    Boolean(identifier && /^com\.anthropic\.claude(?:-code|fordesktop)?(?:\.|$)/i.test(identifier));

  return { signedByAnthropic, identifier, teamId };
}

async function runCurlProbe(
  args: string[],
  timeoutSec = 3.2
): Promise<{ ok: boolean; body: string; latencyMs: number }> {
  const start = Date.now();
  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/curl",
      ["-sS", "--max-time", String(timeoutSec), ...args],
      {
        timeout: Math.ceil((timeoutSec + 0.8) * 1000),
        maxBuffer: 512 * 1024,
        env: {
          PATH: "/usr/bin:/bin",
          HOME: homedir(),
        },
      }
    );
    return { ok: Boolean(stdout.trim()), body: stdout, latencyMs: Date.now() - start };
  } catch {
    return { ok: false, body: "", latencyMs: Date.now() - start };
  }
}

// 注意：AS174 Cogent 属于国际 Tier-1 骨干网与企业专线运营商 (business)，不列入普通廉价云主机 Hosting 关键字
const HOSTING_ORG_KEYWORDS =
  /(digitalocean|vultr|choopa|linode|akamai\s*connected|amazonaws|\baws\b|google\s*cloud|googleusercontent|hetzner|ovh|oracle|racknerd|multacom|dmit|it7\s*networks|bandwagon|leaseweb|contabo|datacamp|m247|tzulo|zenlayer|sharktech|psychz|quadranet|clouvider|hostinger|kamatera|alibaba|aliyun|tencent|huawei\s*cloud|ucloud|volcengine)/i;

const ISP_ORG_KEYWORDS =
  /(comcast|xfinity|at&t|att\s*services|verizon|charter|spectrum|cox\s*communications|t-mobile|frontier|centurylink|lumen|sonic|singtel|starhub|m1\s*limited|ntt\s*docomo|ocn|kddi|softbank|korea\s*telecom|\bkt\b|sk\s*broadband|lg\s*uplus|chunghwa|hinet|british\s*telecom|\bbt\b|virgin\s*media|sky\s*uk|deutsche\s*telekom|vodafone|orange|bell\s*canada|rogers|telus|telstra|optus)/i;

export function classifyAsnOrg(
  org?: string
): "isp" | "hosting" | "education" | "business" | "unknown" {
  if (!org) return "unknown";
  if (HOSTING_ORG_KEYWORDS.test(org)) return "hosting";
  if (/(university|college|institute|edu\b|ernet|cernet)/i.test(org)) return "education";
  if (ISP_ORG_KEYWORDS.test(org)) return "isp";
  return "business";
}

function parseCdnCgiTrace(body: string): { ip?: string; loc?: string; colo?: string } {
  const map: Record<string, string> = {};
  for (const line of body.split(/\r?\n/)) {
    const idx = line.indexOf("=");
    if (idx > 0) {
      map[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  return { ip: map.ip, loc: map.loc?.toUpperCase(), colo: map.colo };
}

function getRegionName(code: string): { zh: string; en: string } {
  const upper = (code || "UNKNOWN").toUpperCase();
  return REGION_NAMES[upper] || { zh: upper, en: upper };
}

export class DarwinPlatformAdapter implements PlatformAdapter {
  readonly platform = "darwin" as const;

  async getNetworkSnapshot(): Promise<NetworkStackSnapshot> {
    const ifaces = networkInterfaces();
    const activeUtunInterfaces: string[] = [];
    const publicIpv6Interfaces: { iface: string; addressMasked: string; isMainlandCarrier: boolean }[] = [];

    for (const [name, addrs] of Object.entries(ifaces)) {
      if (!addrs) continue;
      if (name.startsWith("utun")) {
        const hasIpv4 = addrs.some((a) => a.family === "IPv4" && !a.internal);
        if (hasIpv4) {
          activeUtunInterfaces.push(name);
        }
      }

      for (const a of addrs) {
        if (a.family === "IPv6" && !a.internal && !name.startsWith("utun") && isGlobalUnicastIpv6(a.address)) {
          publicIpv6Interfaces.push({
            iface: name,
            addressMasked: maskIp(a.address),
            isMainlandCarrier: isMainlandCarrierIpv6(a.address),
          });
        }
      }
    }

    const [routeOut, dnsOut, proxyOut, psOut] = await Promise.all([
      runCmd("/sbin/route", ["-n", "get", "1.1.1.1"], 1800),
      runCmd("/usr/sbin/scutil", ["--dns"], 2000),
      runCmd("/usr/sbin/scutil", ["--proxy"], 1800),
      runCmd("/bin/ps", ["-axo", "comm="], 2000),
    ]);

    const ifaceMatch = /interface:\s*(\S+)/.exec(routeOut);
    const defaultRouteInterface = ifaceMatch ? ifaceMatch[1].trim() : "";
    if (defaultRouteInterface.startsWith("utun") && !activeUtunInterfaces.includes(defaultRouteInterface)) {
      activeUtunInterfaces.push(defaultRouteInterface);
    }

    const dnsServers: string[] = [];
    const resolver1Block = dnsOut.split(/DNS configuration \(for scoped queries\)/)[0] || dnsOut;
    const nsRegex = /nameserver\[\d+\]\s*:\s*(\S+)/g;
    let m: RegExpExecArray | null;
    while ((m = nsRegex.exec(resolver1Block)) !== null) {
      const ns = m[1].trim();
      if (!dnsServers.includes(ns) && dnsServers.length < 6) {
        dnsServers.push(ns);
      }
    }

    const tailscaleMagicDns = dnsServers.includes("100.100.100.100");

    const httpEnabled = /HTTPEnable\s*:\s*1/.test(proxyOut);
    const httpsEnabled = /HTTPSEnable\s*:\s*1/.test(proxyOut);
    const socksEnabled = /SOCKSEnable\s*:\s*1/.test(proxyOut);
    const proxyHostMatch = /(?:HTTPSProxy|HTTPProxy|SOCKSProxy)\s*:\s*(\S+)/.exec(proxyOut);
    const proxyPortMatch = /(?:HTTPSPort|HTTPPort|SOCKSPort)\s*:\s*(\d+)/.exec(proxyOut);

    const competingVpns: string[] = [];
    const psLines = psOut.split(/\r?\n/).map((s) => basename(s.trim()));
    const vpnSignatures: [RegExp, string][] = [
      [/^Tailscale$|^tailscaled$/i, "Tailscale"],
      [/^zerotier-one$/i, "ZeroTier"],
      [/^vpnagentd$/i, "Cisco AnyConnect"],
      [/^PanGPS$/i, "Palo Alto GlobalProtect"],
      [/^CloudflareWARP$|^warp-svc$/i, "Cloudflare WARP"],
      [/^WireGuard$/i, "WireGuard"],
      [/^openvpn$/i, "OpenVPN"],
    ];
    for (const [re, label] of vpnSignatures) {
      if (psLines.some((p) => re.test(p)) && !competingVpns.includes(label)) {
        competingVpns.push(label);
      }
    }

    const icloudPrivateRelaySuspected =
      psLines.some((p) => /^nspserviceagent$/i.test(p)) &&
      dnsOut.toLowerCase().includes("mask.icloud.com");

    return {
      activeUtunInterfaces,
      defaultRouteInterface,
      dnsServers,
      dnsServersMasked: dnsServers.map((ip) =>
        isPrivateOrLoopbackIpv4(ip) || isFakeIpv4(ip) ? maskIp(ip) : maskIp(ip)
      ),
      tailscaleMagicDns,
      icloudPrivateRelaySuspected,
      competingVpns,
      systemProxy: {
        httpEnabled,
        httpsEnabled,
        socksEnabled,
        proxyHost: proxyHostMatch?.[1],
        proxyPort: proxyPortMatch ? Number(proxyPortMatch[1]) : undefined,
      },
      publicIpv6Interfaces,
    };
  }

  async probePublicExits(
    netSnap: NetworkStackSnapshot,
    options: AuditOptions
  ): Promise<{
    primaryExit?: PublicExitSnapshot;
    systemProxyExit?: PublicExitSnapshot;
    ipv6Exit?: PublicExitSnapshot;
    cliExitIpHash?: string;
  }> {
    const directTracePromise = runCurlProbe(["-4", "--noproxy", "*", "https://1.1.1.1/cdn-cgi/trace"], 3.2).then(
      async (res) => {
        if (res.ok && res.body.includes("ip=")) return { ...res, source: "cloudflare-1.1.1.1" };
        const fallback = await runCurlProbe(
          ["-4", "--noproxy", "*", "https://www.cloudflare.com/cdn-cgi/trace"],
          3.2
        );
        return { ...fallback, source: "cloudflare-edge" };
      }
    );

    const ipinfoPromise = runCurlProbe(["-4", "--noproxy", "*", "https://ipinfo.io/json"], 3.2);

    const sysProxyEnabled =
      netSnap.systemProxy.httpEnabled ||
      netSnap.systemProxy.httpsEnabled ||
      netSnap.systemProxy.socksEnabled;
    const proxyPort = sysProxyEnabled
      ? netSnap.systemProxy.proxyPort
      : extractPortFromProxyEnv(process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.ALL_PROXY);

    const sysProxyPromise = proxyPort
      ? runCurlProbe(
          ["-4", "-x", `http://127.0.0.1:${proxyPort}`, "https://www.cloudflare.com/cdn-cgi/trace"],
          3.2
        )
      : Promise.resolve(null);

    const ipv6Promise =
      netSnap.publicIpv6Interfaces.length > 0
        ? runCurlProbe(["-6", "--noproxy", "*", "https://[2606:4700:4700::1111]/cdn-cgi/trace"], 2.6)
        : Promise.resolve(null);

    const [directTrace, ipinfoRes, sysProxyTrace, ipv6Trace] = await Promise.all([
      directTracePromise,
      ipinfoPromise,
      sysProxyPromise,
      ipv6Promise,
    ]);

    let primaryExit: PublicExitSnapshot | undefined;
    let cliExitIpHash: string | undefined;

    let ipinfoJson: Record<string, unknown> = {};
    if (ipinfoRes.ok) {
      try {
        ipinfoJson = JSON.parse(ipinfoRes.body) as Record<string, unknown>;
      } catch {
        // ignore
      }
    }

    const traceParsed = directTrace.ok ? parseCdnCgiTrace(directTrace.body) : {};
    const rawPrimaryIp = traceParsed.ip || (typeof ipinfoJson.ip === "string" ? ipinfoJson.ip : undefined);
    const rawPrimaryCountry = (
      traceParsed.loc ||
      (typeof ipinfoJson.country === "string" ? ipinfoJson.country : "UNKNOWN")
    ).toUpperCase();

    if (rawPrimaryIp) {
      const orgStr = typeof ipinfoJson.org === "string" ? ipinfoJson.org : undefined;
      const asnMatch = orgStr ? /^(AS\d+)\s*(.*)$/.exec(orgStr) : null;
      cliExitIpHash = hashIpForComparison(rawPrimaryIp, options.sessionSalt);
      primaryExit = {
        source: directTrace.source,
        ipMasked: maskIp(rawPrimaryIp),
        ipRawForLocalToggle: rawPrimaryIp,
        countryCode: rawPrimaryCountry,
        countryName: getRegionName(rawPrimaryCountry),
        region: typeof ipinfoJson.region === "string" ? ipinfoJson.region : undefined,
        city: typeof ipinfoJson.city === "string" ? ipinfoJson.city : undefined,
        asn: asnMatch ? asnMatch[1] : undefined,
        org: asnMatch ? asnMatch[2] : orgStr,
        asnType: classifyAsnOrg(orgStr),
        isSupportedRegion: !RESTRICTED_REGIONS.has(rawPrimaryCountry) && rawPrimaryCountry !== "UNKNOWN",
        isRestrictedRegion: RESTRICTED_REGIONS.has(rawPrimaryCountry),
        viaMode: "direct-socket-noproxy",
        latencyMs: directTrace.latencyMs,
      };
    }

    let systemProxyExit: PublicExitSnapshot | undefined;
    if (sysProxyTrace && sysProxyTrace.ok) {
      const sp = parseCdnCgiTrace(sysProxyTrace.body);
      if (sp.ip) {
        const cc = (sp.loc || "UNKNOWN").toUpperCase();
        systemProxyExit = {
          source: `127.0.0.1:${proxyPort}`,
          ipMasked: maskIp(sp.ip),
          ipRawForLocalToggle: sp.ip,
          countryCode: cc,
          countryName: getRegionName(cc),
          asnType: "unknown",
          isSupportedRegion: !RESTRICTED_REGIONS.has(cc) && cc !== "UNKNOWN",
          isRestrictedRegion: RESTRICTED_REGIONS.has(cc),
          viaMode: "system-proxy",
          latencyMs: sysProxyTrace.latencyMs,
        };
      }
    }

    let ipv6Exit: PublicExitSnapshot | undefined;
    if (ipv6Trace && ipv6Trace.ok) {
      const v6 = parseCdnCgiTrace(ipv6Trace.body);
      if (v6.ip) {
        const cc = (v6.loc || "UNKNOWN").toUpperCase();
        ipv6Exit = {
          source: "cloudflare-ipv6",
          ipMasked: maskIp(v6.ip),
          ipRawForLocalToggle: v6.ip,
          countryCode: cc,
          countryName: getRegionName(cc),
          asnType: "unknown",
          isSupportedRegion: !RESTRICTED_REGIONS.has(cc) && cc !== "UNKNOWN",
          isRestrictedRegion: RESTRICTED_REGIONS.has(cc),
          viaMode: "ipv6",
          latencyMs: ipv6Trace.latencyMs,
        };
      }
    }

    return { primaryExit, systemProxyExit, ipv6Exit, cliExitIpHash };
  }

  async probeDomainMatrix(
    targets: DomainTarget[],
    proxyAudit: ProxyStaticAudit,
    primaryExit: PublicExitSnapshot | undefined,
    options: AuditOptions
  ): Promise<DomainProbeResult[]> {
    const results = await Promise.all(
      targets.map(async (target): Promise<DomainProbeResult> => {
        const isRawIp = target.category === "raw_ip";
        let resolvedIps: string[] = [];
        let hasIpv6Resolution = false;

        if (isRawIp) {
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

        const firstIpv4 = resolvedIps.find((ip) => !ip.includes(":")) || resolvedIps[0] || "";
        const fakeIp = firstIpv4 ? isFakeIpv4(firstIpv4) : false;

        let routeInterface = "";
        if (firstIpv4) {
          const routeOut = await runCmd("/sbin/route", ["-n", "get", firstIpv4.split("%")[0]], 1400);
          const m = /interface:\s*(\S+)/.exec(routeOut);
          routeInterface = m ? m[1].trim() : "";
        }

        const isTunRouted = routeInterface.startsWith("utun");

        let edgeExitIpMasked: string | undefined;
        let edgeCountry: string | undefined;
        let probeMode: "local-zero-packet" | "edge-trace" = "local-zero-packet";

        if (options.deepProbe && !target.officialAnthropic && target.host === "challenges.cloudflare.com") {
          const traceRes = await runCurlProbe(
            ["-4", "--noproxy", "*", `https://${target.host}/cdn-cgi/trace`],
            2.5
          );
          if (traceRes.ok) {
            const parsed = parseCdnCgiTrace(traceRes.body);
            if (parsed.ip) {
              probeMode = "edge-trace";
              edgeExitIpMasked = maskIp(parsed.ip);
              edgeCountry = parsed.loc;
            }
          }
        }

        const staticRuleDecision: "proxy" | "direct" | "reject" | "unknown" = proxyAudit.configInspected
          ? proxyAudit.mode === "direct" || proxyAudit.finalMatchIsDirect
            ? "direct"
            : proxyAudit.hasStealthDomainDirectRule &&
                /(anthropic|claude|sentry|datadog|statsig|featuregates|siftscience|stripe|intercom)/i.test(
                  target.host
                )
              ? "direct"
              : "proxy"
          : "unknown";

        let status: "pass" | "warn" | "critical" = "pass";
        let statusReason = {
          zh: `经 ${routeInterface || "TUN"} 接管${fakeIp ? " (Fake-IP 命中)" : ""}，与海外主出口同源`,
          en: `Routed via ${routeInterface || "TUN"}${fakeIp ? " (Fake-IP hijacked)" : ""}, aligned with primary exit`,
        };

        if (!firstIpv4) {
          status = "warn";
          statusReason = {
            zh: "本地 DNS 解析超时或被阻断",
            en: "Local DNS lookup failed or blocked",
          };
        } else if (!isTunRouted) {
          status = "critical";
          statusReason = {
            zh: `未走虚拟网卡！当前走物理接口 ${routeInterface || "en0"} 直连裸奔`,
            en: `Bypassing TUN! Exiting directly via physical interface ${routeInterface || "en0"}`,
          };
        } else if (staticRuleDecision === "direct") {
          status = "critical";
          statusReason = {
            zh: "虽进入 TUN 网卡，但代理分流规则将其指向了 DIRECT 本地直连",
            en: "Enters TUN, but proxy rule routes this domain to DIRECT",
          };
        } else if (primaryExit?.isRestrictedRegion) {
          status = "critical";
          statusReason = {
            zh: `当前出口位于受限地区 (${primaryExit.countryCode})`,
            en: `Current exit is in restricted region (${primaryExit.countryCode})`,
          };
        } else if (!fakeIp && !isRawIp) {
          status = "warn";
          statusReason = {
            zh: `走 ${routeInterface} 路由，但未启用 Fake-IP（实 IP 解析需防范本地 DNS 抢答泄漏）`,
            en: `Routed via ${routeInterface}, but resolved to real IP instead of Fake-IP`,
          };
        }

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
          routeInterface: routeInterface || "unknown",
          isTunRouted,
          staticRuleDecision,
          edgeExitIpMasked: edgeExitIpMasked || primaryExit?.ipMasked,
          edgeCountry: edgeCountry || primaryExit?.countryCode,
          probeMode,
          status,
          statusReason,
        };
      })
    );

    return results;
  }

  async auditProxyConfigSafely(options: AuditOptions): Promise<ProxyStaticAudit> {
    const psOut = await runCmd("/bin/ps", ["-axo", "comm="], 2000);
    const procs = psOut.split(/\r?\n/).map((p) => basename(p.trim()));
    const detectedClients: string[] = [];

    const clientMatchers: [RegExp, string][] = [
      [/^verge-mihomo$|^clash-verge$/i, "Clash Verge Rev (Mihomo)"],
      [/^mihomo$|^clash\.meta$/i, "Mihomo Core"],
      [/^ClashX(\s*Pro)?$/i, "ClashX"],
      [/^Surge/i, "Surge"],
      [/^Stash/i, "Stash"],
      [/^sing-box$/i, "sing-box"],
      [/^Shadowrocket$/i, "Shadowrocket"],
      [/^V2rayU$/i, "V2rayU"],
    ];
    for (const [re, label] of clientMatchers) {
      if (procs.some((p) => re.test(p)) && !detectedClients.includes(label)) {
        detectedClients.push(label);
      }
    }

    const emptyAudit: ProxyStaticAudit = {
      detectedClients,
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

    if (options.skipProxyFileRead) {
      return emptyAudit;
    }

    const home = homedir();
    const candidateRuntimeConfigs = [
      join(home, "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"),
      join(home, ".config/mihomo/config.yaml"),
      join(home, ".config/clash/config.yaml"),
    ];

    for (const cfgPath of candidateRuntimeConfigs) {
      try {
        if (existsSync(cfgPath) && statSync(cfgPath).size < 10 * 1024 * 1024) {
          const raw = readFileSync(cfgPath, "utf8");
          return parseClashYamlMetadataSafely(raw, detectedClients);
        }
      } catch {
        // ignore
      }
    }

    return emptyAudit;
  }

  async scanBinariesAndFirewall(): Promise<{
    binaries: ClaudeBinaryItem[];
    firewall: FirewallAudit;
  }> {
    const home = homedir();

    // 1. 只读解析 LuLu 状态与 NSKeyedArchiver XML1 rules.plist（0644 普通权限即可读取，无需 sudo）
    const luluInstalled = existsSync("/Applications/LuLu.app");
    const psOut = await runCmd("/bin/ps", ["-axo", "comm="], 2000);
    const luluDaemonRunning = /LuLu/i.test(psOut);
    let luluDisabled = false;
    let luluPassiveMode: boolean | undefined;

    if (existsSync("/Library/Objective-See/LuLu/preferences.plist")) {
      const prefXml = await runCmd(
        "/usr/bin/plutil",
        ["-convert", "xml1", "-o", "-", "/Library/Objective-See/LuLu/preferences.plist"],
        2000
      );
      if (prefXml) {
        const prefsObj = parseAppleXmlPlist(prefXml);
        if (prefsObj && typeof prefsObj === "object" && !Array.isArray(prefsObj)) {
          const prefs = prefsObj as Record<string, unknown>;
          if (prefs.disabled === true || prefs.disabled === 1) luluDisabled = true;
          if (typeof prefs.passiveMode === "boolean") luluPassiveMode = prefs.passiveMode;
          else if (typeof prefs.passiveMode === "number") luluPassiveMode = prefs.passiveMode === 1;
        }
      }
    }

    const luluActive = luluInstalled && luluDaemonRunning && !luluDisabled;
    let luluSummary = parseLuluRules("");

    if (existsSync("/Library/Objective-See/LuLu/rules.plist")) {
      const rulesXml = await runCmd(
        "/usr/bin/plutil",
        ["-convert", "xml1", "-o", "-", "/Library/Objective-See/LuLu/rules.plist"],
        3000
      );
      if (rulesXml) {
        luluSummary = parseLuluRules(rulesXml);
      }
    }

    const littleSnitchDetected =
      existsSync("/Library/Application Support/Objective Development/Little Snitch") ||
      /at\.obdev\.littlesnitch/i.test(psOut);

    // 2. 扫描本机全部 Claude 入口
    const binaries: ClaudeBinaryItem[] = [];

    const claudeAppPath = "/Applications/Claude.app";
    if (existsSync(claudeAppPath)) {
      const mainCovered = luluActive && luluSummary.coversClaudeAppMain;
      binaries.push({
        id: "desktop-main",
        name: "Claude Desktop 主进程",
        displayPath: "/Applications/Claude.app",
        kind: "desktop-main",
        exists: true,
        signedByAnthropic: true,
        bundleOrSigningId: "com.anthropic.claudefordesktop",
        firewallCovered: mainCovered,
        riskLevel: mainCovered ? "pass" : "warn",
        note: mainCovered
          ? { zh: "已由 LuLu 规则锁定默认阻断保护", en: "Locked by active LuLu default-block rule" }
          : {
              zh: "未检测到生效的默认阻断规则，代理闪退时可能直连上报",
              en: "Not locked by active default-block firewall rule; may connect directly if proxy drops",
            },
      });

      const subTargets: {
        rel: string;
        id: string;
        name: string;
        kind: ClaudeBinaryItem["kind"];
      }[] = [
        {
          rel: "Contents/Frameworks/Claude Helper.app",
          id: "desktop-helper",
          name: "Claude Chromium 网络辅助进程 (4x Helpers)",
          kind: "desktop-helper",
        },
        {
          rel: "Contents/Frameworks/Squirrel.framework/Versions/A/Resources/ShipIt",
          id: "desktop-shipit",
          name: "ShipIt 后台静默更新器",
          kind: "desktop-updater",
        },
        {
          rel: "Contents/Resources/coworkd",
          id: "desktop-coworkd",
          name: "Cowork VM 本地虚拟机守护进程",
          kind: "desktop-cowork-vm",
        },
      ];

      for (const sub of subTargets) {
        const abs = join(claudeAppPath, sub.rel);
        if (existsSync(abs)) {
          const covered = luluActive && luluSummary.coversClaudeHelpers;
          binaries.push({
            id: sub.id,
            name: sub.name,
            displayPath: abs,
            kind: sub.kind,
            exists: true,
            signedByAnthropic: true,
            firewallCovered: covered,
            riskLevel: covered ? "pass" : "warn",
            note: covered
              ? {
                  zh: "子进程已纳入 `/Applications/Claude.app/*` 或子程序封锁范围",
                  en: "Covered by `/Applications/Claude.app/*` wildcard or helper firewall rule",
                }
              : {
                  zh: "Electron 实际发包的独立子进程，单独只拦主程序会漏掉它",
                  en: "Separate child binary making real network calls; must be covered",
                },
          });
        }
      }
    }

    const appSupportCCDir = join(home, "Library/Application Support/Claude/claude-code");
    if (existsSync(appSupportCCDir)) {
      let latestVer = "";
      try {
        const vers = readdirSync(appSupportCCDir).filter((d) => !d.startsWith("."));
        latestVer = vers.sort().reverse()[0] || "";
      } catch {
        // ignore
      }
      const covered =
        luluActive &&
        (luluSummary.coversAppSupportClaudeCode || luluSummary.coversAnthropicSigningId);
      binaries.push({
        id: "desktop-bundled-cli",
        name: `桌面端后台内置 claude-code${latestVer ? ` (${latestVer})` : ""}`,
        displayPath: sanitizePath(latestVer ? join(appSupportCCDir, latestVer) : appSupportCCDir),
        kind: "desktop-bundled-cli",
        exists: true,
        signedByAnthropic: true,
        bundleOrSigningId: "com.anthropic.claude-code",
        firewallCovered: covered,
        riskLevel: covered ? "pass" : "warn",
        note: covered
          ? { zh: "后台内置 CLI 目录或签名已受防火墙默认阻断保护", en: "Bundled CLI path or signature locked by firewall" }
          : {
              zh: "桌面端自动下载的独立 CLI，升级换版本号会变目录，需用通配路径或签名拦截",
              en: "Auto-downloaded by Desktop; versioned path changes on update",
            },
      });
    }

    const globalCandidates = new Set<string>();
    const whichOut = await runCmd("/usr/bin/which", ["-a", "claude"], 1500);
    for (const line of whichOut.split(/\r?\n/)) {
      if (line.trim()) globalCandidates.add(line.trim());
    }
    for (const extra of [
      join(home, ".local/bin/claude"),
      "/opt/homebrew/bin/claude",
      "/usr/local/bin/claude",
      join(home, ".bun/bin/claude"),
      join(home, "Library/pnpm/claude"),
      join(home, ".volta/bin/claude"),
      join(home, ".asdf/shims/claude"),
      join(home, ".local/share/mise/shims/claude"),
    ]) {
      if (existsSync(extra)) globalCandidates.add(extra);
    }

    const seenResolvedCliTargets = new Set<string>();
    for (const cliPath of globalCandidates) {
      if (!existsSync(cliPath)) continue;
      const binType = inspectCliBinaryKind(cliPath);
      const dedupeKey = `${binType.classification}:${binType.resolvedBinaryPath || cliPath}`;
      if (seenResolvedCliTargets.has(dedupeKey)) continue;
      seenResolvedCliTargets.add(dedupeKey);

      if (binType.classification === "node-script") {
        // 分支 A：确认为驻留 node / bun / deno 解释器的 JS 脚本
        binaries.push({
          id: `global-npm-${cliPath}`,
          name: "全局终端 claude (Node.js 脚本运行时)",
          displayPath: sanitizePath(cliPath),
          kind: "global-cli-npm-node",
          exists: true,
          signedByAnthropic: false,
          firewallCovered: false,
          riskLevel: "critical",
          note: {
            zh: "底层实际驻留进程为 node（常见于旧版 JS 包或未拉取原生二进制的 fallback 包装器），应用防火墙无法按签名单独隔离，建议升级至包含原生 Mach-O 二进制的新版或使用官方独立安装器。",
            en: "Runs inside the 'node' runtime (legacy JS build or fallback wrapper), preventing per-app firewall isolation without blocking all Node dev tools.",
          },
        });
      } else if (binType.classification === "uninstalled-stub") {
        // 分支 C1：pnpm v10 默认拦截 postinstall 或 --ignore-scripts 留下的报错占位桩文件
        binaries.push({
          id: `global-stub-${cliPath}`,
          name: "全局终端 claude (未完成 postinstall 占位脚本)",
          displayPath: sanitizePath(cliPath),
          kind: "global-cli-stub",
          exists: true,
          signedByAnthropic: false,
          firewallCovered: false,
          riskLevel: "warn",
          note: {
            zh: "检测到 `claude native binary not installed` 报错桩文件（常见于 pnpm v10 拦截 postinstall 或使用了 --ignore-scripts / --omit=optional），当前无法运行，需执行 postinstall 拉取原生二进制。",
            en: "Placeholder stub ('claude native binary not installed'); postinstall was skipped (e.g. pnpm v10 build policy or --ignore-scripts).",
          },
        });
      } else if (binType.classification === "native-macho") {
        // 读取 codesign -dv 合并输出 (stderr) 严格验证是否确实携带 Anthropic 官方签名（排除 volta-shim 等第三方二进制垫片！）
        const signCheckTarget = binType.resolvedBinaryPath || cliPath;
        const codesignOut = await runCmdCombined("/usr/bin/codesign", ["-dv", signCheckTarget], 1500);
        const signVerify = verifyAnthropicCodesignOutput(codesignOut);

        if (signVerify.signedByAnthropic) {
          // 分支 B：确认为带 Anthropic 官方签名的原生 Mach-O 二进制
          const viaPkgManager = /node_modules|pnpm/i.test(signCheckTarget) || binType.viaShellExecWrapper;
          const covered = luluActive && luluSummary.coversAnthropicSigningId;
          binaries.push({
            id: `global-native-${cliPath}`,
            name: viaPkgManager
              ? "全局终端 claude (npm/pnpm 分发原生二进制)"
              : "全局终端 claude (官方原生二进制)",
            displayPath: sanitizePath(cliPath),
            kind: "global-cli-native",
            exists: true,
            signedByAnthropic: true,
            teamId: signVerify.teamId,
            bundleOrSigningId: signVerify.identifier || "com.anthropic.claude-code",
            firewallCovered: covered,
            riskLevel: covered ? "pass" : "warn",
            note: covered
              ? {
                  zh: "已通过 codesign 确认为 Anthropic 官方签名 Mach-O 二进制，且已受防火墙签名规则锁定",
                  en: "Verified Anthropic-signed Mach-O binary covered by firewall signing rule",
                }
              : {
                  zh: "已通过 codesign 确认为 Anthropic 官方签名 Mach-O 二进制（无 node 驻留），可在防火墙中按签名 com.anthropic.claude-code 单独锁定",
                  en: "Verified Anthropic-signed Mach-O binary (no Node runtime); lock via signing ID com.anthropic.claude-code in firewall",
                },
          });
        } else {
          // 分支 C2：虽然是 Mach-O 二进制，但并非 Anthropic 签名（典型如 ~/.volta/bin/claude 指向的 volta-shim）
          binaries.push({
            id: `global-shim-macho-${cliPath}`,
            name: "全局终端 claude (版本管理器二进制垫片 / 非官方签名)",
            displayPath: sanitizePath(cliPath),
            kind: "global-cli-unverified-shim",
            exists: true,
            signedByAnthropic: false,
            bundleOrSigningId: signVerify.identifier,
            firewallCovered: false,
            riskLevel: "warn",
            note: {
              zh: `该入口为非 Anthropic 签名的二进制垫片（如 Volta shim${signVerify.identifier ? `: ${signVerify.identifier}` : ""}），无法静态确认其转发的目标程序是原生签名版还是旧版 node 脚本，请核实底层实际工具链路径与签名。`,
              en: "Non-Anthropic binary shim (e.g. Volta shim); cannot statically confirm whether the delegated binary is native-signed or Node-based.",
            },
          });
        }
      } else {
        // 分支 C3：asdf / mise 等动态 Shell 垫片或无法静态追踪 exec 落点的包装脚本
        binaries.push({
          id: `global-shim-script-${cliPath}`,
          name: "全局终端 claude (动态环境垫片脚本 / 待核验)",
          displayPath: sanitizePath(cliPath),
          kind: "global-cli-unverified-shim",
          exists: true,
          signedByAnthropic: false,
          firewallCovered: false,
          riskLevel: "warn",
          note: {
            zh: "该入口为动态版本管理器垫片（如 asdf / mise shim）或自定义脚本，无法静态解析最终二进制签名，请执行 `claude --version` 并核实实际落地文件是否携带 com.anthropic.claude-code 签名。",
            en: "Dynamic version-manager shim (e.g. asdf / mise); cannot statically resolve underlying binary code signature.",
          },
        });
      }
    }

    const ideExtDirs = [
      { label: "VS Code", dir: join(home, ".vscode/extensions") },
      { label: "Cursor", dir: join(home, ".cursor/extensions") },
      { label: "Windsurf", dir: join(home, ".windsurf/extensions") },
    ];
    for (const ide of ideExtDirs) {
      try {
        if (!existsSync(ide.dir)) continue;
        const matches = readdirSync(ide.dir).filter((d) =>
          d.toLowerCase().startsWith("anthropic.claude-code-")
        );
        if (matches.length > 0) {
          const latest = matches.sort().reverse()[0];
          const covered = luluActive && luluSummary.coversAnthropicSigningId;
          binaries.push({
            id: `ide-ext-${ide.label}`,
            name: `${ide.label} 插件内置 Claude Code`,
            displayPath: sanitizePath(join(ide.dir, latest)),
            kind: "ide-extension-cli",
            exists: true,
            signedByAnthropic: true,
            bundleOrSigningId: "com.anthropic.claude-code",
            firewallCovered: covered,
            riskLevel: covered ? "pass" : "warn",
            note: covered
              ? { zh: "按官方代码签名规则已自动覆盖 IDE 插件二进制", en: "Covered via Anthropic signing ID rule" }
              : {
                  zh: "极易遗漏！只按 `/Applications/Claude.app/*` 路径建防火墙规则会漏掉 IDE 插件内置进程",
                  en: "Path-only rules for `/Applications/Claude.app/*` miss IDE extension binaries!",
                },
          });
        }
      } catch {
        // ignore
      }
    }

    // 3. 增强排查 macOS PF `user != root` 内核死锁脚本（解析 LaunchDaemon ProgramArguments 外部脚本并区分运行/停用残留）
    const { activeFiles: pfDeadlockFiles, residualFiles: pfDeadlockResidualFiles } =
      await scanMacosPfDeadlockScripts();

    // 4. 检查开机自启抢跑隐患
    let hasClaudeLaunchAgent = false;
    const launchAgentsDir = join(home, "Library/LaunchAgents");
    try {
      if (existsSync(launchAgentsDir)) {
        hasClaudeLaunchAgent = readdirSync(launchAgentsDir).some((f) => /anthropic|claude/i.test(f));
      }
    } catch {
      // ignore
    }

    const claudeAppFullyLocked =
      luluActive && luluSummary.coversClaudeAppMain && luluSummary.coversClaudeHelpers;

    const installedCliBins = binaries.filter(
      (b) =>
        b.kind === "desktop-bundled-cli" ||
        b.kind === "global-cli-native" ||
        b.kind === "global-cli-npm-node" ||
        b.kind === "global-cli-unverified-shim" ||
        b.kind === "ide-extension-cli"
    );
    const claudeCliLocked =
      installedCliBins.length > 0
        ? installedCliBins.every((b) => b.firewallCovered) &&
          !installedCliBins.some(
            (b) => b.kind === "global-cli-npm-node" || b.kind === "global-cli-unverified-shim"
          )
        : claudeAppFullyLocked;

    return {
      binaries,
      firewall: {
        luluInstalled,
        luluActive,
        luluPassiveMode,
        luluCoveredRuleCount: luluSummary.totalRuleEntries,
        luluCidrMisconfiguredRules: luluSummary.cidrMisconfiguredRules,
        claudeAppFullyLocked,
        claudeCliLocked,
        littleSnitchDetected,
        pfDeadlockRiskDetected: pfDeadlockFiles.length > 0,
        pfDeadlockFiles,
        pfDeadlockResidualFiles,
        bootRaceRisk: hasClaudeLaunchAgent && !claudeAppFullyLocked,
      },
    };
  }

  async inspectEnvironmentHygiene(
    netSnap: NetworkStackSnapshot,
    proxyAudit?: ProxyStaticAudit
  ): Promise<EnvironmentHygieneSnapshot> {
    const home = homedir();
    let systemTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    try {
      const link = readlinkSync("/etc/localtime");
      const idx = link.indexOf("zoneinfo/");
      if (idx >= 0) {
        systemTimezone = link.slice(idx + "zoneinfo/".length);
      }
    } catch {
      // fallback to Intl
    }

    const isMainlandTimezone = /^(Asia\/Shanghai|Asia\/Chongqing|Asia\/Urumqi|Asia\/Harbin|PRC)$/i.test(
      systemTimezone
    );

    const [localeOut, launchctlBaseUrl, psOut, netstatOut, defaultBrowser] = await Promise.all([
      runCmd("/usr/bin/defaults", ["read", "-g", "AppleLocale"], 1200),
      runCmd("/bin/launchctl", ["getenv", "ANTHROPIC_BASE_URL"], 1000),
      runCmd("/bin/ps", ["-axo", "command="], 2000),
      runCmd("/usr/sbin/netstat", ["-an", "-p", "tcp"], 1800),
      detectDefaultBrowserMac(home),
    ]);

    const systemLocale = (
      process.env.LC_ALL ||
      process.env.LANG ||
      localeOut.trim() ||
      Intl.DateTimeFormat().resolvedOptions().locale
    ).trim();

    // 提取本机当前所有活跃 LISTEN 的回环/通配 TCP 端口（无需 sudo，即使 root 服务监听也能识别）
    const activeListeningLoopbackPorts = extractListeningLoopbackPortsMac(netstatOut);

    // 读取 ~/.claude/settings.json 原始文本供零凭证结构检查器解析
    let settingsJsonRaw: string | undefined;
    const settingsPath = join(home, ".claude/settings.json");
    try {
      if (existsSync(settingsPath) && statSync(settingsPath).size < 1024 * 1024) {
        settingsJsonRaw = readFileSync(settingsPath, "utf8");
      }
    } catch {
      // ignore
    }

    const settingsInspection = inspectClaudeSettingsAndProxyEnv({
      settingsJsonRaw,
      processEnv: process.env,
      launchctlBaseUrl: launchctlBaseUrl.trim(),
      systemProxyPort: netSnap.systemProxy.proxyPort,
      proxyConfigListenerPorts: proxyAudit?.localListenerPorts ?? [],
      activeListeningLoopbackPorts,
    });

    // 扫描高危本地反代切号进程
    const riskyReverseProxies: string[] = [];
    for (const [re, name] of [
      [/cliproxyapi/i, "CLIProxyAPI"],
      [/sub2api/i, "Sub2API"],
      [/claude-proxy|one-api|new-api/i, "Local API Relay"],
    ] as [RegExp, string][]) {
      if (re.test(psOut) && !riskyReverseProxies.includes(name)) {
        riskyReverseProxies.push(name);
      }
    }

    // 只读统计 MCP Server 数量与启动器名称（绝不读取 args/env 内容！）
    let mcpServerCount = 0;
    const mcpCommandsSet = new Set<string>();
    for (const mcpCfgPath of [
      join(home, "Library/Application Support/Claude/claude_desktop_config.json"),
      join(home, ".claude.json"),
    ]) {
      try {
        if (existsSync(mcpCfgPath) && statSync(mcpCfgPath).size < 5 * 1024 * 1024) {
          const parsed = JSON.parse(readFileSync(mcpCfgPath, "utf8")) as Record<string, unknown>;
          const servers = parsed.mcpServers;
          if (servers && typeof servers === "object") {
            for (const entry of Object.values(servers as Record<string, unknown>)) {
              mcpServerCount += 1;
              if (entry && typeof entry === "object") {
                const cmd = (entry as Record<string, unknown>).command;
                if (typeof cmd === "string" && cmd.trim()) {
                  mcpCommandsSet.add(basename(cmd.trim()));
                }
              }
            }
          }
        }
      } catch {
        // ignore
      }
    }

    return {
      systemTimezone: systemTimezone || "UTC",
      isMainlandTimezone,
      systemLocale,
      defaultBrowser,
      hasAnthropicBaseUrl: settingsInspection.hasAnthropicBaseUrl,
      anthropicBaseUrlIsCustomThirdParty: settingsInspection.anthropicBaseUrlIsCustomThirdParty,
      settingsHasCustomBaseUrl: settingsInspection.settingsHasCustomBaseUrl,
      proxyEnvVarsPresent: settingsInspection.proxyEnvVarsPresent,
      proxyEnvConflictsWithSystem: settingsInspection.proxyEnvConflictsWithSystem,
      dedicatedLoopbackProxyPorts: settingsInspection.dedicatedLoopbackProxyPorts,
      deadLoopbackProxyPorts: settingsInspection.deadLoopbackProxyPorts,
      riskyReverseProxies,
      mcpServerCount,
      mcpCommands: [...mcpCommandsSet],
      suspiciousSettingsEnvKeys: settingsInspection.suspiciousSettingsEnvKeys,
    };
  }

  async runKillSwitchProbe(): Promise<KillSwitchProbeSnapshot> {
    const netSnap = await this.getNetworkSnapshot();
    const tunActive =
      netSnap.activeUtunInterfaces.length > 0 &&
      netSnap.defaultRouteInterface.startsWith("utun");

    const probe = await runCurlProbe(
      ["-4", "--noproxy", "*", "https://1.1.1.1/cdn-cgi/trace"],
      2.5
    );

    if (!probe.ok || !probe.body.includes("ip=")) {
      return {
        tunActive,
        blocked: true,
        latencyMs: probe.latencyMs,
      };
    }

    const parsed = parseCdnCgiTrace(probe.body);
    return {
      tunActive,
      blocked: false,
      latencyMs: probe.latencyMs,
      leakedIpMasked: parsed.ip ? maskIp(parsed.ip) : undefined,
      leakedCountry: parsed.loc?.toUpperCase(),
    };
  }
}

async function scanMacosPfDeadlockScripts(): Promise<{
  activeFiles: string[];
  residualFiles: string[];
}> {
  const activeSet = new Set<string>();
  const residualSet = new Set<string>();

  const checkSmallFileForPfDeadlock = (fpath: string): boolean => {
    try {
      if (existsSync(fpath) && statSync(fpath).isFile() && statSync(fpath).size < 256 * 1024) {
        const txt = readFileSync(fpath, "utf8");
        return hasMacosPfDeadlockPattern(txt);
      }
    } catch {
      // ignore
    }
    return false;
  };

  // 1. 直接检查系统主 PF 配置与锚点文件
  const directPfFiles = ["/etc/pf.conf"];
  try {
    if (existsSync("/etc/pf.anchors")) {
      for (const f of readdirSync("/etc/pf.anchors")) {
        directPfFiles.push(join("/etc/pf.anchors", f));
      }
    }
  } catch {
    // ignore
  }
  for (const pfFile of directPfFiles) {
    if (checkSmallFileForPfDeadlock(pfFile)) {
      activeSet.add(sanitizePath(pfFile));
    }
  }

  // 2. 扫描 /Library/LaunchDaemons/*.plist，解析其 ProgramArguments 指向的外部脚本及同目录规则文件，并检查服务运行态
  const daemonsDir = "/Library/LaunchDaemons";
  try {
    if (existsSync(daemonsDir)) {
      for (const fname of readdirSync(daemonsDir)) {
        if (!fname.endsWith(".plist")) continue;
        if (!/(clash|guard|kill|pf|proxy|leak|firewall|tun)/i.test(fname)) continue;

        const plistPath = join(daemonsDir, fname);
        if (!statSync(plistPath).isFile() || statSync(plistPath).size > 256 * 1024) continue;

        const plistXml = await runCmd(
          "/usr/bin/plutil",
          ["-convert", "xml1", "-o", "-", plistPath],
          1500
        );
        const { label, scriptPaths } = extractLaunchDaemonLabelAndScripts(plistXml);
        const daemonLabel = label || fname.replace(/\.plist$/i, "");

        const candidateFilesToScan = new Set<string>([plistPath, ...scriptPaths]);
        // 顺带扫描外部专用脚本目录（如 /Library/Application Support/clash-guard/）下的附属 .sh / .conf / .pf 文件
        for (const sp of scriptPaths) {
          const parentDir = dirname(sp);
          if (
            parentDir !== "/Library" &&
            parentDir !== "/usr/local/bin" &&
            parentDir !== "/opt/homebrew/bin" &&
            existsSync(parentDir)
          ) {
            try {
              for (const sib of readdirSync(parentDir)) {
                if (/\.(sh|conf|pf|rules)$/i.test(sib)) {
                  candidateFilesToScan.add(join(parentDir, sib));
                }
              }
            } catch {
              // ignore
            }
          }
        }

        const matchedHits: string[] = [];
        for (const targetFile of candidateFilesToScan) {
          if (checkSmallFileForPfDeadlock(targetFile)) {
            matchedHits.push(sanitizePath(targetFile));
          }
        }

        if (matchedHits.length > 0) {
          const launchctlOut = await runCmd(
            "/bin/launchctl",
            ["print", `system/${daemonLabel}`],
            1500
          );
          const running = isLaunchDaemonActive(launchctlOut);
          for (const hit of matchedHits) {
            if (running) {
              activeSet.add(`${hit} (${daemonLabel}: running)`);
            } else {
              residualSet.add(`${hit} (${daemonLabel}: not running)`);
            }
          }
        }
      }
    }
  } catch {
    // ignore
  }

  return {
    activeFiles: [...activeSet],
    residualFiles: [...residualSet],
  };
}

export function extractListeningLoopbackPortsMac(netstatOut: string): number[] {
  const ports = new Set<number>();
  for (const line of netstatOut.split(/\r?\n/)) {
    if (!/\bLISTEN\b/.test(line)) continue;
    // 匹配 macOS netstat 格式: 127.0.0.1.7897 / ::1.7897 / *.7897
    const m = /(?:^|\s)(?:127\.0\.0\.1|::1|\*)\.(\d{1,5})\s/.exec(line);
    if (m) {
      const p = Number(m[1]);
      if (p > 0 && p <= 65535) ports.add(p);
    }
  }
  return [...ports];
}

function extractPortFromProxyEnv(proxyUrl?: string): number | undefined {
  if (!proxyUrl) return undefined;
  try {
    const normalized = proxyUrl.includes("://") ? proxyUrl : `http://${proxyUrl}`;
    const u = new URL(normalized);
    return u.port ? Number(u.port) : undefined;
  } catch {
    return undefined;
  }
}

export type CliBinaryClassification =
  | "node-script"
  | "native-macho"
  | "uninstalled-stub"
  | "unknown-shim";

export interface CliBinaryInspection {
  classification: CliBinaryClassification;
  isNodeScript: boolean;
  isMachO: boolean;
  viaShellExecWrapper: boolean;
  resolvedBinaryPath: string;
}

function hasMachOMagic(filePath: string): boolean {
  try {
    const fd = openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    const bytesRead = readSync(fd, buf, 0, 4, 0);
    closeSync(fd);
    if (bytesRead < 4) return false;
    const magic = buf.readUInt32BE(0);
    return (
      magic === 0xcffaedfe ||
      magic === 0xfeedfacf ||
      magic === 0xcafebabe ||
      magic === 0xbebafeca
    );
  } catch {
    return false;
  }
}

/**
 * 追踪软链接与包管理器（pnpm / yarn / fnm / volta / asdf / mise）生成的启动入口，
 * 严谨区分四类落点：
 * - `native-macho`：最终指向原生 Mach-O 二进制（后续再交由 `codesign -dv` stderr 校验是否为 Anthropic 签名）
 * - `node-script`：最终驻留 `node` / `bun` / `deno` 解释器运行 JS 脚本
 * - `uninstalled-stub`：`@anthropic-ai/claude-code` 因跳过 `postinstall` 留下的报错占位桩文件
 * - `unknown-shim`：`asdf` / `mise` 等动态环境垫片或无法静态确认落点的自定义脚本
 */
export function inspectCliBinaryKind(filePath: string, depth = 0): CliBinaryInspection {
  if (depth > 4) {
    return {
      classification: "unknown-shim",
      isNodeScript: false,
      isMachO: false,
      viaShellExecWrapper: depth > 0,
      resolvedBinaryPath: filePath,
    };
  }

  let realTarget = filePath;
  try {
    realTarget = realpathSync(filePath);
  } catch {
    try {
      const linked = readlinkSync(filePath);
      realTarget = linked.startsWith("/") ? linked : resolve(dirname(filePath), linked);
    } catch {
      // 普通文件非软链
    }
  }

  try {
    // 1. 先直接读取文件头判断是否为原生 Mach-O 可执行文件（含官方二进制或 volta-shim 等二进制垫片，由上层结合 codesign 区分）
    if (hasMachOMagic(realTarget)) {
      return {
        classification: "native-macho",
        isNodeScript: false,
        isMachO: true,
        viaShellExecWrapper: depth > 0,
        resolvedBinaryPath: realTarget,
      };
    }

    // 2. 非二进制文件：读取前 4KB 检查报错桩文件、Shebang 与 Shell exec 链路
    const fd = openSync(realTarget, "r");
    const buf = Buffer.alloc(4096);
    const bytesRead = readSync(fd, buf, 0, 4096, 0);
    closeSync(fd);

    const text = buf.subarray(0, bytesRead).toString("utf8");
    const firstLine = (text.split(/\r?\n/, 1)[0] || "").trim();

    // 2a. `@anthropic-ai/claude-code` 跳过 postinstall（如 pnpm v10 默认拦截或 --ignore-scripts）时残留的无 #! 9 行报错桩脚本
    if (/claude native binary not installed/i.test(text)) {
      return {
        classification: "uninstalled-stub",
        isNodeScript: false,
        isMachO: false,
        viaShellExecWrapper: depth > 0,
        resolvedBinaryPath: realTarget,
      };
    }

    // 2b. 直接由 node / bun / deno 解释执行的 JS 脚本（如旧版 cli.js 或 cli-wrapper.cjs）
    if (
      (firstLine.startsWith("#!") && /\b(node|bun|deno)\b/i.test(firstLine)) ||
      /\.(c?js|mjs)$/i.test(realTarget)
    ) {
      return {
        classification: "node-script",
        isNodeScript: true,
        isMachO: false,
        viaShellExecWrapper: depth > 0,
        resolvedBinaryPath: realTarget,
      };
    }

    // 2c. POSIX Shell 包装脚本（如 pnpm cmd-shim 或 asdf / mise 动态垫片）
    if (firstLine.startsWith("#!") && /\b(sh|bash|zsh|dash)\b/i.test(firstLine)) {
      const baseDir = dirname(realTarget);
      const lines = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"));

      for (const line of lines) {
        if (!line.startsWith("exec ")) continue;

        // 若 exec 调用的是 node / bun / deno 解释器，则运行时确实驻留 node 进程
        if (
          /^exec\s+(?:["']?[^"'\s]*\/)?(?:node|bun|deno)(?:\.exe)?["']?\s/i.test(line) ||
          /\.(c?js|mjs)["']?(?:\s|$)/i.test(line)
        ) {
          return {
            classification: "node-script",
            isNodeScript: true,
            isMachO: false,
            viaShellExecWrapper: true,
            resolvedBinaryPath: realTarget,
          };
        }

        // 若 exec 转发给 asdf / mise / rtx / volta / nodenv 等版本管理器分发器，无法静态确认最终二进制签名
        if (/^exec\s+(?:["']?[^"'\s]*\/)?(?:asdf|mise|rtx|volta|volta-shim|nodenv|anyenv)["']?(?:\s|$)/i.test(line)) {
          return {
            classification: "unknown-shim",
            isNodeScript: false,
            isMachO: false,
            viaShellExecWrapper: true,
            resolvedBinaryPath: realTarget,
          };
        }

        // 提取 exec 指向的具体目标文件路径（替换 $basedir / ${basedir}）
        const quotedTarget = /^exec\s+"([^"]+)"/.exec(line) || /^exec\s+'([^']+)'/.exec(line);
        const bareTarget = !quotedTarget ? /^exec\s+(\S+)/.exec(line) : null;
        const rawExecExpr = quotedTarget?.[1] || bareTarget?.[1];
        if (rawExecExpr) {
          const expanded = rawExecExpr
            .replace(/\$\{?basedir\}?/g, baseDir)
            .replace(/\$\(dirname\s+[^)]+\)/g, baseDir);
          const candidatePath = expanded.startsWith("/") ? expanded : resolve(baseDir, expanded);
          if (existsSync(candidatePath) && candidatePath !== realTarget) {
            const inner = inspectCliBinaryKind(candidatePath, depth + 1);
            return { ...inner, viaShellExecWrapper: true };
          }
        }
      }
    }
  } catch {
    // ignore
  }

  return {
    classification: "unknown-shim",
    isNodeScript: false,
    isMachO: false,
    viaShellExecWrapper: depth > 0,
    resolvedBinaryPath: realTarget,
  };
}

async function detectDefaultBrowserMac(home: string): Promise<string> {
  const lsPlist = join(
    home,
    "Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist"
  );
  if (!existsSync(lsPlist)) return "Safari (macOS Default)";

  const out = await runCmd("/usr/bin/plutil", ["-convert", "xml1", "-o", "-", lsPlist], 1800);
  if (!out) return "Safari (macOS Default)";

  try {
    const data = parseAppleXmlPlist(out) as { LSHandlers?: Record<string, unknown>[] } | null;
    const handlers = data && Array.isArray(data.LSHandlers) ? data.LSHandlers : [];
    for (const h of handlers) {
      if (h.LSHandlerURLScheme === "https" && typeof h.LSHandlerRoleAll === "string") {
        const bundleId = h.LSHandlerRoleAll.toLowerCase();
        if (bundleId.includes("brave")) return "Brave Browser";
        if (bundleId.includes("edgemac")) return "Microsoft Edge";
        if (bundleId.includes("chrome")) return "Google Chrome";
        if (bundleId.includes("thebrowser")) return "Arc Browser";
        if (bundleId.includes("firefox")) return "Mozilla Firefox";
        if (bundleId.includes("safari")) return "Apple Safari";
        if (bundleId.includes("vivaldi")) return "Vivaldi";
        if (bundleId.includes("adspower")) return "AdsPower Browser";
        return h.LSHandlerRoleAll;
      }
    }
  } catch {
    // ignore
  }
  return "Apple Safari";
}

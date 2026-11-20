import { REGION_NAMES } from "../core/domains.js";
import { hashIpForComparison, maskIp } from "../core/privacy.js";
import type {
  ClaudeBinaryItem,
  DomainProbeResult,
  DomainTarget,
  FirewallAudit,
  ProxyStaticAudit,
  PublicExitSnapshot,
} from "../types/report.js";
import type {
  AuditOptions,
  EnvironmentHygieneSnapshot,
  KillSwitchProbeSnapshot,
  NetworkStackSnapshot,
  PlatformAdapter,
} from "./types.js";

export type DemoScenario = "safe" | "leak";

/**
 * 100% 纯虚构脱敏演示适配器（仅使用 RFC 5737 文档测试保留 IP 段 198.51.100.x / 203.0.113.x）
 */
export class MockPlatformAdapter implements PlatformAdapter {
  readonly platform = "darwin" as const;

  constructor(private readonly scenario: DemoScenario) {}

  async getNetworkSnapshot(): Promise<NetworkStackSnapshot> {
    if (this.scenario === "safe") {
      return {
        activeUtunInterfaces: ["utun4"],
        defaultRouteInterface: "utun4",
        dnsServers: ["198.18.0.2"],
        dnsServersMasked: ["198.18.*.* (Fake-IP)"],
        tailscaleMagicDns: false,
        icloudPrivateRelaySuspected: false,
        competingVpns: [],
        systemProxy: {
          httpEnabled: false,
          httpsEnabled: false,
          socksEnabled: false,
        },
        publicIpv6Interfaces: [],
      };
    }

    return {
      activeUtunInterfaces: [],
      defaultRouteInterface: "en0",
      dnsServers: ["114.114.114.114", "100.100.100.100"],
      dnsServersMasked: ["114.114.*.*", "100.100.100.100"],
      tailscaleMagicDns: true,
      icloudPrivateRelaySuspected: false,
      competingVpns: ["Tailscale"],
      systemProxy: {
        httpEnabled: true,
        httpsEnabled: true,
        socksEnabled: false,
        proxyHost: "127.0.0.1",
        proxyPort: 7890,
      },
      publicIpv6Interfaces: [
        {
          iface: "en0",
          addressMasked: "240e:3b7:*:*::*",
          isMainlandCarrier: true,
        },
      ],
    };
  }

  async probePublicExits(
    _netSnap: NetworkStackSnapshot,
    options: AuditOptions
  ): Promise<{
    primaryExit?: PublicExitSnapshot;
    systemProxyExit?: PublicExitSnapshot;
    ipv6Exit?: PublicExitSnapshot;
    cliExitIpHash?: string;
  }> {
    if (this.scenario === "safe") {
      const mockUsIp = "198.51.100.42";
      return {
        cliExitIpHash: hashIpForComparison(mockUsIp, options.sessionSalt),
        primaryExit: {
          source: "cloudflare-1.1.1.1 (mock)",
          ipMasked: maskIp(mockUsIp),
          ipRawForLocalToggle: mockUsIp,
          countryCode: "US",
          countryName: REGION_NAMES.US,
          region: "California",
          city: "Los Angeles",
          asn: "AS7922",
          org: "Comcast Cable Communications",
          asnType: "isp",
          isSupportedRegion: true,
          isRestrictedRegion: false,
          viaMode: "direct-socket-noproxy",
          latencyMs: 142,
        },
      };
    }

    const mockCnIp = "203.0.113.88";
    const mockHkIp = "192.0.2.19";
    return {
      cliExitIpHash: hashIpForComparison(mockCnIp, options.sessionSalt),
      primaryExit: {
        source: "cloudflare-1.1.1.1 (mock)",
        ipMasked: maskIp(mockCnIp),
        ipRawForLocalToggle: mockCnIp,
        countryCode: "CN",
        countryName: REGION_NAMES.CN,
        region: "Guangdong",
        city: "Shenzhen",
        asn: "AS4134",
        org: "Chinanet",
        asnType: "isp",
        isSupportedRegion: false,
        isRestrictedRegion: true,
        viaMode: "direct-socket-noproxy",
        latencyMs: 38,
      },
      systemProxyExit: {
        source: "127.0.0.1:7890 (mock)",
        ipMasked: maskIp(mockHkIp),
        ipRawForLocalToggle: mockHkIp,
        countryCode: "HK",
        countryName: REGION_NAMES.HK,
        asnType: "hosting",
        isSupportedRegion: false,
        isRestrictedRegion: true,
        viaMode: "system-proxy",
        latencyMs: 65,
      },
      ipv6Exit: {
        source: "cloudflare-ipv6 (mock)",
        ipMasked: "240e:3b7:*:*::*",
        countryCode: "CN",
        countryName: REGION_NAMES.CN,
        asnType: "isp",
        isSupportedRegion: false,
        isRestrictedRegion: true,
        viaMode: "ipv6",
        latencyMs: 29,
      },
    };
  }

  async probeDomainMatrix(
    targets: DomainTarget[],
    _proxyAudit: ProxyStaticAudit,
    primaryExit: PublicExitSnapshot | undefined
  ): Promise<DomainProbeResult[]> {
    return targets.map((target, idx) => {
      if (this.scenario === "safe") {
        const isRaw = target.category === "raw_ip";
        return {
          host: target.host,
          category: target.category,
          officialAnthropic: target.officialAnthropic,
          label: target.label,
          riskNote: target.riskNote,
          resolvedIps: [],
          maskedResolvedIps: [isRaw ? "1.1.1.1" : "198.18.*.* (Fake-IP)"],
          isFakeIp: !isRaw,
          hasIpv6Resolution: false,
          routeInterface: "utun4",
          isTunRouted: true,
          staticRuleDecision: "proxy",
          edgeExitIpMasked: primaryExit?.ipMasked,
          edgeCountry: "US",
          probeMode: "local-zero-packet",
          status: "pass",
          statusReason: {
            zh: `经 utun4 虚拟网卡接管${isRaw ? "" : " (Fake-IP 命中)"}，锁定美国同源出口`,
            en: `Routed via utun4${isRaw ? "" : " (Fake-IP hijacked)"}, locked to US exit`,
          },
        };
      }

      const leaked =
        idx % 3 === 0 ||
        target.category === "telemetry" ||
        target.host === "siftscience.com" ||
        target.host === "api.anthropic.com";
      return {
        host: target.host,
        category: target.category,
        officialAnthropic: target.officialAnthropic,
        label: target.label,
        riskNote: target.riskNote,
        resolvedIps: [],
        maskedResolvedIps: [target.category === "raw_ip" ? "1.1.1.1" : "203.0.*.*"],
        isFakeIp: false,
        hasIpv6Resolution: idx % 2 === 0,
        routeInterface: leaked ? "en0" : "utun0",
        isTunRouted: !leaked,
        staticRuleDecision: leaked ? "direct" : "proxy",
        edgeExitIpMasked: leaked ? "203.0.*.*" : "192.0.*.*",
        edgeCountry: leaked ? "CN" : "HK",
        probeMode: "local-zero-packet",
        status: "critical",
        statusReason: leaked
          ? { zh: "未走 TUN！经物理网卡 en0 暴露中国大陆真实宽带 IP", en: "Bypassing TUN! Leaking CN ISP IP via en0" }
          : { zh: "出口落在受限地区 (HK 香港机房节点)", en: "Exiting via unsupported HK datacenter node" },
      };
    });
  }

  async auditProxyConfigSafely(): Promise<ProxyStaticAudit> {
    if (this.scenario === "safe") {
      return {
        detectedClients: ["Clash Verge Rev (Mihomo)"],
        configInspected: true,
        mode: "rule",
        tunEnabled: true,
        tunStack: "gvisor",
        strictRoute: true,
        dnsEnabled: true,
        enhancedMode: "fake-ip",
        dnsIpv6Enabled: false,
        ipv6Enabled: false,
        localListenerPorts: [7897],
        claudeTargetGroups: ["AI-Dedicated"],
        autoFallbackRiskGroups: [],
        manualSelectCautionGroups: [],
        hasDirectInProxyGroups: false,
        hasRestrictedRegionInGroups: false,
        hasStealthDomainDirectRule: false,
        finalMatchIsDirect: false,
        ruleCount: 86,
      };
    }

    return {
      detectedClients: ["Clash Verge Rev (Mihomo)"],
      configInspected: true,
      mode: "rule",
      tunEnabled: false,
      strictRoute: false,
      dnsEnabled: true,
      enhancedMode: "redir-host",
      dnsIpv6Enabled: true,
      ipv6Enabled: true,
      localListenerPorts: [7890],
      claudeTargetGroups: ["Auto-Fallback"],
      autoFallbackRiskGroups: ["Auto-Fallback"],
      manualSelectCautionGroups: [],
      hasDirectInProxyGroups: true,
      hasRestrictedRegionInGroups: true,
      hasStealthDomainDirectRule: true,
      finalMatchIsDirect: false,
      ruleCount: 42,
    };
  }

  async scanBinariesAndFirewall(): Promise<{ binaries: ClaudeBinaryItem[]; firewall: FirewallAudit }> {
    if (this.scenario === "safe") {
      return {
        binaries: [
          {
            id: "desktop-main",
            name: "Claude Desktop 主进程",
            displayPath: "/Applications/Claude.app",
            kind: "desktop-main",
            exists: true,
            signedByAnthropic: true,
            bundleOrSigningId: "com.anthropic.claudefordesktop",
            firewallCovered: true,
            riskLevel: "pass",
            note: { zh: "已由 LuLu 规则锁定虚拟网卡通道", en: "Locked to TUN interface by LuLu rules" },
          },
          {
            id: "desktop-helper",
            name: "Claude Chromium 网络辅助进程 (4x Helpers)",
            displayPath: "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app",
            kind: "desktop-helper",
            exists: true,
            signedByAnthropic: true,
            firewallCovered: true,
            riskLevel: "pass",
            note: {
              zh: "子进程已纳入 `/Applications/Claude.app/*` 封锁范围",
              en: "Covered by `/Applications/Claude.app/*` directory rule",
            },
          },
          {
            id: "desktop-shipit",
            name: "ShipIt 后台静默更新器",
            displayPath: "/Applications/Claude.app/Contents/Frameworks/Squirrel.framework/Resources/ShipIt",
            kind: "desktop-updater",
            exists: true,
            signedByAnthropic: true,
            firewallCovered: true,
            riskLevel: "pass",
            note: { zh: "自动更新器已受防火墙保护", en: "Updater binary locked by firewall" },
          },
          {
            id: "desktop-bundled-cli",
            name: "桌面端后台内置 claude-code (2.1.326)",
            displayPath: "~/Library/Application Support/Claude/claude-code/2.1.326",
            kind: "desktop-bundled-cli",
            exists: true,
            signedByAnthropic: true,
            bundleOrSigningId: "com.anthropic.claude-code",
            firewallCovered: true,
            riskLevel: "pass",
            note: { zh: "后台内置 CLI 目录与签名已受保护", en: "Bundled CLI path & signing ID covered" },
          },
          {
            id: "global-native",
            name: "全局终端 claude (官方原生二进制)",
            displayPath: "~/.local/bin/claude",
            kind: "global-cli-native",
            exists: true,
            signedByAnthropic: true,
            bundleOrSigningId: "com.anthropic.claude-code",
            firewallCovered: true,
            riskLevel: "pass",
            note: {
              zh: "官方原生签名二进制，已由 com.anthropic.claude-code 规则锁定",
              en: "Native Mach-O binary locked by signing ID",
            },
          },
        ],
        firewall: {
          luluInstalled: true,
          luluActive: true,
          luluPassiveMode: true,
          luluCoveredRuleCount: 30,
          luluCidrMisconfiguredRules: [],
          claudeAppFullyLocked: true,
          claudeCliLocked: true,
          littleSnitchDetected: false,
          pfDeadlockRiskDetected: false,
          pfDeadlockFiles: [],
          pfDeadlockResidualFiles: [],
          bootRaceRisk: false,
        },
      };
    }

    return {
      binaries: [
        {
          id: "desktop-main",
          name: "Claude Desktop 主进程",
          displayPath: "/Applications/Claude.app",
          kind: "desktop-main",
          exists: true,
          signedByAnthropic: true,
          bundleOrSigningId: "com.anthropic.claudefordesktop",
          firewallCovered: false,
          riskLevel: "warn",
          note: { zh: "无防火墙兜底，代理闪退或开机抢跑时将直连裸奔", en: "Unprotected; leaks ISP IP if proxy crashes" },
        },
        {
          id: "global-npm",
          name: "全局终端 claude (npm / Node.js 脚本版)",
          displayPath: "/opt/homebrew/bin/claude",
          kind: "global-cli-npm-node",
          exists: true,
          signedByAnthropic: false,
          firewallCovered: false,
          riskLevel: "critical",
          note: {
            zh: "高危盲区：通过 npm 安装，底层进程为 node，应用防火墙无法单独拦截！建议改用官方原生版",
            en: "Installed via npm ('node' process); per-app firewalls cannot isolate it!",
          },
        },
        {
          id: "ide-cursor",
          name: "Cursor 插件内置 Claude Code",
          displayPath: "~/.cursor/extensions/anthropic.claude-code-2.1.300",
          kind: "ide-extension-cli",
          exists: true,
          signedByAnthropic: true,
          firewallCovered: false,
          riskLevel: "warn",
          note: { zh: "IDE 扩展目录独立原生二进制未纳入防火墙保护", en: "IDE extension binary not covered by firewall" },
        },
      ],
      firewall: {
        luluInstalled: false,
        luluActive: false,
        luluCoveredRuleCount: 0,
        luluCidrMisconfiguredRules: [],
        claudeAppFullyLocked: false,
        claudeCliLocked: false,
        littleSnitchDetected: false,
        pfDeadlockRiskDetected: true,
        pfDeadlockFiles: ["/Library/Application Support/clash-guard/guard.sh (local.clash-guard: running)"],
        pfDeadlockResidualFiles: [],
        bootRaceRisk: true,
      },
    };
  }

  async inspectEnvironmentHygiene(): Promise<EnvironmentHygieneSnapshot> {
    if (this.scenario === "safe") {
      return {
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
        mcpServerCount: 2,
        mcpCommands: ["npx", "uvx"],
        suspiciousSettingsEnvKeys: [],
      };
    }

    return {
      systemTimezone: "Asia/Shanghai",
      isMainlandTimezone: true,
      systemLocale: "zh_CN.UTF-8",
      defaultBrowser: "Google Chrome",
      hasAnthropicBaseUrl: true,
      anthropicBaseUrlIsCustomThirdParty: true,
      settingsHasCustomBaseUrl: true,
      proxyEnvVarsPresent: ["HTTPS_PROXY"],
      proxyEnvConflictsWithSystem: true,
      dedicatedLoopbackProxyPorts: [],
      deadLoopbackProxyPorts: [17899],
      riskyReverseProxies: ["Sub2API"],
      mcpServerCount: 4,
      mcpCommands: ["npx", "python3"],
      suspiciousSettingsEnvKeys: ["_ACCOUNT_2_BACKUP"],
    };
  }

  async runKillSwitchProbe(): Promise<KillSwitchProbeSnapshot> {
    if (this.scenario === "safe") {
      return {
        tunActive: false,
        blocked: true,
        latencyMs: 19,
      };
    }

    return {
      tunActive: false,
      blocked: false,
      latencyMs: 34,
      leakedIpMasked: "203.0.*.*",
      leakedCountry: "CN",
    };
  }
}

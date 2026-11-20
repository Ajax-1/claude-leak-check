import { randomUUID } from "node:crypto";
import { arch, platform, release } from "node:os";
import { DOMAIN_MATRIX } from "./domains.js";
import { evaluateAuditScores } from "./scorer.js";
import { DarwinPlatformAdapter } from "../platforms/darwin.js";
import { MockPlatformAdapter, type DemoScenario } from "../platforms/mock.js";
import { Win32PlatformAdapter } from "../platforms/win32.js";
import type { AuditOptions, PlatformAdapter } from "../platforms/types.js";
import type { AuditReport, BrowserRealtimeSync, KillSwitchDrillResult } from "../types/report.js";

export interface RunAuditConfig {
  demo?: DemoScenario;
  deepProbe?: boolean;
  skipProxyFileRead?: boolean;
  sessionSalt?: string;
  customAdapter?: PlatformAdapter;
}

export function createPlatformAdapter(demo?: DemoScenario, customAdapter?: PlatformAdapter): PlatformAdapter {
  if (customAdapter) return customAdapter;
  if (demo) return new MockPlatformAdapter(demo);
  const osPlat = platform();
  if (osPlat === "darwin") return new DarwinPlatformAdapter();
  return new Win32PlatformAdapter();
}

export async function runFullAudit(
  config: RunAuditConfig = {}
): Promise<{ report: AuditReport; adapter: PlatformAdapter; sessionSalt: string }> {
  const startedAt = Date.now();
  const sessionSalt = config.sessionSalt || randomUUID();
  const adapter = createPlatformAdapter(config.demo, config.customAdapter);
  const options: AuditOptions = {
    deepProbe: config.deepProbe,
    sessionSalt,
    skipProxyFileRead: config.skipProxyFileRead,
  };

  // 第一阶段并发：网络栈快照 + 静态代理配置 + 全家桶与防火墙扫描
  const [netSnap, proxyAudit, binFirewall] = await Promise.all([
    adapter.getNetworkSnapshot(),
    adapter.auditProxyConfigSafely(options),
    adapter.scanBinariesAndFirewall(),
  ]);

  // 第二阶段并发：公网出口无凭证探测 + 环境卫生扫描（结合 proxyAudit 中的本地监听端口）
  const [exits, envSnap] = await Promise.all([
    adapter.probePublicExits(netSnap, options),
    adapter.inspectEnvironmentHygiene(netSnap, proxyAudit),
  ]);

  // 第三阶段：核心与暗桩域名矩阵路由与解析核验
  const domainMatrix = await adapter.probeDomainMatrix(
    DOMAIN_MATRIX,
    proxyAudit,
    exits.primaryExit,
    options
  );

  const browserSync: BrowserRealtimeSync =
    config.demo === "safe"
      ? {
          completed: true,
          browserExitIpMasked: exits.primaryExit?.ipMasked,
          browserExitIpHash: exits.cliExitIpHash,
          browserCountryCode: "US",
          matchesCliExit: true,
          webrtcTested: true,
          webrtcPublicIpsMasked: [],
          webrtcHasDomesticOrMismatchLeak: false,
          webrtcHasLanIpOnly: false,
          browserTimezone: "America/Los_Angeles",
          browserLanguages: ["en-US", "en"],
        }
      : config.demo === "leak"
        ? {
            completed: true,
            browserExitIpMasked: "198.51.*.*",
            browserCountryCode: "US",
            matchesCliExit: false,
            webrtcTested: true,
            webrtcPublicIpsMasked: ["203.0.*.*"],
            webrtcHasDomesticOrMismatchLeak: true,
            webrtcHasLanIpOnly: false,
            browserTimezone: "Asia/Shanghai",
            browserLanguages: ["zh-CN", "zh"],
          }
        : {
            completed: false,
            webrtcTested: false,
            webrtcPublicIpsMasked: [],
            webrtcHasDomesticOrMismatchLeak: false,
            webrtcHasLanIpOnly: false,
          };

  const killSwitchDrill: KillSwitchDrillResult = {
    executed: false,
    tunActiveDuringDrill: netSnap.activeUtunInterfaces.length > 0,
    systemProbeBlocked: false,
    systemProbeLatencyMs: 0,
    perAppFirewallVerified:
      binFirewall.firewall.claudeAppFullyLocked && binFirewall.firewall.claudeCliLocked,
    verdict: "untested",
    verdictTitle: {
      zh: "尚未执行断网防漏演练（完成后可解锁 S+ 金盾勋章）",
      en: "Kill-Switch Drill not yet executed (Complete to unlock S+ Gold Shield)",
    },
    verdictDetail: {
      zh: "请在报告页向导中手动关闭 TUN 或退出代理软件 3 秒，点击测试按钮实测是否会漏出真实宽带 IP。",
      en: "Follow the interactive wizard in the HTML report: manually turn off TUN/proxy for 3s and test if traffic leaks.",
    },
    proxyRestoredVerified: true,
  };

  const scored = evaluateAuditScores({
    netSnap,
    primaryExit: exits.primaryExit,
    systemProxyExit: exits.systemProxyExit,
    ipv6Exit: exits.ipv6Exit,
    domainMatrix,
    binaries: binFirewall.binaries,
    proxyAudit,
    firewallAudit: binFirewall.firewall,
    envSnap,
    browserSync,
    killSwitchDrill,
  });

  const osPlat = platform();
  const normalizedPlatform: "darwin" | "win32" | "linux" =
    osPlat === "darwin" || osPlat === "win32" ? osPlat : "linux";

  const report: AuditReport = {
    reportId: randomUUID().slice(0, 8),
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    platform: config.demo ? "darwin" : normalizedPlatform,
    osRelease: release(),
    arch: arch(),
    demoMode: config.demo,
    privacyNote: {
      zh: "100% 纯只读本地审计 · 0 账号凭证读取 · 0 系统配置改动 · 敏感 IP 与路径已默认脱敏打码",
      en: "100% Read-Only Local Audit · Zero Credential Access · Zero System Modification · Auto-Redacted IPs",
    },
    rawScore: scored.rawScore,
    finalScore: scored.finalScore,
    grade: scored.grade,
    redlineTriggered: scored.redlineTriggered,
    redlineReasons: scored.redlineReasons,
    killSwitchVerifiedBadge: scored.killSwitchVerifiedBadge,
    primaryExit: exits.primaryExit,
    systemProxyExit: exits.systemProxyExit,
    ipv6Exit: exits.ipv6Exit,
    cliExitIpHash: exits.cliExitIpHash,
    modules: scored.modules,
    domainMatrix,
    binaries: binFirewall.binaries,
    proxyAudit,
    firewallAudit: binFirewall.firewall,
    environmentSummary: {
      systemTimezone: envSnap.systemTimezone,
      isMainlandTimezone: envSnap.isMainlandTimezone,
      systemLocale: envSnap.systemLocale,
      defaultBrowser: envSnap.defaultBrowser,
      activeUtunInterfaces: netSnap.activeUtunInterfaces,
      dnsServersMasked: netSnap.dnsServersMasked,
      tailscaleMagicDns: netSnap.tailscaleMagicDns,
      icloudPrivateRelaySuspected: netSnap.icloudPrivateRelaySuspected,
      publicIpv6Interfaces: netSnap.publicIpv6Interfaces.map((i) => `${i.iface} (${i.addressMasked})`),
      hasAnthropicBaseUrl: envSnap.hasAnthropicBaseUrl,
      settingsHasCustomBaseUrl: envSnap.settingsHasCustomBaseUrl,
      proxyEnvVarsPresent: envSnap.proxyEnvVarsPresent,
      dedicatedLoopbackProxyPorts: envSnap.dedicatedLoopbackProxyPorts,
      deadLoopbackProxyPorts: envSnap.deadLoopbackProxyPorts,
      riskyReverseProxies: envSnap.riskyReverseProxies,
      mcpServerCount: envSnap.mcpServerCount,
      mcpCommands: envSnap.mcpCommands,
      suspiciousSettingsEnvKeys: envSnap.suspiciousSettingsEnvKeys,
    },
    browserSync,
    killSwitchDrill,
  };

  return { report, adapter, sessionSalt };
}

/**
 * 导出用于公开 JSON / Markdown / 静态 HTML 分享的 100% 彻底擦除原始 IP 副本
 */
export function stripLocalToggleRawFields(report: AuditReport): AuditReport {
  const clone = structuredClone(report);
  if (clone.primaryExit) delete clone.primaryExit.ipRawForLocalToggle;
  if (clone.systemProxyExit) delete clone.systemProxyExit.ipRawForLocalToggle;
  if (clone.ipv6Exit) delete clone.ipv6Exit.ipRawForLocalToggle;
  return clone;
}

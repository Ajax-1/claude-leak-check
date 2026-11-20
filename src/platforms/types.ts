import type {
  ClaudeBinaryItem,
  DomainProbeResult,
  DomainTarget,
  FirewallAudit,
  ProxyStaticAudit,
  PublicExitSnapshot,
} from "../types/report.js";

export interface NetworkStackSnapshot {
  activeUtunInterfaces: string[];
  defaultRouteInterface: string;
  dnsServers: string[];
  dnsServersMasked: string[];
  tailscaleMagicDns: boolean;
  icloudPrivateRelaySuspected: boolean;
  competingVpns: string[];
  systemProxy: {
    httpEnabled: boolean;
    httpsEnabled: boolean;
    socksEnabled: boolean;
    proxyHost?: string;
    proxyPort?: number;
  };
  publicIpv6Interfaces: {
    iface: string;
    addressMasked: string;
    isMainlandCarrier: boolean;
  }[];
}

export interface EnvironmentHygieneSnapshot {
  systemTimezone: string;
  isMainlandTimezone: boolean;
  systemLocale: string;
  defaultBrowser: string;
  hasAnthropicBaseUrl: boolean;
  anthropicBaseUrlIsCustomThirdParty: boolean;
  settingsHasCustomBaseUrl: boolean;
  proxyEnvVarsPresent: string[];
  proxyEnvConflictsWithSystem: boolean;
  dedicatedLoopbackProxyPorts: number[];
  deadLoopbackProxyPorts: number[];
  riskyReverseProxies: string[];
  mcpServerCount: number;
  mcpCommands: string[];
  suspiciousSettingsEnvKeys: string[];
}

export interface KillSwitchProbeSnapshot {
  tunActive: boolean;
  blocked: boolean;
  latencyMs: number;
  leakedIpMasked?: string;
  leakedCountry?: string;
}

export interface AuditOptions {
  deepProbe?: boolean;
  sessionSalt: string;
  skipProxyFileRead?: boolean;
}

export interface PlatformAdapter {
  readonly platform: "darwin" | "win32" | "linux";
  getNetworkSnapshot(): Promise<NetworkStackSnapshot>;
  probePublicExits(
    netSnap: NetworkStackSnapshot,
    options: AuditOptions
  ): Promise<{
    primaryExit?: PublicExitSnapshot;
    systemProxyExit?: PublicExitSnapshot;
    ipv6Exit?: PublicExitSnapshot;
    cliExitIpHash?: string;
  }>;
  probeDomainMatrix(
    targets: DomainTarget[],
    proxyAudit: ProxyStaticAudit,
    primaryExit: PublicExitSnapshot | undefined,
    options: AuditOptions
  ): Promise<DomainProbeResult[]>;
  auditProxyConfigSafely(options: AuditOptions): Promise<ProxyStaticAudit>;
  scanBinariesAndFirewall(): Promise<{
    binaries: ClaudeBinaryItem[];
    firewall: FirewallAudit;
  }>;
  inspectEnvironmentHygiene(
    netSnap: NetworkStackSnapshot,
    proxyAudit?: ProxyStaticAudit
  ): Promise<EnvironmentHygieneSnapshot>;
  runKillSwitchProbe(): Promise<KillSwitchProbeSnapshot>;
}

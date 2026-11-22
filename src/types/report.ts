export interface BilingualText {
  zh: string;
  en: string;
}

export type Severity = "pass" | "info" | "warn" | "fail" | "critical";

export type Grade = "S+" | "A+" | "A" | "B" | "C" | "D" | "F";

export type ProxyTopologyPreference = "auto" | "host-tun" | "router-gateway";

export type ResolvedProxyTopology = "host-tun" | "router-gateway";

export type DomainCategory =
  | "core"
  | "feature_gate"
  | "telemetry"
  | "antifraud_billing"
  | "auth_infra"
  | "raw_ip";

export interface DomainTarget {
  host: string;
  category: DomainCategory;
  officialAnthropic: boolean;
  label: BilingualText;
  riskNote: BilingualText;
}

export interface DomainProbeResult {
  host: string;
  category: DomainCategory;
  officialAnthropic: boolean;
  label: BilingualText;
  riskNote: BilingualText;
  resolvedIps: string[];
  maskedResolvedIps: string[];
  isFakeIp: boolean;
  hasIpv6Resolution: boolean;
  routeInterface: string;
  isTunRouted: boolean;
  staticRuleDecision: "proxy" | "direct" | "reject" | "unknown";
  edgeExitIpMasked?: string;
  edgeCountry?: string;
  probeMode: "local-zero-packet" | "edge-trace";
  status: "pass" | "warn" | "critical";
  statusReason: BilingualText;
}

export interface PublicExitSnapshot {
  source: string;
  ipMasked: string;
  ipRawForLocalToggle?: string;
  countryCode: string;
  countryName: BilingualText;
  region?: string;
  city?: string;
  asn?: string;
  org?: string;
  asnType: "isp" | "hosting" | "education" | "business" | "unknown";
  isSupportedRegion: boolean;
  isRestrictedRegion: boolean;
  viaMode: "direct-socket-noproxy" | "system-proxy" | "ipv6" | "non-gfw-echo";
  latencyMs: number;
}

export interface ClaudeBinaryItem {
  id: string;
  name: string;
  displayPath: string;
  kind:
    | "desktop-main"
    | "desktop-helper"
    | "desktop-updater"
    | "desktop-cowork-vm"
    | "desktop-bundled-cli"
    | "global-cli-native"
    | "global-cli-npm-node"
    | "global-cli-unverified-shim"
    | "global-cli-stub"
    | "ide-extension-cli";
  exists: boolean;
  signedByAnthropic: boolean;
  teamId?: string;
  bundleOrSigningId?: string;
  firewallCovered: boolean;
  riskLevel: "pass" | "warn" | "critical";
  note: BilingualText;
}

export interface ProxyStaticAudit {
  detectedClients: string[];
  configInspected: boolean;
  mode?: "rule" | "global" | "direct" | "unknown";
  tunEnabled?: boolean;
  tunStack?: string;
  strictRoute?: boolean;
  dnsEnabled?: boolean;
  enhancedMode?: string;
  dnsIpv6Enabled?: boolean;
  ipv6Enabled?: boolean;
  localListenerPorts: number[];
  claudeTargetGroups: string[];
  autoFallbackRiskGroups: string[];
  manualSelectCautionGroups: string[];
  hasDirectInProxyGroups: boolean;
  hasRestrictedRegionInGroups: boolean;
  hasStealthDomainDirectRule: boolean;
  finalMatchIsDirect: boolean;
  ruleCount: number;
}

export interface FirewallAudit {
  luluInstalled: boolean;
  luluActive: boolean;
  luluPassiveMode?: boolean;
  luluCoveredRuleCount: number;
  luluCidrMisconfiguredRules: string[];
  claudeAppFullyLocked: boolean;
  claudeCliLocked: boolean;
  littleSnitchDetected: boolean;
  pfDeadlockRiskDetected: boolean;
  pfDeadlockFiles: string[];
  pfDeadlockResidualFiles: string[];
  bootRaceRisk: boolean;
}

export interface CheckFinding {
  id: string;
  moduleId: ModuleId;
  severity: Severity;
  pointsDeducted: number;
  triggersRedline: boolean;
  title: BilingualText;
  detail: BilingualText;
  remediation: BilingualText;
}

export type ModuleId =
  | "egress_matrix"
  | "network_stack"
  | "browser_sync"
  | "app_footprint"
  | "env_hygiene";

export interface ModuleScore {
  id: ModuleId;
  name: BilingualText;
  maxPoints: number;
  earnedPoints: number;
  status: "pass" | "warn" | "critical";
  summary: BilingualText;
  findings: CheckFinding[];
}

export interface BrowserRealtimeSync {
  completed: boolean;
  probeBlockedOrFailed?: boolean;
  probeSource?: string;
  browserExitIpMasked?: string;
  browserExitIpHash?: string;
  browserCountryCode?: string;
  matchesCliExit?: boolean;
  webrtcTested: boolean;
  webrtcPublicIpsMasked: string[];
  webrtcHasDomesticOrMismatchLeak: boolean;
  webrtcHasLanIpOnly: boolean;
  userAgent?: string;
  browserTimezone?: string;
  browserLanguages?: string[];
  dohSuspected?: boolean;
}

export interface KillSwitchDrillResult {
  executed: boolean;
  executedAt?: string;
  tunActiveDuringDrill: boolean;
  systemProbeBlocked: boolean;
  systemProbeLatencyMs: number;
  systemProbeLeakedIpMasked?: string;
  systemProbeLeakedCountry?: string;
  perAppFirewallVerified: boolean;
  verdict: "untested" | "global_blocked" | "app_firewall_locked" | "leaked" | "proxy_still_on";
  verdictTitle: BilingualText;
  verdictDetail: BilingualText;
  proxyRestoredVerified: boolean;
}

export interface AuditReport {
  reportId: string;
  generatedAt: string;
  durationMs: number;
  platform: "darwin" | "win32" | "linux";
  osRelease: string;
  arch: string;
  demoMode?: string;
  topologyPreference: ProxyTopologyPreference;
  resolvedTopology: ResolvedProxyTopology;
  routerAutoDetected: boolean;
  privacyNote: BilingualText;

  // Scores & Grades
  rawScore: number;
  finalScore: number;
  grade: Grade;
  redlineTriggered: boolean;
  redlineReasons: BilingualText[];
  killSwitchVerifiedBadge: boolean;

  // Primary Exit Summary
  primaryExit?: PublicExitSnapshot;
  nonGfwExit?: PublicExitSnapshot;
  nonGfwMatchesPrimary?: boolean;
  systemProxyExit?: PublicExitSnapshot;
  ipv6Exit?: PublicExitSnapshot;
  cliExitIpHash?: string;

  // Detailed Sections
  modules: ModuleScore[];
  domainMatrix: DomainProbeResult[];
  binaries: ClaudeBinaryItem[];
  proxyAudit: ProxyStaticAudit;
  firewallAudit: FirewallAudit;
  environmentSummary: {
    systemTimezone: string;
    isMainlandTimezone: boolean;
    systemLocale: string;
    defaultBrowser: string;
    activeUtunInterfaces: string[];
    defaultRouteInterface: string;
    defaultGatewayMasked?: string;
    dnsServersMasked: string[];
    tailscaleMagicDns: boolean;
    icloudPrivateRelaySuspected: boolean;
    publicIpv6Interfaces: string[];
    hasAnthropicBaseUrl: boolean;
    settingsHasCustomBaseUrl: boolean;
    proxyEnvVarsPresent: string[];
    dedicatedLoopbackProxyPorts: number[];
    deadLoopbackProxyPorts: number[];
    riskyReverseProxies: string[];
    mcpServerCount: number;
    mcpCommands: string[];
    suspiciousSettingsEnvKeys: string[];
  };
  browserSync: BrowserRealtimeSync;
  killSwitchDrill: KillSwitchDrillResult;
}

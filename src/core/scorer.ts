import { RESTRICTED_REGIONS } from "./domains.js";
import type {
  BilingualText,
  BrowserRealtimeSync,
  CheckFinding,
  ClaudeBinaryItem,
  DomainProbeResult,
  FirewallAudit,
  Grade,
  KillSwitchDrillResult,
  ModuleScore,
  ProxyStaticAudit,
  PublicExitSnapshot,
  ResolvedProxyTopology,
} from "../types/report.js";
import type { EnvironmentHygieneSnapshot, NetworkStackSnapshot } from "../platforms/types.js";

const DOMESTIC_PUBLIC_DNS_SET = new Set([
  "114.114.114.114",
  "114.114.115.115",
  "223.5.5.5",
  "223.6.6.6",
  "119.29.29.29",
  "119.28.28.28",
  "180.76.76.76",
  "1.2.4.8",
  "210.2.4.8",
]);

export interface ScoringInputs {
  resolvedTopology?: ResolvedProxyTopology;
  routerAutoDetected?: boolean;
  netSnap: NetworkStackSnapshot;
  primaryExit?: PublicExitSnapshot;
  nonGfwExit?: PublicExitSnapshot;
  nonGfwMatchesPrimary?: boolean;
  systemProxyExit?: PublicExitSnapshot;
  ipv6Exit?: PublicExitSnapshot;
  domainMatrix: DomainProbeResult[];
  binaries: ClaudeBinaryItem[];
  proxyAudit: ProxyStaticAudit;
  firewallAudit: FirewallAudit;
  envSnap: EnvironmentHygieneSnapshot;
  browserSync: BrowserRealtimeSync;
  killSwitchDrill: KillSwitchDrillResult;
}

export interface ScoringOutput {
  modules: ModuleScore[];
  rawScore: number;
  finalScore: number;
  grade: Grade;
  redlineTriggered: boolean;
  redlineReasons: BilingualText[];
  killSwitchVerifiedBadge: boolean;
}

export function evaluateAuditScores(input: ScoringInputs): ScoringOutput {
  const isRouterMode = input.resolvedTopology === "router-gateway";
  const redlineReasons: BilingualText[] = [];
  const addRedline = (reason: BilingualText): void => {
    if (!redlineReasons.some((r) => r.zh === reason.zh)) {
      redlineReasons.push(reason);
    }
  };

  // =========================================================================
  // 模块 1：暗桩域名全矩阵与出口质量 (30 分)
  // =========================================================================
  const m1Findings: CheckFinding[] = [];
  let m1Deduct = 0;

  if (!input.primaryExit) {
    m1Deduct += 20;
    m1Findings.push({
      id: "exit-unreachable",
      moduleId: "egress_matrix",
      severity: "fail",
      pointsDeducted: 20,
      triggersRedline: false,
      title: {
        zh: "底层无代理环境变量 Socket 无法连通公共检测节点",
        en: "Underlying non-env socket could not reach public probe endpoint",
      },
      detail: {
        zh: "使用 --noproxy '*' 访问海外公共回显接口超时，说明当前未开启有效的 TUN 全局接管或网络已阻断。",
        en: "Direct socket probe timed out; either TUN mode is off or outbound network is currently blocked.",
      },
      remediation: {
        zh: "开启代理客户端的 TUN（虚拟网卡）模式，确保不读取 HTTP_PROXY 的命令行与子进程也能正常走海外通道。",
        en: "Enable TUN virtual adapter mode in your proxy client so non-HTTP_PROXY processes route properly.",
      },
    });
  } else if (input.primaryExit.isRestrictedRegion) {
    m1Deduct += 30;
    const reason = {
      zh: `底层真实出口落在不支持/高危受限地区：${input.primaryExit.countryName.zh} (${input.primaryExit.ipMasked})`,
      en: `Primary socket exit is in an unsupported/restricted region: ${input.primaryExit.countryName.en} (${input.primaryExit.ipMasked})`,
    };
    addRedline(reason);
    m1Findings.push({
      id: "exit-restricted-region",
      moduleId: "egress_matrix",
      severity: "critical",
      pointsDeducted: 30,
      triggersRedline: true,
      title: reason,
      detail: {
        zh: "Anthropic 对中国大陆、香港、澳门等不支持地区的直连或节点出口执行严格自动化风控，极易触发立即封禁。",
        en: "Anthropic strictly enforces regional restrictions; traffic from CN/HK/MO triggers automated suspension.",
      },
      remediation: {
        zh: "将代理出口切换并固定在官方支持国家（如 US / SG / JP / KR / GB），并开启 TUN 模式接管底层流量。",
        en: "Route traffic through a fixed exit in an officially supported country (e.g., US, SG, JP, KR, GB) with TUN enabled.",
      },
    });
  } else {
    const asnLabel =
      input.primaryExit.asnType === "isp"
        ? { zh: "原生 ISP / 家庭宽带属性", en: "Native ISP / Residential ASN" }
        : input.primaryExit.asnType === "hosting"
          ? {
              zh: "数据中心 / 云机房 ASN（请确保为独享静态节点，勿用万人骑机场）",
              en: "Hosting / Datacenter ASN (Ensure dedicated static IP, avoid shared pools)",
            }
          : { zh: "商业专线 / 骨干网运营商 ASN", en: "Business / Tier-1 Backbone ASN" };

    m1Findings.push({
      id: "exit-region-ok",
      moduleId: "egress_matrix",
      severity: input.primaryExit.asnType === "hosting" ? "info" : "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `主出口位于受支持地区：${input.primaryExit.countryName.zh} (${input.primaryExit.ipMasked})`,
        en: `Primary exit in supported region: ${input.primaryExit.countryName.en} (${input.primaryExit.ipMasked})`,
      },
      detail: {
        zh: `归属组织：${input.primaryExit.asn || ""} ${input.primaryExit.org || "Unknown"} · ${asnLabel.zh}`,
        en: `Organization: ${input.primaryExit.asn || ""} ${input.primaryExit.org || "Unknown"} · ${asnLabel.en}`,
      },
      remediation: {
        zh: "日常使用请锁死同一国家的固定静态 IP，切勿在多国节点间频繁切换。",
        en: "Keep using a single static IP in the same country; avoid hopping across countries.",
      },
    });
  }

  const totalDomainCount = input.domainMatrix.length;
  const criticalDomains = input.domainMatrix.filter((d) => d.status === "critical");
  const warnDomains = input.domainMatrix.filter((d) => d.status === "warn");

  if (criticalDomains.length > 0) {
    const sampleHosts = criticalDomains.slice(0, 4).map((d) => d.host).join(", ");
    m1Deduct += 25;
    addRedline({
      zh: `${criticalDomains.length} 个核心/遥测暗桩域名未走虚拟网卡或被直连放行（含 ${sampleHosts}）`,
      en: `${criticalDomains.length} core/telemetry domains bypass TUN or route DIRECT (${sampleHosts})`,
    });
    m1Findings.push({
      id: "matrix-critical-leak",
      moduleId: "egress_matrix",
      severity: "critical",
      pointsDeducted: 25,
      triggersRedline: true,
      title: {
        zh: `抓获 ${criticalDomains.length}/${totalDomainCount} 个暗桩域名存在直连或受限出口泄漏`,
        en: `${criticalDomains.length}/${totalDomainCount} stealth/telemetry domains leaking directly or to restricted region`,
      },
      detail: {
        zh: `典型漏网目标：${sampleHosts}。即使主站打不开或走了代理，Sentry/Datadog/Statsig/Sift 等第三方接口国内直连秒通，会瞬间上报真实宽带 IP。`,
        en: `Affected hosts include ${sampleHosts}. Third-party telemetry endpoints connect directly without GFW block, exposing your real IP alongside your session.`,
      },
      remediation: {
        zh: "开启 TUN 虚拟网卡严格路由，并在分流规则最前方确保 Datadog、Sentry、Statsig、Sift、Stripe、Intercom 与纯 IP 兜底规则统一指向同一海外出口。",
        en: "Enable TUN strict-route and ensure Datadog, Sentry, Statsig, Sift, Stripe, Intercom, and final MATCH rules point to the same supported exit.",
      },
    });
  } else if (warnDomains.length > 0) {
    const pts = Math.min(8, warnDomains.length * 2);
    m1Deduct += pts;
    m1Findings.push({
      id: "matrix-fakeip-warn",
      moduleId: "egress_matrix",
      severity: "warn",
      pointsDeducted: pts,
      triggersRedline: false,
      title: {
        zh: `${warnDomains.length} 个域名虽走虚拟网卡，但未命中 Fake-IP 劫持或解析异常`,
        en: `${warnDomains.length} domains route via TUN without Fake-IP hijacking or failed lookup`,
      },
      detail: {
        zh: "实 IP 模式下若本地 DNS 存在并发抢答，可能向国内运营商暴露查询记录。",
        en: "Real-IP resolution without Fake-IP may risk ISP DNS snooping if local DNS servers race.",
      },
      remediation: {
        zh: "建议在 Clash / Mihomo 中开启 dns.enhanced-mode: fake-ip 以实现零延迟防 DNS 抢答。",
        en: "Recommend setting `dns.enhanced-mode: fake-ip` in Clash/Mihomo to prevent DNS race leaks.",
      },
    });
  } else {
    m1Findings.push({
      id: "matrix-all-locked",
      moduleId: "egress_matrix",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `全部 ${totalDomainCount}/${totalDomainCount} 个核心与风控暗桩域名 100% 同源接管`,
        en: `All ${totalDomainCount}/${totalDomainCount} core & stealth telemetry domains uniformly routed via TUN`,
      },
      detail: {
        zh: "包含 assets-proxy、bridge 沙盒桥接、Datadog 横杠域名、Sentry、Statsig、Sift、Stripe 及纯 IP 探针均进入同一虚拟网卡通道。",
        en: "Includes assets-proxy, sandbox bridge, hyphenated Datadog RUM, Sentry, Statsig, Sift, Stripe, and raw IP fallback probe.",
      },
      remediation: { zh: "无需操作，保持当前分流完整性。", en: "No action needed." },
    });
  }

  if (
    input.primaryExit &&
    input.nonGfwExit &&
    input.nonGfwMatchesPrimary === false
  ) {
    m1Deduct += 25;
    const leakCc = input.nonGfwExit.countryCode !== "UNKNOWN" ? ` · ${input.nonGfwExit.countryCode}` : "";
    addRedline({
      zh: `软路由/网关分流穿帮：被墙源走 ${input.primaryExit.ipMasked} (${input.primaryExit.countryCode})，但未被墙国际源 (AWS) 暴露不同出口 (${input.nonGfwExit.ipMasked}${leakCc})`,
      en: `Split-routing leak: GFW-blocked target exits via ${input.primaryExit.ipMasked}, while unblocked AWS echo exits via ${input.nonGfwExit.ipMasked}${leakCc}`,
    });
    m1Findings.push({
      id: "router-gfwlist-split-leak",
      moduleId: "egress_matrix",
      severity: "critical",
      pointsDeducted: 25,
      triggersRedline: true,
      title: {
        zh: `抓获 GFWList 绕过漏分流：未被墙国际接口暴露不一致出口 (${input.nonGfwExit.ipMasked}${leakCc})`,
        en: `GFWList Split-Routing Leak: Unblocked international endpoint exposed mismatched exit (${input.nonGfwExit.ipMasked}${leakCc})`,
      },
      detail: {
        zh: `被墙回显源 (1.1.1.1) 走 ${input.primaryExit.countryCode} (${input.primaryExit.ipMasked})，而未被墙的 AWS 公共回显源却走 ${input.nonGfwExit.ipMasked}。在软路由 GFWList（仅代理被墙域名）模式下，Sentry、Datadog、Statsig、Sift 等未被墙的第三方风控暗桩会直接走家庭宽带裸奔上报！`,
        en: `Cloudflare 1.1.1.1 routed via ${input.primaryExit.ipMasked}, whereas unblocked AWS checkip routed via ${input.nonGfwExit.ipMasked}. In GFWList-only router setups, unblocked Sentry/Datadog/Statsig telemetry leaks your real ISP IP.`,
      },
      remediation: {
        zh: "在 OpenClash / PassWall / Nikki 中切勿使用纯 GFWList 模式；请改为「绕过中国大陆 IP（大陆白名单）」或将 Anthropic 及全部第三方遥测域名强制绑定同一静态节点。",
        en: "Switch your router proxy from GFWList-only mode to China-IP-Whitelist (Bypass Mainland CN IPs) or explicitly route all Claude & telemetry domains through your static node.",
      },
    });
  } else if (isRouterMode && input.nonGfwMatchesPrimary === true && input.primaryExit?.isSupportedRegion) {
    m1Findings.push({
      id: "router-nongfw-consistent",
      moduleId: "egress_matrix",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `非 GFW 国际源分流实测同源：被墙源与 AWS 未被墙源共享同一出口 (${input.primaryExit.ipMasked})`,
        en: `Non-GFW Split Check Passed: Blocked & unblocked AWS probes share identical exit (${input.primaryExit.ipMasked})`,
      },
      detail: {
        zh: "已排除软路由「仅代理 GFWList 导致未被墙风控暗桩直连宽带」的高频翻车隐患。",
        en: "Confirmed your transparent router gateway also proxies unblocked international endpoints rather than GFWList-only.",
      },
      remediation: { zh: "保持当前绕过大陆白名单或全局代理策略。", en: "Keep current router rule mode." },
    });
  }

  if (
    input.primaryExit &&
    input.systemProxyExit &&
    input.primaryExit.ipMasked !== input.systemProxyExit.ipMasked
  ) {
    m1Deduct += 20;
    addRedline({
      zh: `系统代理端口出口 (${input.systemProxyExit.ipMasked} · ${input.systemProxyExit.countryCode}) 与底层终端出口 (${input.primaryExit.ipMasked} · ${input.primaryExit.countryCode}) 双 IP 分裂`,
      en: `System proxy exit (${input.systemProxyExit.ipMasked}) differs from underlying socket exit (${input.primaryExit.ipMasked})`,
    });
    m1Findings.push({
      id: "sysproxy-vs-tun-mismatch",
      moduleId: "egress_matrix",
      severity: "critical",
      pointsDeducted: 20,
      triggersRedline: true,
      title: {
        zh: "高危分裂：系统 HTTP 代理与底层 TUN 走向两个不同 IP！",
        en: "Critical Split: System HTTP proxy and underlying TUN route to two different IPs!",
      },
      detail: {
        zh: `遵循系统代理的应用走 ${input.systemProxyExit.countryCode} (${input.systemProxyExit.ipMasked})，而不吃系统代理的终端 CLI / 子进程走 ${input.primaryExit.countryCode} (${input.primaryExit.ipMasked})。`,
        en: `Apps honoring system proxy exit via ${input.systemProxyExit.countryCode}, while raw CLI sockets exit via ${input.primaryExit.countryCode}.`,
      },
      remediation: {
        zh: "排查是否同时运行了两个代理工具，或只开了系统代理而未开启同一个客户端的 TUN 虚拟网卡。",
        en: "Ensure only one proxy client manages traffic and enable its TUN mode so both paths share one exit.",
      },
    });
  }

  // =========================================================================
  // 模块 2：TUN 虚拟网卡 / 透明网关、DNS 劫持与双栈防漏 (20 分)
  // =========================================================================
  const m2Findings: CheckFinding[] = [];
  let m2Deduct = 0;

  if (isRouterMode) {
    const gwDisplay = input.netSnap.defaultGatewayMasked || "LAN Gateway";
    const modeSourceTag = input.routerAutoDetected
      ? { zh: "（已自动识别透明网关拓扑）", en: " (Auto-detected transparent gateway)" }
      : { zh: "（软路由/透明网关模式）", en: " (Router gateway mode)" };
    m2Findings.push({
      id: "router-gateway-active",
      moduleId: "network_stack",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `局域网透明网关接管中：${input.netSnap.defaultRouteInterface || "en0"} -> ${gwDisplay}${modeSourceTag.zh}`,
        en: `LAN Transparent Gateway Active: ${input.netSnap.defaultRouteInterface || "en0"} -> ${gwDisplay}${modeSourceTag.en}`,
      },
      detail: {
        zh: "代理部署于上游软路由/旁路由，本机无需开启 utun 虚拟网卡，命令行与桌面端子进程天然经默认网关转发。",
        en: "Proxy runs on upstream LAN router/gateway; CLI and child processes naturally route via default gateway without local utun.",
      },
      remediation: {
        zh: "若你实际并未使用软路由，可点击页面顶部切换回「本机 TUN 模式」。",
        en: "If you are not using a router proxy, toggle back to Host TUN mode in the top bar.",
      },
    });

    // 软路由 DNS 卫生检查 1：检查是否混入 114 / 223.5.5.5 等国内公共 DNS
    const hitDomesticDns = input.netSnap.dnsServers.filter((ip) => DOMESTIC_PUBLIC_DNS_SET.has(ip));
    if (hitDomesticDns.length > 0) {
      m2Deduct += 8;
      m2Findings.push({
        id: "router-domestic-dns-leak",
        moduleId: "network_stack",
        severity: "warn",
        pointsDeducted: 8,
        triggersRedline: false,
        title: {
          zh: `系统 DNS 包含国内公共 DNS (${hitDomesticDns.join(", ")})，存在解析抢答与泄漏风险`,
          en: `System DNS includes domestic public resolver(s) (${hitDomesticDns.join(", ")})`,
        },
        detail: {
          zh: "在软路由/旁路由环境下，若本机直接配置了 114/阿里/腾讯公共 DNS，DNS 请求可能绕过软路由 Fake-IP/防污染模块或向运营商暴露域名轨迹。",
          en: "Configuring domestic public DNS directly on the host can bypass your router's Fake-IP/anti-poisoning DNS engine.",
        },
        remediation: {
          zh: "将本机与 DHCP 下发的 DNS 唯一指向软路由/旁路由网关地址，由软路由统一做防污染与 Fake-IP 解析。",
          en: "Point host/DHCP DNS exclusively to your OpenWrt/gateway IP so all queries go through the router's DNS engine.",
        },
      });
    }

    // 软路由 DNS 卫生检查 2：旁路由网关 (.2 等非 .1 地址) 与主路由 DNS (.1) 错位检查
    const gwIp = input.netSnap.defaultGatewayIp;
    const anyFakeIpDomain = input.domainMatrix.some((d) => d.isFakeIp);
    if (gwIp && /^(\d+\.\d+\.\d+)\.(\d+)$/.test(gwIp)) {
      const m = /^(\d+\.\d+\.\d+)\.(\d+)$/.exec(gwIp)!;
      const subnetPrefix = m[1];
      const lastOctet = m[2];
      const mainRouterCandidate = `${subnetPrefix}.1`;
      if (
        lastOctet !== "1" &&
        input.netSnap.dnsServers.includes(mainRouterCandidate) &&
        !input.netSnap.dnsServers.includes(gwIp) &&
        !anyFakeIpDomain
      ) {
        m2Deduct += 6;
        m2Findings.push({
          id: "side-router-dns-mismatch",
          moduleId: "network_stack",
          severity: "warn",
          pointsDeducted: 6,
          triggersRedline: false,
          title: {
            zh: "旁路由网关与首选 DNS 错位（网关指向旁路由，但 DNS 仍指向主路由 .1）",
            en: "Side-router gateway/DNS mismatch (Gateway is side-router, but DNS points to .1 main router)",
          },
          detail: {
            zh: "经典旁路由翻车点：默认网关虽指向旁路由，但 DHCP/手动 DNS 仍留在主路由（光猫/硬路由），会导致国内 DNS 抢答或旁路由无法按域名准确分流。",
            en: "When using a side-router gateway while DNS remains on the main ISP router (.1), DNS queries leak to ISP resolvers before hitting the side-router.",
          },
          remediation: {
            zh: "在旁路由 DHCP 或本机网络设置中，将「DNS 服务器」也同步改为旁路由的局域网 IP。",
            en: "Set your DNS server IP to match your side-router gateway IP in DHCP or macOS Wi-Fi settings.",
          },
        });
      }
    }
  } else if (
    input.netSnap.activeUtunInterfaces.length === 0 ||
    !input.netSnap.defaultRouteInterface.startsWith("utun")
  ) {
    if (input.netSnap.defaultRouteInterface !== "WinTUN" && !input.netSnap.activeUtunInterfaces.length) {
      m2Deduct += 15;
      addRedline({
        zh: `未检测到接管默认路由的 TUN 虚拟网卡（当前默认接口：${input.netSnap.defaultRouteInterface || "物理网卡"}）`,
        en: `No active TUN virtual interface hijacking default route (current: ${input.netSnap.defaultRouteInterface || "physical NIC"})`,
      });
      m2Findings.push({
        id: "tun-disabled",
        moduleId: "network_stack",
        severity: "critical",
        pointsDeducted: 15,
        triggersRedline: true,
        title: {
          zh: "致命盲区：未开启 TUN 虚拟网卡全局路由接管",
          en: "Fatal Blindspot: TUN virtual network interface is not active",
        },
        detail: {
          zh: `当前系统默认路由走物理接口 ${input.netSnap.defaultRouteInterface || "en0"}。终端命令行工具（如 Claude Code）及后台辅助进程默认忽略系统 HTTP 代理，极易直接裸奔暴露宽带 IP。（注：若代理部署在软路由，请切换为软路由模式或加 --router 参数）`,
          en: "Terminal tools like Claude Code and helper binaries ignore system HTTP proxies by default, leaking real ISP IP without TUN. (Use --router if your proxy runs on your LAN router.)",
        },
        remediation: {
          zh: "在 Clash Verge / Mihomo / Surge / Sing-box 中开启服务模式与 TUN 严格路由；若使用透明软路由，请点击顶部「模式: 软路由网关」重评。",
          en: "Enable Service Mode + TUN Mode + Strict Route in your proxy client, or switch to Router Gateway mode if using OpenWrt.",
        },
      });
    }
  } else {
    m2Findings.push({
      id: "tun-active",
      moduleId: "network_stack",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `TUN 虚拟网卡已激活接管默认路由 (${input.netSnap.defaultRouteInterface})`,
        en: `TUN virtual adapter active on default route (${input.netSnap.defaultRouteInterface})`,
      },
      detail: {
        zh: `活跃虚拟接口：${input.netSnap.activeUtunInterfaces.join(", ")}`,
        en: `Active virtual interfaces: ${input.netSnap.activeUtunInterfaces.join(", ")}`,
      },
      remediation: { zh: "保持开启。", en: "Keep TUN enabled." },
    });
  }

  if (input.ipv6Exit?.isRestrictedRegion) {
    m2Deduct += 15;
    addRedline({
      zh: `致命 IPv6 双栈泄漏：外部探测直通国内运营商 IPv6 (${input.ipv6Exit.ipMasked})`,
      en: `Fatal IPv6 Leak: Outbound IPv6 bypasses proxy via restricted carrier (${input.ipv6Exit.ipMasked})`,
    });
    m2Findings.push({
      id: "ipv6-active-leak",
      moduleId: "network_stack",
      severity: "critical",
      pointsDeducted: 15,
      triggersRedline: true,
      title: {
        zh: `抓获 IPv6 双栈绕过泄漏 (${input.ipv6Exit.ipMasked} · ${input.ipv6Exit.countryCode})`,
        en: `Active IPv6 Dual-Stack Leak Detected (${input.ipv6Exit.ipMasked} · ${input.ipv6Exit.countryCode})`,
      },
      detail: {
        zh: "现代浏览器与系统默认开启 Happy Eyeballs 协议，即使 IPv4 走美国代理，IPv6 仍直接通过本地运营商宽带向外发包，触发跨国双 IP 秒封！",
        en: "Happy Eyeballs races IPv6 alongside proxied IPv4, exposing your domestic carrier IPv6 address simultaneously.",
      },
      remediation: {
        zh: "在系统网络设置中将 IPv6 设为「仅本地链接 (Link-local only)」，并在 Clash 设置中关闭 IPv6 与 DNS IPv6。",
        en: "Set IPv6 to 'Link-local only' in OS network settings and disable IPv6 in Clash/Mihomo.",
      },
    });
  } else if (input.netSnap.publicIpv6Interfaces.some((i) => i.isMainlandCarrier)) {
    m2Deduct += 8;
    m2Findings.push({
      id: "ipv6-carrier-assigned",
      moduleId: "network_stack",
      severity: "warn",
      pointsDeducted: 8,
      triggersRedline: false,
      title: {
        zh: "物理网卡挂载了国内运营商公网 IPv6 地址",
        en: "Physical NIC holds a domestic carrier global IPv6 address",
      },
      detail: {
        zh: `检测到 ${input.netSnap.publicIpv6Interfaces.map((i) => `${i.iface}: ${i.addressMasked}`).join(", ")}。当代理闪断或规则未拦截 IPv6 时极易抢跑泄漏。`,
        en: "Carrier global IPv6 on physical interface risks leaking during proxy reconnects or WebRTC probes.",
      },
      remediation: {
        zh: "求稳建议在 macOS Wi-Fi 高级设置 -> TCP/IP 中将配置 IPv6 改为「仅本地链接」。",
        en: "Set Configure IPv6 to 'Link-local only' in macOS Wi-Fi TCP/IP settings for maximum safety.",
      },
    });
  }

  if (input.netSnap.tailscaleMagicDns) {
    m2Deduct += 10;
    m2Findings.push({
      id: "tailscale-magic-dns",
      moduleId: "network_stack",
      severity: "warn",
      pointsDeducted: 10,
      triggersRedline: false,
      title: {
        zh: "检测到 Tailscale MagicDNS (100.100.100.100) 抢占系统首选 DNS",
        en: "Tailscale MagicDNS (100.100.100.100) is overriding primary system DNS",
      },
      detail: {
        zh: "Tailscale 接管首选 DNS 时，部分域名解析可能绕过 Clash Fake-IP 直接发往上游，造成 DNS 地域穿帮。",
        en: "Tailscale MagicDNS can intercept queries before Clash Fake-IP, causing upstream DNS region leaks.",
      },
      remediation: {
        zh: "使用 Claude 期间建议在 Tailscale 菜单中取消勾选 AllowOverrideDNS / Use Tailscale DNS，或暂停 Tailscale。",
        en: "Disable 'Use Tailscale DNS' while running Claude so Clash TUN cleanly owns DNS resolution.",
      },
    });
  }

  if (input.netSnap.icloudPrivateRelaySuspected) {
    m2Deduct += 8;
    m2Findings.push({
      id: "icloud-private-relay",
      moduleId: "network_stack",
      severity: "warn",
      pointsDeducted: 8,
      triggersRedline: false,
      title: {
        zh: "检测到 macOS「iCloud 专用代理 (Private Relay)」活跃迹象",
        en: "macOS iCloud Private Relay appears active",
      },
      detail: {
        zh: "开启 iCloud 专用代理会导致 Safari 及部分系统框架流量走苹果就近边缘节点（常跳港台），与代理出口冲突。",
        en: "iCloud Private Relay routes Safari/Apple framework traffic via Apple edge relays, conflicting with your proxy IP.",
      },
      remediation: {
        zh: "建议在系统设置 -> Apple ID -> iCloud -> 专用代理中关闭，统一由 TUN 接管。",
        en: "Turn off iCloud Private Relay in System Settings so all traffic shares one consistent TUN exit.",
      },
    });
  }

  // =========================================================================
  // 模块 3：首次登录浏览器 vs 桌面端同源与 WebRTC/DoH (20 分)
  // =========================================================================
  const m3Findings: CheckFinding[] = [];
  let m3Deduct = 0;

  if (input.browserSync.completed) {
    if (input.browserSync.matchesCliExit === false) {
      m3Deduct += 20;
      addRedline({
        zh: `浏览器当前出口 (${input.browserSync.browserExitIpMasked || "Unknown"} · ${input.browserSync.browserCountryCode || "?"}) 与终端/桌面端出口 (${input.primaryExit?.ipMasked || "Unknown"}) 不一致！`,
        en: `Browser exit IP (${input.browserSync.browserExitIpMasked || "Unknown"}) does NOT match CLI/Desktop exit (${input.primaryExit?.ipMasked || "Unknown"})!`,
      });
      m3Findings.push({
        id: "browser-cli-mismatch",
        moduleId: "browser_sync",
        severity: "critical",
        pointsDeducted: 20,
        triggersRedline: true,
        title: {
          zh: "高危错位：默认浏览器出口与桌面端/CLI 出口不一致",
          en: "Critical Mismatch: Browser exit IP differs from Desktop/CLI exit IP",
        },
        detail: {
          zh: `浏览器当前走 ${input.browserSync.browserExitIpMasked} (${input.browserSync.browserCountryCode || "?"})，而桌面端/终端走 ${input.primaryExit?.ipMasked || "本地网络"}。当桌面端或 CLI 弹出浏览器完成 OAuth 授权登录并传回 Token 的一瞬间，同一会话在 1 秒内跨越两个 IP，极易触发立即封号！`,
          en: "When Claude Desktop/Code opens your browser for OAuth login and hands the token back, Anthropic sees two different IPs on the same session within milliseconds.",
        },
        remediation: {
          zh: "关闭浏览器内的独立代理扩展（如 SwitchyOmega / 梯子插件），让浏览器与桌面端统一走同一个 Clash TUN 虚拟网卡出口！",
          en: "Disable browser-only proxy extensions (like SwitchyOmega) so your browser and Claude Desktop share the exact same TUN exit.",
        },
      });
    } else if (input.browserSync.matchesCliExit === true) {
      m3Findings.push({
        id: "browser-cli-matched",
        moduleId: "browser_sync",
        severity: "pass",
        pointsDeducted: 0,
        triggersRedline: false,
        title: {
          zh: `OAuth 双端完全同源：浏览器与终端/桌面端共享同一出口 (${input.browserSync.browserExitIpMasked})`,
          en: `OAuth Sync Verified: Browser & CLI/Desktop share identical exit (${input.browserSync.browserExitIpMasked})`,
        },
        detail: {
          zh: `默认浏览器 (${input.envSnap.defaultBrowser}) 与系统底层 Socket 出口哈希 100% 吻合，无授权横跳风险。`,
          en: `Default browser (${input.envSnap.defaultBrowser}) matches CLI socket exit 100%.`,
        },
        remediation: {
          zh: "保持浏览器不额外挂载冲突代理插件即可。",
          en: "Keep browser using system TUN without extra proxy extensions.",
        },
      });
    } else if (input.browserSync.browserExitIpMasked) {
      m3Findings.push({
        id: "browser-cli-uncompared",
        moduleId: "browser_sync",
        severity: "warn",
        pointsDeducted: 0,
        triggersRedline: false,
        title: {
          zh: `已读取浏览器出口 (${input.browserSync.browserExitIpMasked})，但终端底层探针离线未能完成双端比对`,
          en: `Browser exit detected (${input.browserSync.browserExitIpMasked}), but CLI socket probe was offline`,
        },
        detail: {
          zh: "浏览器可正常出网而终端底层无代理探针失败，通常意味着代理仅在浏览器插件内生效而未开启系统级 TUN。",
          en: "Browser reached echo endpoints while CLI socket probes failed, suggesting proxy only runs inside browser without TUN.",
        },
        remediation: {
          zh: "请开启代理客户端的 TUN 虚拟网卡模式后重新执行检测。",
          en: "Enable TUN virtual adapter mode in your proxy client and re-run the check.",
        },
      });
    } else {
      m3Findings.push({
        id: "browser-echo-blocked",
        moduleId: "browser_sync",
        severity: "info",
        pointsDeducted: 0,
        triggersRedline: false,
        title: {
          zh: "浏览器跨域回显请求被拦截或不可达（双端同源待确认）",
          en: "Browser outbound IP echo blocked or unreachable (OAuth sync unverified)",
        },
        detail: {
          zh: `当前浏览器 (${input.envSnap.defaultBrowser}) 对多组公共回显接口的请求均未返回出口 IP。常见原因：(1) Brave Shields、uBlock Origin、AdGuard 等隐私防追踪扩展拦截了 127.0.0.1 页面的跨域回显请求；(2) 浏览器内挂载的独立代理扩展（如 SwitchyOmega）指向了未运行端口导致浏览器断网。`,
          en: `All fallback IP echo requests from ${input.envSnap.defaultBrowser} were blocked or failed. Common causes: (1) Brave Shields / uBlock Origin / AdGuard blocking cross-origin probes from 127.0.0.1, or (2) a misconfigured browser proxy extension.`,
        },
        remediation: {
          zh: "可对 127.0.0.1 临时关闭防追踪盾后点击首屏「点此重试」按钮；若浏览器本身无法访问外网，请关闭冲突的浏览器代理扩展以统一走 TUN。",
          en: "Temporarily lower Brave Shields / ad-blocker on 127.0.0.1 and click Retry above, or disable broken browser proxy extensions.",
        },
      });
    }

    if (input.browserSync.webrtcHasDomesticOrMismatchLeak) {
      m3Deduct += 20;
      addRedline({
        zh: `浏览器 WebRTC STUN 绕过代理泄漏真实公网 IP (${input.browserSync.webrtcPublicIpsMasked.join(", ")})`,
        en: `Browser WebRTC STUN leaked mismatched public IP (${input.browserSync.webrtcPublicIpsMasked.join(", ")})`,
      });
      m3Findings.push({
        id: "webrtc-public-leak",
        moduleId: "browser_sync",
        severity: "critical",
        pointsDeducted: 20,
        triggersRedline: true,
        title: {
          zh: "致命穿透：浏览器 WebRTC UDP 暴露了不一致的真实公网 IP！",
          en: "Fatal Leak: Browser WebRTC UDP exposed a mismatched real public IP!",
        },
        detail: {
          zh: `STUN 探测抓获公网候选地址：${input.browserSync.webrtcPublicIpsMasked.join(", ")}。表面挂着代理，底层 UDP 直接把真实宽带位置卖给了前端风控脚本。`,
          en: `STUN probe discovered mismatched public candidate(s): ${input.browserSync.webrtcPublicIpsMasked.join(", ")}.`,
        },
        remediation: {
          zh: "使用 Brave 浏览器（防指纹保护）或在 Chrome/Edge 安装 WebRTC Leak Prevent 将策略设为 disable_non_proxied_udp，并在 Clash 开启严格路由。",
          en: "Use Brave Shields or install WebRTC Leak Prevent (`disable_non_proxied_udp`) in Chrome/Edge.",
        },
      });
    } else if (input.browserSync.webrtcTested) {
      m3Findings.push({
        id: "webrtc-clean",
        moduleId: "browser_sync",
        severity: "pass",
        pointsDeducted: 0,
        triggersRedline: false,
        title: {
          zh: "浏览器原生 WebRTC STUN 穿透实测：0 真实公网 IP 泄漏",
          en: "Browser WebRTC STUN Live Probe: Zero mismatched public IP leak",
        },
        detail: {
          zh:
            input.browserSync.webrtcPublicIpsMasked.length > 0
              ? `仅检测到与代理同源候选地址 (${input.browserSync.webrtcPublicIpsMasked.join(", ")})`
              : "非代理 UDP 已被完美抑制，未暴露任何真实宽带公网地址。",
          en: "Non-proxied UDP candidates are properly suppressed or aligned with your proxy exit.",
        },
        remediation: {
          zh: "请顺手确认已关闭 Chrome/Edge 设置中的「使用安全 DNS (DoH)」，防止内置国内 DoH 绕过 Fake-IP。",
          en: "Also ensure Chrome/Edge built-in 'Use Secure DNS (DoH)' is turned off so it doesn't bypass Fake-IP.",
        },
      });
    }
  } else {
    m3Findings.push({
      id: "browser-sync-pending",
      moduleId: "browser_sync",
      severity: "info",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `已识别默认浏览器：${input.envSnap.defaultBrowser}（打开本地 HTML 报告页即自动完成双端比对与 WebRTC 实测）`,
        en: `Default browser: ${input.envSnap.defaultBrowser} (Open local HTML report to complete live OAuth IP & WebRTC check)`,
      },
      detail: {
        zh: "提醒：首次登录弹窗会拉起默认浏览器，切勿在浏览器内单独开启与桌面端不一致的代理插件；同时建议关闭浏览器内置「安全 DNS (DoH)」。",
        en: "Ensure your browser does not run a separate proxy extension pointing to a different node than TUN, and disable built-in DoH.",
      },
      remediation: {
        zh: "在浏览器中打开本工具生成的报告页即可实时验证双端出口一致性。",
        en: "Open the local HTML report in your browser to run live WebRTC & dual-exit verification.",
      },
    });
  }

  // =========================================================================
  // 模块 4：Claude 全家桶入口、代理分流与防火墙焊死度 (20 分)
  // =========================================================================
  const m4Findings: CheckFinding[] = [];
  let m4Deduct = 0;

  // 4.1 全局 CLI 三态审计（Node 脚本驻留风险 / 未核验版本管理器垫片 / 未完成 postinstall 桩文件）
  const npmCli = input.binaries.find((b) => b.kind === "global-cli-npm-node");
  if (npmCli) {
    m4Deduct += 10;
    m4Findings.push({
      id: "npm-node-cli-risk",
      moduleId: "app_footprint",
      severity: "fail",
      pointsDeducted: 10,
      triggersRedline: false,
      title: {
        zh: `发现基于 Node.js 解释器运行的全局 claude 脚本 (${npmCli.displayPath})`,
        en: `Detected Node.js-interpreted global 'claude' script (${npmCli.displayPath})`,
      },
      detail: {
        zh: "该入口实际驻留进程为 'node'（常见于旧版纯 JS 包或未完成原生二进制替换的 fallback 脚本），LuLu / Little Snitch 等防火墙无法通过 Anthropic 签名将其与普通前端 Node 进程区分开。",
        en: "This entrypoint executes inside the generic 'node' runtime rather than Anthropic's signed native binary, preventing signature-based firewall isolation.",
      },
      remediation: {
        zh: "建议升级至包含原生 Mach-O 二进制的新版 @anthropic-ai/claude-code（确保未开启 --ignore-scripts / --omit=optional），或改用官方独立安装器。",
        en: "Upgrade to a modern native-binary release (without --ignore-scripts / --omit=optional) or use Anthropic's standalone installer.",
      },
    });
  }

  const unverifiedShim = input.binaries.find((b) => b.kind === "global-cli-unverified-shim");
  if (unverifiedShim) {
    m4Deduct += 4;
    m4Findings.push({
      id: "cli-unverified-shim",
      moduleId: "app_footprint",
      severity: "warn",
      pointsDeducted: 4,
      triggersRedline: false,
      title: {
        zh: `全局 claude 为版本管理器垫片或非 Anthropic 签名程序 (${unverifiedShim.displayPath})`,
        en: `Global 'claude' is a version-manager shim or non-Anthropic binary (${unverifiedShim.displayPath})`,
      },
      detail: {
        zh: "该入口并非带 Anthropic 官方签名的原生 Mach-O（典型如 Volta shim、asdf 或 mise 动态垫片），纯静态检查无法确认其底层最终拉起的是官方签名二进制还是 Node 脚本。",
        en: "This entrypoint is a dynamic shim (e.g. Volta / asdf / mise) or non-Anthropic binary, so static inspection cannot verify its underlying runtime signature.",
      },
      remediation: {
        zh: "建议核实垫片实际转发的底层二进制是否带有 com.anthropic.claude-code (Q6L2SF6YDW) 签名，并在防火墙中按签名或实际落地路径锁定。",
        en: "Verify that the underlying binary invoked by your version manager is signed with com.anthropic.claude-code (Q6L2SF6YDW) and locked in your firewall.",
      },
    });
  }

  const stubCli = input.binaries.find((b) => b.kind === "global-cli-stub");
  if (stubCli) {
    m4Findings.push({
      id: "cli-uninstalled-stub",
      moduleId: "app_footprint",
      severity: "info",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `检测到未完成 postinstall 的全局 claude 占位桩文件 (${stubCli.displayPath})`,
        en: `Detected incomplete postinstall stub for global 'claude' (${stubCli.displayPath})`,
      },
      detail: {
        zh: "该文件为包管理器跳过 postinstall（如 pnpm v10 默认拦截构建脚本或使用了 --ignore-scripts）留下的报错脚本，运行时直接退出，不会发起网络请求。",
        en: "Placeholder error script left when postinstall was skipped (e.g. pnpm v10 build policy or --ignore-scripts); exits immediately without network activity.",
      },
      remediation: {
        zh: "如需使用该全局命令，请执行 pnpm approve-builds -g 允许构建脚本拉取原生二进制，或卸载该残缺全局包。",
        en: "Run 'pnpm approve-builds -g' / reinstall without '--ignore-scripts', or remove the unused broken stub.",
      },
    });
  }

  // 4.2 LuLu Fake-IP CIDR `isEndpointAddrRegex = 0` 字面量模式误配排雷
  if (input.firewallAudit.luluCidrMisconfiguredRules.length > 0) {
    m4Deduct += 6;
    const sampleRule = input.firewallAudit.luluCidrMisconfiguredRules.join(", ");
    m4Findings.push({
      id: "lulu-cidr-literal-mode",
      moduleId: "app_footprint",
      severity: "warn",
      pointsDeducted: 6,
      triggersRedline: false,
      title: {
        zh: "发现 LuLu 网段放行规则模式误配（CIDR 被设为了字面量 `isEndpointAddrRegex = 0`）",
        en: "LuLu CIDR subnet rule misconfigured as literal string (`isEndpointAddrRegex = 0`)",
      },
      detail: {
        zh: `命中规则：${sampleRule}。在 Objective-See LuLu v4.4+ 中，网段前缀（如 198.18.0.0/16）必须将内部属性 isEndpointAddrRegex 设为 2（CIDR 模式）才能正确匹配网段，设为 0 会当成普通字符串比对导致正常 Fake-IP 流量被误拦截！`,
        en: `Affected rule(s): ${sampleRule}. In LuLu v4.4+, CIDR ranges require \`isEndpointAddrRegex = 2\` to match subnets rather than literal strings.`,
      },
      remediation: {
        zh: "在 LuLu 规则编辑器中重新添加该网段放行规则，或将导入 JSON 中的 `isEndpointAddrRegex` 修正为 `2` 后重新导入。",
        en: "Edit the subnet rule in LuLu UI or set `isEndpointAddrRegex: 2` in your imported rules JSON.",
      },
    });
  }

  // 4.3 macOS PF `user != root` 内核死锁排雷（区分当前活跃 vs 已停用仅残留文件）
  if (input.firewallAudit.pfDeadlockRiskDetected) {
    m4Deduct += 8;
    m4Findings.push({
      id: "pf-kernel-deadlock",
      moduleId: "app_footprint",
      severity: "fail",
      pointsDeducted: 8,
      triggersRedline: false,
      title: {
        zh: "高危系统排雷：发现正在运行的 `user != root` 旧版 macOS PF 防漏脚本！",
        en: "Active System Hazard: Running legacy macOS PF script using `user != root`!",
      },
      detail: {
        zh: `命中活跃配置/守护脚本：${input.firewallAudit.pfDeadlockFiles.join(", ")}。在 macOS 内核中，PF 规则使用 user != root 反向匹配 socket owner 会触发内核锁重入死锁，导致 Wi-Fi 灰掉打不开、整机假死卡死！`,
        en: `Active in ${input.firewallAudit.pfDeadlockFiles.join(", ")}. Using \`user != root\` in macOS PF triggers an XNU socket-lock kernel deadlock that freezes Wi-Fi and hangs macOS.`,
      },
      remediation: {
        zh: "强烈建议停用并卸载该旧版 PF 守护脚本，改用基于苹果现代 Network Extension 机制的开源防火墙 LuLu 锁定 Claude 进程。",
        en: "Unload and remove legacy `user != root` PF scripts and use modern Network Extension firewalls like Objective-See LuLu instead.",
      },
    });
  } else if (input.firewallAudit.pfDeadlockResidualFiles.length > 0) {
    m4Findings.push({
      id: "pf-kernel-deadlock-residual",
      moduleId: "app_footprint",
      severity: "info",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: "检测到已停用的旧版 PF 脚本文件残留（当前未运行，0 死机风险）",
        en: "Inactive legacy `user != root` PF script file found on disk (Not running)",
      },
      detail: {
        zh: `残留路径：${input.firewallAudit.pfDeadlockResidualFiles.join(", ")}。经 launchctl 核实该服务处于停用状态，不会影响当前系统，但切勿重新启用它。`,
        en: `Residual file(s): ${input.firewallAudit.pfDeadlockResidualFiles.join(", ")}. Verified inactive via launchctl; do not re-enable.`,
      },
      remediation: {
        zh: "保持停用即可，后续确认不再需要时可顺手删除残留 plist 与脚本文件。",
        en: "Keep it unloaded, or remove the leftover plist/script files when convenient.",
      },
    });
  }

  // 4.4 代理静态配置回落隐患（仅针对实际承载 Claude 流量的目标策略组判断，绝不连坐无关组！）
  if (input.proxyAudit.configInspected) {
    if (input.proxyAudit.autoFallbackRiskGroups.length > 0) {
      m4Deduct += 6;
      const grpList = input.proxyAudit.autoFallbackRiskGroups.join(", ");
      m4Findings.push({
        id: "proxy-group-auto-fallback-risk",
        moduleId: "app_footprint",
        severity: "warn",
        pointsDeducted: 6,
        triggersRedline: false,
        title: {
          zh: `承载 Claude 流量的自动切换策略组 (${grpList}) 混入了 DIRECT 或港澳受限节点`,
          en: `Auto-switching policy group(s) carrying Claude traffic (${grpList}) include DIRECT or HK/MO nodes`,
        },
        detail: {
          zh: `策略组「${grpList}」属于自动测速/故障转移类型（url-test / fallback / load-balance），一旦网络波动会自动将 Claude 流量切往港澳受限节点或本地直连！`,
          en: `Auto-switching groups (${grpList}) can silently shift your session IP to HK/MO or DIRECT during latency spikes.`,
        },
        remediation: {
          zh: "为 Claude 规则单独绑定纯手动 `type: select` 固定节点组（仅保留支持国静态节点，剔除自动切换与港澳/DIRECT 项）。",
          en: "Route Claude to a manual `type: select` group pinned to a single supported static node.",
        },
      });
    } else if (input.proxyAudit.manualSelectCautionGroups.length > 0) {
      const grpList = input.proxyAudit.manualSelectCautionGroups.join(", ");
      m4Findings.push({
        id: "proxy-group-manual-select-note",
        moduleId: "app_footprint",
        severity: "info",
        pointsDeducted: 0,
        triggersRedline: false,
        title: {
          zh: `目标策略组「${grpList}」为纯手动 select 模式（候选含 DIRECT / 港澳项，不会自动漂移）`,
          en: `Target group '${grpList}' uses manual \`select\` mode (will not auto-drift, though DIRECT/HK options exist in list)`,
        },
        detail: {
          zh: `已确认承载流量的策略组「${grpList}」不是自动测速切换组，只要不手滑误点里面的 DIRECT 或受限地区节点就不会自动跳 IP。`,
          en: `Because '${grpList}' is a manual \`select\` group rather than \`url-test\`/\`fallback\`, it won't switch automatically unless clicked manually.`,
        },
        remediation: {
          zh: "日常保持手选在固定的受支持国家静态节点上，切勿手滑点选同组内的 DIRECT。",
          en: "Keep your manual selection pinned to your supported static node and avoid clicking DIRECT.",
        },
      });
    }
  }

  // 4.5 防火墙焊死度检查（排除无法联网的未安装占位桩文件与已单独告警的动态垫片）
  const actionableBins = input.binaries.filter(
    (b) => b.kind !== "global-cli-stub" && b.kind !== "global-cli-unverified-shim"
  );
  const installedCount = actionableBins.length;
  const unprotectedBins = actionableBins.filter((b) => !b.firewallCovered);
  const routerGlobalKillVerified =
    isRouterMode &&
    input.killSwitchDrill.executed &&
    input.killSwitchDrill.verdict === "global_blocked";

  if (routerGlobalKillVerified) {
    m4Findings.push({
      id: "router-killswitch-verified",
      moduleId: "app_footprint",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: "软路由级断网阻断 (Kill-Switch) 已实测通过",
        en: "Router-level WAN forwarding Kill-Switch verified via live drill",
      },
      detail: {
        zh: "实测表明当上游透明代理暂停时，路由器防火墙已阻断 LAN -> WAN 直连回退，不会漏出家庭宽带 IP。",
        en: "Verified that stopping the router proxy blocks LAN-to-WAN fallback rather than leaking ISP traffic.",
      },
      remediation: { zh: "保持路由器防火墙阻断兜底规则。", en: "Keep router firewall kill-switch enabled." },
    });
  } else if (isRouterMode && installedCount > 0 && unprotectedBins.length > 0 && !input.firewallAudit.littleSnitchDetected) {
    m4Deduct += 4;
    m4Findings.push({
      id: "router-killswitch-unverified",
      moduleId: "app_footprint",
      severity: "warn",
      pointsDeducted: 4,
      triggersRedline: false,
      title: {
        zh: "软路由插件崩溃/掉线时的防直连兜底 (Kill-Switch) 尚未验证",
        en: "Router proxy crash fallback (Kill-Switch) is not yet verified",
      },
      detail: {
        zh: "软路由 OpenClash / PassWall 更新重启或核心崩溃期间，默认网关往往会自动回退到主路由宽带直连。本机当前未开启 LuLu 锁定，需确认路由器侧已配置断代理禁连 WAN 规则。",
        en: "When OpenClash/PassWall restarts or crashes on a router, LAN traffic often falls back directly to WAN ISP unless blocked by router firewall or host LuLu.",
      },
      remediation: {
        zh: "建议在 OpenWrt 防火墙配置禁止绕过透明代理直连 WAN（并在上方演练舱暂停插件实测解锁 S+），或在本机用 LuLu 仅放行软路由 Fake-IP 网段。",
        en: "Configure OpenWrt nftables/iptables to block direct LAN->WAN fallback (and verify via the Drill above for S+), or lock Fake-IP CIDR in LuLu.",
      },
    });
  } else if (installedCount > 0 && unprotectedBins.length > 0 && !input.firewallAudit.littleSnitchDetected) {
    const pts = Math.min(10, input.firewallAudit.bootRaceRisk ? 10 : 7);
    m4Deduct += pts;
    m4Findings.push({
      id: "firewall-not-locked",
      moduleId: "app_footprint",
      severity: "warn",
      pointsDeducted: pts,
      triggersRedline: false,
      title: {
        zh: `本机 ${unprotectedBins.length}/${installedCount} 个 Claude 组件缺少系统级断网防火墙焊死保护`,
        en: `${unprotectedBins.length}/${installedCount} local Claude binaries lack system-level firewall kill-switch protection`,
      },
      detail: {
        zh: `只靠代理软件自身分流存在致命空窗期：一旦代理崩溃闪退、休眠唤醒慢了 2 秒${input.firewallAudit.bootRaceRisk ? "（且检测到 Claude 自启抢跑风险！）" : ""}，客户端重连会直接走物理宽带把真实 IP 上报给 Sentry/Datadog。`,
        en: "Relying solely on Clash rules leaves a gap if Clash crashes, updates, or starts slower than Claude on boot/wake.",
      },
      remediation: {
        zh: "建议配合 LuLu 防火墙，将 `/Applications/Claude.app/*`、`~/Library/Application Support/Claude/*` 及 `com.anthropic.*` 签名限制为仅允许 Fake-IP (198.18.0.0/15, CIDR 模式 2) 与回环通信，阻断一切直连外网。",
        en: "Use LuLu firewall rules to restrict `/Applications/Claude.app/*`, `~/Library/Application Support/Claude/*`, and `com.anthropic.*` signatures strictly to Fake-IP/TUN ranges.",
      },
    });
  } else if (installedCount > 0 && unprotectedBins.length === 0) {
    m4Findings.push({
      id: "firewall-all-locked",
      moduleId: "app_footprint",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `完美焊死：本机全部 ${installedCount} 个 Claude 入口及子进程均已受 LuLu 防火墙锁定`,
        en: `Locked Down: All ${installedCount} local Claude binaries & helpers are protected by LuLu rules`,
      },
      detail: {
        zh: `已精确核实 ${input.firewallAudit.luluCoveredRuleCount} 条生效的 Claude 防火墙规则（默认阻断 *:* 已就位，无全局放行后门）。`,
        en: `Verified across ${input.firewallAudit.luluCoveredRuleCount} active Claude-targeted LuLu rules with default-block enforced.`,
      },
      remediation: {
        zh: "可在上方「断网防漏演练舱」进一步实测验证解锁 S+ 金盾勋章。",
        en: "Run the interactive Kill-Switch Drill above to earn the S+ Gold Shield badge.",
      },
    });
  }

  // =========================================================================
  // 模块 5：本机环境“送中/暗标”与残留卫生 (10 分)
  // =========================================================================
  const m5Findings: CheckFinding[] = [];
  let m5Deduct = 0;

  if (input.envSnap.isMainlandTimezone) {
    m5Deduct += 4;
    m5Findings.push({
      id: "timezone-mainland",
      moduleId: "env_hygiene",
      severity: "warn",
      pointsDeducted: 4,
      triggersRedline: false,
      title: {
        zh: `系统时区为大陆标识 (${input.envSnap.systemTimezone})，与海外出口画像存在冲突`,
        en: `System timezone is set to mainland China (${input.envSnap.systemTimezone}), conflicting with overseas exit`,
      },
      detail: {
        zh: "社区逆向与抓包证实客户端遥测（如 Sentry 启动载荷及历史环境检测逻辑）会读取本地系统时区。",
        en: "Client telemetry payloads (including Sentry launch context) read the host OS timezone.",
      },
      remediation: {
        zh: "若不想改变北京时间显示，可将系统时区改为同样是 UTC+8 的台北 (Asia/Taipei) 或新加坡 (Asia/Singapore)，或对齐节点所在国时区。",
        en: "Consider switching OS timezone to `Asia/Taipei` or `Asia/Singapore` (also UTC+8) or matching your proxy country's timezone.",
      },
    });
  } else {
    m5Findings.push({
      id: "timezone-safe",
      moduleId: "env_hygiene",
      severity: "pass",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `系统时区非高危受限区标识 (${input.envSnap.systemTimezone})`,
        en: `System timezone is clean (${input.envSnap.systemTimezone})`,
      },
      detail: {
        zh: `当前语言区域：${input.envSnap.systemLocale}`,
        en: `Current system locale: ${input.envSnap.systemLocale}`,
      },
      remediation: { zh: "无需调整。", en: "No change required." },
    });
  }

  if (input.envSnap.anthropicBaseUrlIsCustomThirdParty) {
    m5Deduct += 4;
    const srcHint = input.envSnap.settingsHasCustomBaseUrl
      ? "~/.claude/settings.json (env.ANTHROPIC_BASE_URL)"
      : "Shell / launchctl ANTHROPIC_BASE_URL";
    m5Findings.push({
      id: "custom-base-url",
      moduleId: "env_hygiene",
      severity: "warn",
      pointsDeducted: 4,
      triggersRedline: false,
      title: {
        zh: `检测到自定义第三方 ANTHROPIC_BASE_URL 中转配置 (${srcHint})`,
        en: `Custom third-party \`ANTHROPIC_BASE_URL\` detected in ${srcHint}`,
      },
      detail: {
        zh: "若登录官方个人 Pro/Max 订阅号时残留了第三方中转站域名配置，可能命中客户端内置中转域名检测。",
        en: "Leaving a third-party relay `ANTHROPIC_BASE_URL` set while logging into an official Pro/Max account risks tripping relay checks.",
      },
      remediation: {
        zh: "使用官方直连订阅账号前请移除 `~/.claude/settings.json` 或终端配置中的第三方 `ANTHROPIC_BASE_URL`。",
        en: "Remove third-party `ANTHROPIC_BASE_URL` from `~/.claude/settings.json` or shell profile when using official subscriptions.",
      },
    });
  }

  // 代理环境变量校验（智能识别本机活跃专属 listener 端口 vs 未监听死端口）
  if (input.envSnap.deadLoopbackProxyPorts.length > 0 || input.envSnap.proxyEnvConflictsWithSystem) {
    m5Deduct += 3;
    const deadPortsStr =
      input.envSnap.deadLoopbackProxyPorts.length > 0
        ? ` (未监听端口: 127.0.0.1:${input.envSnap.deadLoopbackProxyPorts.join(", ")})`
        : "";
    m5Findings.push({
      id: "proxy-env-dead-or-conflict",
      moduleId: "env_hygiene",
      severity: "warn",
      pointsDeducted: 3,
      triggersRedline: false,
      title: {
        zh: `代理环境变量 (${input.envSnap.proxyEnvVarsPresent.join(", ")}) 指向未监听死端口或异常代理地址${deadPortsStr}`,
        en: `Proxy env var (${input.envSnap.proxyEnvVarsPresent.join(", ")}) points to an inactive port or conflicting endpoint${deadPortsStr}`,
      },
      detail: {
        zh: "在 Shell 或 `~/.claude/settings.json` 中配置的代理端口当前未处于本地监听状态，会导致子进程连接失败或回退异常。",
        en: "Configured proxy endpoint in shell or `~/.claude/settings.json` is not actively listening on loopback.",
      },
      remediation: {
        zh: "核对 `HTTP_PROXY` / `HTTPS_PROXY` 是否填写了已关闭旧代理软件的残留端口号。",
        en: "Verify `HTTP_PROXY` / `HTTPS_PROXY` in your shell or `settings.json` matches an active proxy port.",
      },
    });
  } else if (input.envSnap.dedicatedLoopbackProxyPorts.length > 0) {
    const portsStr = input.envSnap.dedicatedLoopbackProxyPorts.map((p) => `127.0.0.1:${p}`).join(", ");
    m5Findings.push({
      id: "proxy-env-dedicated-listener-ok",
      moduleId: "env_hygiene",
      severity: "info",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `已识别 Claude 专属本地代理端口配置 (${portsStr} · 监听正常)`,
        en: `Recognized active local proxy listener for Claude (${portsStr})`,
      },
      detail: {
        zh: `配置来源：${input.envSnap.proxyEnvVarsPresent.join(", ")}。已核实该回环端口属于本机活跃代理监听器（如 Clash mixed-port 或独立 listeners 端口）。`,
        en: `Configured via ${input.envSnap.proxyEnvVarsPresent.join(", ")} and verified actively listening locally.`,
      },
      remediation: {
        zh: "确保该专属入站端口在代理规则中指向与桌面端完全相同的固定海外节点即可。",
        en: "Ensure this listener port routes to the exact same static overseas exit as TUN.",
      },
    });
  }

  if (input.envSnap.riskyReverseProxies.length > 0) {
    m5Deduct += 6;
    m5Findings.push({
      id: "risky-local-relay",
      moduleId: "env_hygiene",
      severity: "fail",
      pointsDeducted: 6,
      triggersRedline: false,
      title: {
        zh: `发现高危本地反代号池进程：${input.envSnap.riskyReverseProxies.join(", ")}`,
        en: `Detected high-risk local reverse-proxy relay process: ${input.envSnap.riskyReverseProxies.join(", ")}`,
      },
      detail: {
        zh: "此类工具通过拦截并伪造请求头/TLS 特征将个人订阅转为 API，极易触发 Anthropic 服务端反蒸馏与异常并发分类器导致封号。",
        en: "Local subscription-to-API reverse proxies spoof headers/TLS and frequently trigger server-side behavioral classifiers.",
      },
      remediation: {
        zh: "多账号切换请直接修改 `~/.claude/settings.json` 中的官方 setup-token 或使用纯改配置工具，切勿过本地反代层。",
        en: "Switch accounts natively via `settings.json` setup-tokens rather than local reverse-proxy servers.",
      },
    });
  }

  if (input.envSnap.suspiciousSettingsEnvKeys.length > 0) {
    m5Deduct += 3;
    m5Findings.push({
      id: "settings-env-backup-leak",
      moduleId: "env_hygiene",
      severity: "warn",
      pointsDeducted: 3,
      triggersRedline: false,
      title: {
        zh: "`~/.claude/settings.json` 的 `env` 对象内疑似混入备用账号字段",
        en: "Suspicious backup account keys found inside `env` block of `~/.claude/settings.json`",
      },
      detail: {
        zh: `检测到键名：${input.envSnap.suspiciousSettingsEnvKeys.join(", ")}（未读取键值）。写在 env 对象内的所有字段都会被导出为子进程环境变量！`,
        en: `Keys inside \`env\` (${input.envSnap.suspiciousSettingsEnvKeys.join(", ")}) are exported to every spawned child process.`,
      },
      remediation: {
        zh: "备用账号备忘字段（如 _ACCOUNT_2）务必放在 JSON 最外层顶层对象中，不要放在 `env` 内部。",
        en: "Move memo keys outside the `env` block to the top-level JSON object.",
      },
    });
  }

  if (input.envSnap.mcpServerCount > 0) {
    m5Findings.push({
      id: "mcp-subprocess-note",
      moduleId: "env_hygiene",
      severity: "info",
      pointsDeducted: 0,
      triggersRedline: false,
      title: {
        zh: `检测到 ${input.envSnap.mcpServerCount} 个本地 MCP Server 配置 (${input.envSnap.mcpCommands.join(", ") || "stdio"})`,
        en: `Detected ${input.envSnap.mcpServerCount} configured MCP Server(s) (${input.envSnap.mcpCommands.join(", ") || "stdio"})`,
      },
      detail: {
        zh: "外部拉起的 npx / uvx / python 子进程不携带 Anthropic 签名，必须依赖 TUN 虚拟网卡确保其外网请求不走本地宽带。",
        en: "Spawned MCP child processes (`npx`/`uvx`/`python`) rely on TUN routing since they don't carry Anthropic code signatures.",
      },
      remediation: {
        zh: "保持 TUN 开启即可自动保护所有 MCP 子进程流量。",
        en: "Keep TUN enabled so MCP child traffic stays routed safely.",
      },
    });
  }

  const modules: ModuleScore[] = [
    buildModuleScore(
      "egress_matrix",
      { zh: "暗桩域名矩阵与出口同源", en: "Stealth Domain Matrix & Exit" },
      30,
      m1Deduct,
      m1Findings
    ),
    buildModuleScore(
      "network_stack",
      { zh: "TUN 虚拟网卡、DNS 与双栈", en: "TUN, DNS & IPv6 Stack" },
      20,
      m2Deduct,
      m2Findings
    ),
    buildModuleScore(
      "browser_sync",
      { zh: "登录浏览器同源与 WebRTC", en: "Browser OAuth Sync & WebRTC" },
      20,
      m3Deduct,
      m3Findings
    ),
    buildModuleScore(
      "app_footprint",
      { zh: "全家桶入口与防火墙焊死度", en: "App Binaries & Firewall Lock" },
      20,
      m4Deduct,
      m4Findings
    ),
    buildModuleScore(
      "env_hygiene",
      { zh: "系统环境暗标与残留卫生", en: "Host Fingerprint & Hygiene" },
      10,
      m5Deduct,
      m5Findings
    ),
  ];

  if (input.killSwitchDrill.executed && input.killSwitchDrill.verdict === "leaked") {
    const leakedCC = input.killSwitchDrill.systemProbeLeakedCountry || "ISP";
    if (RESTRICTED_REGIONS.has(leakedCC) || leakedCC === "ISP") {
      addRedline({
        zh: `断网防漏演练实测未通过：关闭代理后暴露真实网络 (${input.killSwitchDrill.systemProbeLeakedIpMasked || "直连连通"} · ${leakedCC}) 且无防火墙拦截 Claude`,
        en: `Kill-Switch Drill Failed: Traffic fell back directly to ${input.killSwitchDrill.systemProbeLeakedIpMasked || "ISP"} (${leakedCC}) when proxy closed`,
      });
    }
  }

  const rawScore = modules.reduce((sum, m) => sum + m.earnedPoints, 0);
  const redlineTriggered = redlineReasons.length > 0;
  const finalScore = redlineTriggered ? Math.min(rawScore, 45) : rawScore;

  const killSwitchVerifiedBadge =
    !redlineTriggered &&
    finalScore >= 85 &&
    input.killSwitchDrill.executed &&
    (input.killSwitchDrill.verdict === "global_blocked" ||
      input.killSwitchDrill.verdict === "app_firewall_locked");

  let grade: Grade;
  if (redlineTriggered || finalScore <= 45) {
    grade = "F";
  } else if (killSwitchVerifiedBadge) {
    grade = "S+";
  } else if (finalScore >= 90) {
    grade = "A+";
  } else if (finalScore >= 80) {
    grade = "A";
  } else if (finalScore >= 70) {
    grade = "B";
  } else if (finalScore >= 60) {
    grade = "C";
  } else {
    grade = "D";
  }

  return {
    modules,
    rawScore,
    finalScore,
    grade,
    redlineTriggered,
    redlineReasons,
    killSwitchVerifiedBadge,
  };
}

function buildModuleScore(
  id: ModuleScore["id"],
  name: BilingualText,
  maxPoints: number,
  deducted: number,
  findings: CheckFinding[]
): ModuleScore {
  const earnedPoints = Math.max(0, maxPoints - deducted);
  const hasCritical = findings.some((f) => f.severity === "critical" || f.triggersRedline);
  const hasWarnOrFail = findings.some((f) => f.severity === "fail" || f.severity === "warn");

  const status: ModuleScore["status"] = hasCritical ? "critical" : hasWarnOrFail ? "warn" : "pass";
  const summary: BilingualText =
    status === "pass"
      ? { zh: "全部关键指标通过", en: "All key checks passed" }
      : status === "critical"
        ? { zh: "发现高危泄漏或双 IP 冲突红线", en: "Critical leak or dual-IP conflict detected" }
        : { zh: "存在潜在分流或环境风险项", en: "Potential routing or environment risks found" };

  return {
    id,
    name,
    maxPoints,
    earnedPoints,
    status,
    summary,
    findings,
  };
}

import type { DomainTarget } from "../types/report.js";

/**
 * 核心与第三方暗桩域名探针矩阵（27 个实抓目标）
 * - officialAnthropic = true 的域名在默认模式下执行「100% 纯本地零发包核验」（仅查系统 DNS + 内核路由表 + 静态规则），不向 Anthropic 发送任何数据包。
 */
export const DOMAIN_MATRIX: DomainTarget[] = [
  // 1. Anthropic 核心主站与内容接口
  {
    host: "claude.ai",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Claude 网页与桌面主站", en: "Claude Web & Desktop Main" },
    riskNote: {
      zh: "桌面端与网页会话主入口，必须锁定固定海外出口",
      en: "Primary web & desktop session endpoint; must stay on fixed supported exit",
    },
  },
  {
    host: "api.anthropic.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Claude Code / API 推理接口", en: "Claude Code & API Inference" },
    riskNote: {
      zh: "终端 Claude Code 核心高频通道，未开 TUN 时极易直连裸奔",
      en: "Core CLI inference endpoint; leaks ISP IP immediately if TUN is off",
    },
  },
  {
    host: "assets-proxy.anthropic.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Claude 桌面端静态资源代理", en: "Anthropic Assets Proxy" },
    riskNote: {
      zh: "桌面端真机抓包高频触发的资源代理域，漏配会暴露直连出口",
      en: "Desktop static/UI asset proxy observed in live captures; must align with main exit",
    },
  },
  {
    host: "claude.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Claude 品牌与文档跳转域", en: "Claude Brand & Docs Redirect" },
    riskNote: {
      zh: "登录跳转与静态资源关联域",
      en: "Associated redirect & docs domain",
    },
  },
  {
    host: "claudeusercontent.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Artifacts 沙盒与附件渲染域", en: "Artifacts & User Content Sandbox" },
    riskNote: {
      zh: "预览 Artifacts 或上传图片时触发，常被精简分流规则遗漏",
      en: "Triggered when rendering Artifacts/uploads; often missed in minimal rule sets",
    },
  },
  {
    host: "bridge.claudeusercontent.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "Claude 桌面沙盒通信桥接域", en: "Claude Sandbox Bridge" },
    riskNote: {
      zh: "桌面端与沙盒内容容器的桥接子域，需与主站走同一出口",
      en: "Desktop sandbox bridge subdomain captured in live traffic",
    },
  },
  {
    host: "claudemcpcontent.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "MCP 远程连接器内容域", en: "MCP Connector Content" },
    riskNote: {
      zh: "使用远程 MCP 工具时加载，漏配会暴露第二个地区 IP",
      en: "Used by MCP connectors; missing rules expose secondary regional IP",
    },
  },
  {
    host: "platform.claude.com",
    category: "core",
    officialAnthropic: true,
    label: { zh: "开发者控制台与 OAuth 授权", en: "Developer Platform & OAuth" },
    riskNote: {
      zh: "Claude Code 首次 OAuth 授权与 API 账单页面",
      en: "Used during CLI OAuth handshake and console billing",
    },
  },

  // 2. Statsig 动态风控与灰度开关（远程下发检测逻辑的核心通道）
  {
    host: "statsig.anthropic.com",
    category: "feature_gate",
    officialAnthropic: true,
    label: { zh: "Anthropic Statsig 遥测网关", en: "Anthropic Statsig Telemetry" },
    riskNote: {
      zh: "上报客户端特征与会话画像的第一方遥测代理域",
      en: "First-party Statsig proxy reporting client traits and session context",
    },
  },
  {
    host: "featuregates.org",
    category: "feature_gate",
    officialAnthropic: false,
    label: { zh: "Statsig 动态灰度风控开关", en: "Statsig Feature Gates" },
    riskNote: {
      zh: "客户端动态拉取云端风控开关，国内未被墙，直连即暴露真实 IP",
      en: "Fetches dynamic risk flags; reachable directly in CN if not proxied",
    },
  },
  {
    host: "prodregistryv2.org",
    category: "feature_gate",
    officialAnthropic: false,
    label: { zh: "Statsig 注册与实验分发域", en: "Statsig Registry v2" },
    riskNote: {
      zh: "极隐蔽的无品牌第三方域名，大量通用代理规则未收录",
      en: "Unbranded Statsig domain frequently missed by generic proxy lists",
    },
  },

  // 3. Sentry & Datadog 崩溃与实时日志上报（2026 封号漏网头号重灾区）
  {
    host: "o1158394.ingest.us.sentry.io",
    category: "telemetry",
    officialAnthropic: false,
    label: { zh: "Anthropic 专属 Sentry 收集器", en: "Anthropic Sentry Ingest" },
    riskNote: {
      zh: "应用启动瞬间（甚至登录前）即上报系统时区、语言与崩溃上下文",
      en: "Fires at app launch with host timezone, locale, and runtime metadata",
    },
  },
  {
    host: "us.sentry.io",
    category: "telemetry",
    officialAnthropic: false,
    label: { zh: "Sentry 美区错误追踪节点", en: "Sentry US Regional Endpoint" },
    riskNote: {
      zh: "国内直连秒通！一旦未走代理或断梯子重连，瞬间上报国内真实 IP",
      en: "Directly reachable without GFW block; leaks real ISP IP on fallback",
    },
  },
  {
    host: "us5.datadoghq.com",
    category: "telemetry",
    officialAnthropic: false,
    label: { zh: "Datadog US5 监控主域", en: "Datadog US5 Core Telemetry" },
    riskNote: {
      zh: "近期大量封号复盘揪出的漏网域名，不在传统 AI 规则集内",
      en: "Major 2026 leak vector; missing from older AI domain rule lists",
    },
  },
  {
    host: "http-intake.logs.us5.datadoghq.com",
    category: "telemetry",
    officialAnthropic: false,
    label: { zh: "Datadog 客户端日志收集入口", en: "Datadog HTTP Logs Intake" },
    riskNote: {
      zh: "客户端后台批量上报运行日志，直连会导致双地区 IP 同时在线",
      en: "Ships client logs in background; direct routing causes dual-IP conflict",
    },
  },
  {
    host: "browser-intake-us5-datadoghq.com",
    category: "telemetry",
    officialAnthropic: false,
    label: { zh: "Datadog 独立横杠域名（防漏重点）", en: "Datadog Hyphenated RUM Domain" },
    riskNote: {
      zh: "注意它是连字符 -datadoghq.com 而非子域名，只配 *.datadoghq.com 照样漏！",
      en: "Uses hyphen (-datadoghq.com), so wildcard *.datadoghq.com rules MISS IT!",
    },
  },

  // 4. Sift 反欺诈 / Stripe 支付 / Intercom 客服
  {
    host: "siftscience.com",
    category: "antifraud_billing",
    officialAnthropic: false,
    label: { zh: "Sift 账号与支付反欺诈引擎", en: "Sift Anti-Fraud Scoring" },
    riskNote: {
      zh: "开号、绑卡与升级 Pro/Max 时评估欺诈分，漏配极易触发 KYC 或拒付",
      en: "Evaluates fraud score during signup & billing; leaks trigger KYC or holds",
    },
  },
  {
    host: "js.stripe.com",
    category: "antifraud_billing",
    officialAnthropic: false,
    label: { zh: "Stripe 支付环境指纹脚本", en: "Stripe Payment Fingerprinting" },
    riskNote: {
      zh: "网页订阅收银台加载，若被办公白名单直连会导致支付 IP 与账号 IP 冲突",
      en: "Stripe checkout telemetry; direct routing mismatches billing vs session IP",
    },
  },
  {
    host: "r.stripe.com",
    category: "antifraud_billing",
    officialAnthropic: false,
    label: { zh: "Stripe 风控遥测信标接口", en: "Stripe Risk Beacon" },
    riskNote: {
      zh: "静默上报设备与网络环境信标用于反盗刷风控",
      en: "Silent risk telemetry beacon for Stripe Radar",
    },
  },
  {
    host: "api-iam.intercom.io",
    category: "antifraud_billing",
    officialAnthropic: false,
    label: { zh: "Intercom 客服与用户身份关联", en: "Intercom Identity & Support API" },
    riskNote: {
      zh: "登录后后台自动握手同步用户会话与申诉组件",
      en: "Syncs logged-in user session in background for support widget",
    },
  },
  {
    host: "nexus-websocket-a.intercom.io",
    category: "antifraud_billing",
    officialAnthropic: false,
    label: { zh: "Intercom 长连接实时通道", en: "Intercom WebSocket Stream" },
    riskNote: {
      zh: "长连接 WebSocket，代理闪断重连时极易暴露底层网卡 IP",
      en: "Persistent WebSocket; reconnects during proxy hiccups expose ISP IP",
    },
  },

  // 5. Cloudflare 验证 / Google 登录统计推送 / WorkOS
  {
    host: "challenges.cloudflare.com",
    category: "auth_infra",
    officialAnthropic: false,
    label: { zh: "Cloudflare Turnstile 人机盾", en: "Cloudflare Turnstile Challenge" },
    riskNote: {
      zh: "登录与防爬验证核心域，若与主站出口不一致会无限循环弹盾",
      en: "Turnstile verification; IP mismatch with claude.ai causes challenge loops",
    },
  },
  {
    host: "accounts.google.com",
    category: "auth_infra",
    officialAnthropic: false,
    label: { zh: "Google OAuth 快捷登录域", en: "Google OAuth Sign-In" },
    riskNote: {
      zh: "用 Google 登录 Claude 时的跳转源，需与 Claude 保持同国出口",
      en: "Google SSO provider; region mismatch during OAuth raises risk score",
    },
  },
  {
    host: "googletagmanager.com",
    category: "auth_infra",
    officialAnthropic: false,
    label: { zh: "Google 统计标签（白名单搭便车高发）", en: "Google Tag Manager" },
    riskNote: {
      zh: "部分国内加速规则误将其放行或切到港台节点，导致跨区暴露",
      en: "Sometimes routed to HK/TW speed groups in split rules",
    },
  },
  {
    host: "fcmtoken.googleapis.com",
    category: "auth_infra",
    officialAnthropic: false,
    label: { zh: "Chromium / Electron 推送令牌服务", en: "FCM Push Token Endpoint" },
    riskNote: {
      zh: "Electron 桌面端底层 Chromium 组件常驻请求",
      en: "Background Chromium/Electron push registration service",
    },
  },
  {
    host: "workos.com",
    category: "auth_infra",
    officialAnthropic: false,
    label: { zh: "WorkOS 企业 SSO 与 MCP 鉴权", en: "WorkOS SSO & MCP AuthKit" },
    riskNote: {
      zh: "Claude Team/Enterprise 及部分官方远程 MCP 连接器鉴权依赖",
      en: "Used for SSO and remote MCP OAuth handshakes",
    },
  },

  // 6. 纯 IP 兜底路由探针（防硬编码 IP 如 34.8.0.0/16 绕过域名规则）
  {
    host: "1.1.1.1",
    category: "raw_ip",
    officialAnthropic: false,
    label: { zh: "无域名纯 IP 流量兜底探针", en: "Raw IP Fallback Route Probe" },
    riskNote: {
      zh: "检验客户端不走 DNS 直接连海外 IP（如 34.8.0.0/16）时是否仍受 TUN 保护",
      en: "Verifies hardcoded IP connections without DNS still route via TUN",
    },
  },
];

/**
 * Anthropic 明确限制或高危不支持的国家/地区代码（ISO-3166-1 alpha-2）
 */
export const RESTRICTED_REGIONS = new Set([
  "CN", // 中国大陆
  "HK", // 中国香港
  "MO", // 中国澳门
  "RU", // 俄罗斯
  "BY", // 白俄罗斯
  "IR", // 伊朗
  "KP", // 朝鲜
  "SY", // 叙利亚
  "CU", // 古巴
]);

export const REGION_NAMES: Record<string, { zh: string; en: string }> = {
  US: { zh: "美国", en: "United States" },
  SG: { zh: "新加坡", en: "Singapore" },
  JP: { zh: "日本", en: "Japan" },
  KR: { zh: "韩国", en: "South Korea" },
  TW: { zh: "中国台湾", en: "Taiwan" },
  GB: { zh: "英国", en: "United Kingdom" },
  DE: { zh: "德国", en: "Germany" },
  CA: { zh: "加拿大", en: "Canada" },
  AU: { zh: "澳大利亚", en: "Australia" },
  NL: { zh: "荷兰", en: "Netherlands" },
  FR: { zh: "法国", en: "France" },
  CH: { zh: "瑞士", en: "Switzerland" },
  SE: { zh: "瑞典", en: "Sweden" },
  IN: { zh: "印度", en: "India" },
  CN: { zh: "中国大陆 (受限高危)", en: "Mainland China (Restricted)" },
  HK: { zh: "中国香港 (不支持地区)", en: "Hong Kong (Unsupported)" },
  MO: { zh: "中国澳门 (不支持地区)", en: "Macau (Unsupported)" },
  RU: { zh: "俄罗斯 (受限地区)", en: "Russia (Restricted)" },
};

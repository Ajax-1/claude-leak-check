import { createHash } from "node:crypto";
import { homedir } from "node:os";
import type { ProxyStaticAudit } from "../types/report.js";

const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * 判断是否为 Fake-IP 地址段 (RFC 2544: 198.18.0.0/15)
 */
export function isFakeIpv4(ip: string): boolean {
  const m = IPV4_REGEX.exec(ip.trim());
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 198 && (b === 18 || b === 19);
}

/**
 * 判断是否为局域网/回环私有 IPv4
 */
export function isPrivateOrLoopbackIpv4(ip: string): boolean {
  const m = IPV4_REGEX.exec(ip.trim());
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Tailscale
  return false;
}

/**
 * 判断 IPv6 是否属于中国大陆三大运营商常见公网前缀 (240e 电信 / 2408 联通 / 2409 移动 / 240c 教育网等)
 */
export function isMainlandCarrierIpv6(ip: string): boolean {
  const clean = ip.trim().toLowerCase().split("%")[0];
  return (
    clean.startsWith("240e:") ||
    clean.startsWith("2408:") ||
    clean.startsWith("2409:") ||
    clean.startsWith("240c:") ||
    clean.startsWith("2402:4e00") ||
    clean.startsWith("2400:3200")
  );
}

/**
 * 判断是否为全局可路由公网 IPv6 (2000::/3)
 */
export function isGlobalUnicastIpv6(ip: string): boolean {
  const clean = ip.trim().toLowerCase().split("%")[0];
  if (!clean.includes(":")) return false;
  if (
    clean === "::1" ||
    clean.startsWith("fe80:") ||
    clean.startsWith("fc") ||
    clean.startsWith("fd") ||
    clean.startsWith("ff") ||
    clean.startsWith("100:")
  ) {
    return false;
  }
  const firstChar = clean[0];
  return firstChar === "2" || firstChar === "3";
}

/**
 * 对任意 IPv4 / IPv6 进行强脱敏打码，方便直接晒图分享
 * 例：198.51.100.42 -> 198.51.*.*
 * 例：198.18.0.45 -> 198.18.*.* (Fake-IP)
 * 例：240e:3b7:3271:88a0::1 -> 240e:3b7:*:*::*
 */
export function maskIp(ip: string): string {
  const trimmed = ip.trim().split("%")[0];
  const m4 = IPV4_REGEX.exec(trimmed);
  if (m4) {
    if (trimmed === "127.0.0.1" || trimmed === "1.1.1.1" || trimmed === "8.8.8.8" || trimmed === "100.100.100.100") {
      return trimmed;
    }
    const base = `${m4[1]}.${m4[2]}.*.*`;
    return isFakeIpv4(trimmed) ? `${base} (Fake-IP)` : base;
  }
  if (trimmed.includes(":")) {
    if (trimmed === "::1") return "::1";
    const parts = trimmed.split(":").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[0]}:${parts[1]}:*:*::*`;
    }
    return `${parts[0] || "ipv6"}::*`;
  }
  return "[REDACTED]";
}

/**
 * 计算单向加盐短哈希，仅用于本地判断“终端出口 IP === 浏览器出口 IP”是否严格一致，不暴露原 IP
 */
export function hashIpForComparison(ip: string, sessionSalt: string): string {
  return createHash("sha256")
    .update(`${sessionSalt}:${ip.trim().toLowerCase()}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * 脱敏本地路径，将当前系统用户名目录替换为 ~
 */
export function sanitizePath(rawPath: string): string {
  const home = homedir();
  let out = rawPath;
  if (home && out.startsWith(home)) {
    out = `~${out.slice(home.length)}`;
  }
  out = out.replace(/^\/Users\/[^/]+/, "~");
  out = out.replace(/^[A-Za-z]:\\Users\\[^\\]+/, "~");
  return out;
}

/**
 * 脱敏任意文本中可能出现的 IPv4 / IPv6 / 用户名路径
 */
export function scrubFreeText(input: string): string {
  let text = sanitizePath(input);
  text = text.replace(/\/Users\/[^/\s"']+/g, "~");
  text = text.replace(/[A-Za-z]:\\Users\\[^\\\s"']+/g, "~");
  text = text.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (full) => maskIp(full));
  return text;
}

const SENSITIVE_TOP_LEVEL_YAML_KEYS = new Set([
  "proxies",
  "proxy-providers",
  "secret",
  "authentication",
  "external-controller-secret",
  "tunnels",
  "sub-urls",
]);

const TOP_LEVEL_PORT_KEYS = new Set([
  "port",
  "socks-port",
  "mixed-port",
  "redir-port",
  "tproxy-port",
]);

const RESTRICTED_GROUP_NODE_KEYWORDS =
  /(香港|澳门|中国|大陆|\bHK\b|\bHong\s*Kong\b|\bMO\b|\bMacau\b|\bCN\b|\bChina\b|俄罗斯|\bRU\b)/i;

const STEALTH_DOMAIN_KEYWORDS =
  /(anthropic|claude|statsig|featuregates|prodregistryv2|sentry\.io|datadoghq|browser-intake-.*datadoghq|siftscience|stripe\.com|intercom\.io)/i;

const CLAUDE_GEOSITE_OR_PROCESS_KEYWORDS = /(anthropic|claude)/i;

const RULE_TRAILING_OPTIONS = new Set([
  "NO-RESOLVE",
  "SRC",
  "PRE-MATCHING",
  "EXTENDED-MATCHING",
]);

interface InternalProxyGroup {
  name: string;
  type: string;
  hasDirect: boolean;
  hasRestricted: boolean;
  rawMembers: string[];
}

/**
 * 严格白名单状态机解析 Clash / Mihomo YAML 结构元数据
 * 铁律：遇到 proxies / proxy-providers / secret / authentication 等敏感顶级块立即物理跳过整块，
 * 绝不提取、绝不解析、绝不保留任何服务器 IP、域名、端口、密码、UUID 或订阅 URL！
 */
export function parseClashYamlMetadataSafely(
  yamlContent: string,
  detectedClients: string[] = []
): ProxyStaticAudit {
  const result: ProxyStaticAudit = {
    detectedClients,
    configInspected: true,
    mode: "unknown",
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

  type Section =
    | "root"
    | "skip_sensitive"
    | "listeners"
    | "tun"
    | "dns"
    | "proxy-groups"
    | "rules"
    | "other";

  let currentSection: Section = "root";
  let currentGroup: InternalProxyGroup | null = null;
  let groupDashIndent = -1;
  let inProxiesListInsideGroup = false;

  const groups: InternalProxyGroup[] = [];
  const claudeDirectTargetNames = new Set<string>();
  const listenerPortsSet = new Set<number>();

  const addValidPort = (rawVal: string): void => {
    const n = Number(unquote(rawVal));
    if (Number.isInteger(n) && n > 0 && n <= 65535) {
      listenerPortsSet.add(n);
    }
  };

  const lines = yamlContent.split(/\r?\n/);
  for (const rawLine of lines) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith("#")) {
      continue;
    }

    const indentMatch = /^(\s*)/.exec(rawLine);
    const indent = indentMatch ? indentMatch[1].length : 0;
    const trimmed = rawLine.trim();

    // 顶级键 (缩进为 0 且包含冒号，非列表项)
    if (indent === 0 && !trimmed.startsWith("-") && trimmed.includes(":")) {
      const colonIdx = trimmed.indexOf(":");
      const topKey = trimmed.slice(0, colonIdx).trim().toLowerCase();
      const topVal = stripYamlComment(trimmed.slice(colonIdx + 1));

      inProxiesListInsideGroup = false;
      currentGroup = null;
      groupDashIndent = -1;

      if (SENSITIVE_TOP_LEVEL_YAML_KEYS.has(topKey)) {
        currentSection = "skip_sensitive";
        continue;
      }

      if (TOP_LEVEL_PORT_KEYS.has(topKey)) {
        addValidPort(topVal);
        currentSection = "root";
        continue;
      }

      if (topKey === "listeners") {
        currentSection = "listeners";
        continue;
      }

      if (topKey === "mode") {
        const m = unquote(topVal).toLowerCase();
        if (m === "rule" || m === "global" || m === "direct") {
          result.mode = m;
        }
        currentSection = "root";
        continue;
      }

      if (topKey === "ipv6") {
        const b = parseBool(topVal);
        if (b !== undefined) result.ipv6Enabled = b;
        currentSection = "root";
        continue;
      }

      if (topKey === "tun") {
        currentSection = "tun";
        continue;
      }
      if (topKey === "dns") {
        currentSection = "dns";
        continue;
      }
      if (topKey === "proxy-groups") {
        currentSection = "proxy-groups";
        continue;
      }
      if (topKey === "rules") {
        currentSection = "rules";
        continue;
      }

      currentSection = "other";
      continue;
    }

    if (currentSection === "skip_sensitive" || currentSection === "other") {
      continue;
    }

    if (currentSection === "listeners") {
      // 仅安全提取本地监听器的 port 整数（忽略 users/password 等任何其他字段）
      const inlinePort = /\bport\s*:\s*(\d{1,5})\b/i.exec(trimmed);
      if (inlinePort) {
        addValidPort(inlinePort[1]);
        continue;
      }
      const kv = splitKeyVal(trimmed);
      if (kv && kv.key === "port") {
        addValidPort(kv.val);
      }
      continue;
    }

    if (currentSection === "tun") {
      const kv = splitKeyVal(trimmed);
      if (!kv) continue;
      if (kv.key === "enable") {
        const b = parseBool(kv.val);
        if (b !== undefined) result.tunEnabled = b;
      } else if (kv.key === "stack") {
        result.tunStack = unquote(kv.val).slice(0, 24);
      } else if (kv.key === "strict-route") {
        const b = parseBool(kv.val);
        if (b !== undefined) result.strictRoute = b;
      }
      continue;
    }

    if (currentSection === "dns") {
      const kv = splitKeyVal(trimmed);
      if (!kv) continue;
      if (kv.key === "enable") {
        const b = parseBool(kv.val);
        if (b !== undefined) result.dnsEnabled = b;
      } else if (kv.key === "enhanced-mode") {
        result.enhancedMode = unquote(kv.val).toLowerCase().slice(0, 24);
      } else if (kv.key === "ipv6") {
        const b = parseBool(kv.val);
        if (b !== undefined) result.dnsIpv6Enabled = b;
      }
      continue;
    }

    if (currentSection === "proxy-groups") {
      // 单行内联对象格式: - { name: Proxy, type: select, proxies: [US, DIRECT] }
      if (trimmed.startsWith("-") && trimmed.includes("{") && trimmed.includes("}")) {
        const inlineGroup = parseInlineProxyGroup(trimmed);
        if (inlineGroup) {
          groups.push(inlineGroup);
        }
        currentGroup = null;
        inProxiesListInsideGroup = false;
        continue;
      }

      // 新策略组起始项: 匹配 `- name: xxx` 或与首个策略组同缩进层级的 `-`
      const isNewGroupItem =
        trimmed.startsWith("-") &&
        (/^-\s*name\s*:/i.test(trimmed) || groupDashIndent === -1 || indent <= groupDashIndent);

      if (isNewGroupItem) {
        const afterDash = trimmed.slice(1).trim();
        groupDashIndent = indent;
        inProxiesListInsideGroup = false;
        currentGroup = {
          name: "",
          type: "unknown",
          hasDirect: false,
          hasRestricted: false,
          rawMembers: [],
        };
        groups.push(currentGroup);
        if (afterDash) {
          const kv = splitKeyVal(afterDash);
          if (kv) applyGroupKeyVal(currentGroup, kv.key, kv.val);
        }
        continue;
      }

      if (!currentGroup) continue;

      if (trimmed.startsWith("proxies:") || (trimmed.startsWith("- ") === false && /^proxies\s*:/.test(trimmed))) {
        inProxiesListInsideGroup = true;
        const inlineMatch = /proxies\s*:\s*\[([^\]]*)\]/i.exec(trimmed);
        if (inlineMatch) {
          appendGroupMembers(currentGroup, inlineMatch[1].split(","));
          inProxiesListInsideGroup = false;
        }
        continue;
      }

      if (inProxiesListInsideGroup) {
        if (trimmed.startsWith("-")) {
          const item = unquote(stripYamlComment(trimmed.slice(1)));
          appendGroupMembers(currentGroup, [item]);
          continue;
        }
        // 遇到同级其他键（如 url:, interval:, type:）退出 proxies 列表模式
        if (trimmed.includes(":")) {
          inProxiesListInsideGroup = false;
        }
      }

      if (!inProxiesListInsideGroup) {
        const kv = splitKeyVal(trimmed);
        if (kv) {
          applyGroupKeyVal(currentGroup, kv.key, kv.val);
        }
      }
      continue;
    }

    if (currentSection === "rules") {
      if (trimmed.startsWith("-")) {
        const ruleBody = unquote(stripYamlComment(trimmed.slice(1)));
        if (!ruleBody) continue;
        result.ruleCount += 1;
        const parts = ruleBody.split(",").map((s) => s.trim());
        const ruleType = (parts[0] || "").toUpperCase();

        if (ruleType === "MATCH" || ruleType === "FINAL") {
          const target = parts[1] || "";
          if (target.toUpperCase() === "DIRECT") {
            result.finalMatchIsDirect = true;
          } else if (target && target.toUpperCase() !== "REJECT") {
            claudeDirectTargetNames.add(unquote(target));
          }
          continue;
        }

        if (parts.length >= 3) {
          const pattern = parts[1] || "";
          const target = extractRulePolicyTarget(parts);
          const targetUpper = target.toUpperCase();

          // 1. 域名或规则集命中 Claude / 遥测暗桩
          if (STEALTH_DOMAIN_KEYWORDS.test(pattern)) {
            if (targetUpper === "DIRECT") {
              result.hasStealthDomainDirectRule = true;
            } else if (target && targetUpper !== "REJECT") {
              claudeDirectTargetNames.add(target);
            }
          } else if (
            (ruleType.startsWith("PROCESS-") && CLAUDE_GEOSITE_OR_PROCESS_KEYWORDS.test(pattern)) ||
            (ruleType === "GEOSITE" && /(anthropic|claude|!cn|geolocation-!cn)/i.test(pattern)) ||
            ruleType === "IN-PORT" ||
            (ruleType === "IN-NAME" && /(claude|anthropic|ai)/i.test(pattern))
          ) {
            // 2. 进程路径规则 (如 PROCESS-PATH-REGEX 匹配 Claude)、非中国 Geosite、以及专属入站端口规则
            if (ruleType.startsWith("PROCESS-") && targetUpper === "DIRECT") {
              result.hasStealthDomainDirectRule = true;
            } else if (target && targetUpper !== "DIRECT" && targetUpper !== "REJECT") {
              claudeDirectTargetNames.add(target);
            }
          }
        }
      }
    }
  }

  result.localListenerPorts = [...listenerPortsSet].sort((a, b) => a - b);

  // 建立策略组索引并仅针对承载 Claude 流量的目标组（含嵌套引用的子策略组）执行 BFS 风险评估
  const groupByName = new Map<string, InternalProxyGroup>();
  for (const g of groups) {
    if (g.name) groupByName.set(g.name, g);
  }

  if (result.mode === "global" && groupByName.has("GLOBAL")) {
    claudeDirectTargetNames.add("GLOBAL");
  }

  const visitedGroups = new Set<string>();
  const queue = [...claudeDirectTargetNames];

  while (queue.length > 0) {
    const gName = queue.shift()!;
    if (visitedGroups.has(gName)) continue;
    const grp = groupByName.get(gName);
    if (!grp) continue; // 若成员是普通节点名而非策略组名，直接忽略，绝不记录或导出节点名称！

    visitedGroups.add(gName);
    const safeGroupName = scrubFreeText(grp.name).slice(0, 48);
    if (!result.claudeTargetGroups.includes(safeGroupName)) {
      result.claudeTargetGroups.push(safeGroupName);
    }

    const isAutoSwitchGroup =
      grp.type === "url-test" || grp.type === "fallback" || grp.type === "load-balance";

    if (grp.hasDirect || grp.hasRestricted) {
      if (isAutoSwitchGroup) {
        if (!result.autoFallbackRiskGroups.includes(safeGroupName)) {
          result.autoFallbackRiskGroups.push(safeGroupName);
        }
        if (grp.hasDirect) result.hasDirectInProxyGroups = true;
        if (grp.hasRestricted) result.hasRestrictedRegionInGroups = true;
      } else {
        if (!result.manualSelectCautionGroups.includes(safeGroupName)) {
          result.manualSelectCautionGroups.push(safeGroupName);
        }
      }
    }

    // 继续追踪该策略组引用的子策略组（仅当子项存在于 groupByName 中才入队）
    for (const member of grp.rawMembers) {
      if (groupByName.has(member) && !visitedGroups.has(member)) {
        queue.push(member);
      }
    }
  }

  return result;
}

function applyGroupKeyVal(group: InternalProxyGroup, key: string, val: string): void {
  if (key === "name") {
    group.name = unquote(val);
  } else if (key === "type") {
    group.type = unquote(val).toLowerCase();
  }
}

function appendGroupMembers(group: InternalProxyGroup, rawTokens: string[]): void {
  for (const raw of rawTokens) {
    const t = unquote(raw.trim());
    if (!t) continue;
    group.rawMembers.push(t);
    if (t.toUpperCase() === "DIRECT") {
      group.hasDirect = true;
    }
    if (RESTRICTED_GROUP_NODE_KEYWORDS.test(t)) {
      group.hasRestricted = true;
    }
  }
}

function parseInlineProxyGroup(line: string): InternalProxyGroup | null {
  const braceStart = line.indexOf("{");
  const braceEnd = line.lastIndexOf("}");
  if (braceStart < 0 || braceEnd <= braceStart) return null;
  const inner = line.slice(braceStart + 1, braceEnd);

  const grp: InternalProxyGroup = {
    name: "",
    type: "unknown",
    hasDirect: false,
    hasRestricted: false,
    rawMembers: [],
  };

  const nameMatch = /\bname\s*:\s*([^,}]+)/i.exec(inner);
  if (nameMatch) grp.name = unquote(nameMatch[1]);

  const typeMatch = /\btype\s*:\s*([^,}]+)/i.exec(inner);
  if (typeMatch) grp.type = unquote(typeMatch[1]).toLowerCase();

  const proxiesMatch = /\bproxies\s*:\s*\[([^\]]*)\]/i.exec(inner);
  if (proxiesMatch) {
    appendGroupMembers(grp, proxiesMatch[1].split(","));
  }

  return grp.name ? grp : null;
}

function extractRulePolicyTarget(parts: string[]): string {
  // 从末尾剔除 no-resolve 等规则修饰项，取真正的策略目标字段（通常为 parts[2]）
  let idx = parts.length - 1;
  while (idx > 2 && RULE_TRAILING_OPTIONS.has(parts[idx].toUpperCase())) {
    idx--;
  }
  return unquote(parts[2] && !RULE_TRAILING_OPTIONS.has(parts[2].toUpperCase()) ? parts[2] : parts[idx] || "");
}

function stripYamlComment(val: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < val.length; i++) {
    const c = val[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble) {
      return val.slice(0, i).trim();
    }
  }
  return val.trim();
}

function unquote(val: string): string {
  const v = val.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1).trim();
  }
  return v;
}

function splitKeyVal(line: string): { key: string; val: string } | null {
  const cleaned = line.startsWith("- ") ? line.slice(2).trim() : line;
  const idx = cleaned.indexOf(":");
  if (idx <= 0) return null;
  return {
    key: cleaned.slice(0, idx).trim().toLowerCase(),
    val: stripYamlComment(cleaned.slice(idx + 1)),
  };
}

function parseBool(val: string): boolean | undefined {
  const v = unquote(val).toLowerCase();
  if (v === "true" || v === "yes") return true;
  if (v === "false" || v === "no") return false;
  return undefined;
}

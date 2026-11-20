import { isFakeIpv4, isPrivateOrLoopbackIpv4, maskIp } from "../core/privacy.js";

export interface LuluCoverageSummary {
  totalRuleEntries: number;
  claudeRuleEntries: number;
  coversClaudeAppMain: boolean;
  coversClaudeHelpers: boolean;
  coversAppSupportClaudeCode: boolean;
  coversAnthropicSigningId: boolean;
  hasBlockActionForClaude: boolean;
  cidrMisconfiguredRules: string[];
}

interface RawLuluRule {
  key?: unknown;
  path?: unknown;
  name?: unknown;
  csInfo?: unknown;
  action?: unknown;
  endpointAddr?: unknown;
  endpointPort?: unknown;
  isDisabled?: unknown;
  isEndpointAddrRegex?: unknown;
}

/**
 * 零依赖轻量 Apple XML1 Plist 解析器（专门适配 `/usr/bin/plutil -convert xml1 -o -` 输出）
 */
export function parseAppleXmlPlist(xmlInput: string): unknown {
  // 剥离 XML 声明、DOCTYPE 与注释
  const cleaned = xmlInput
    .replace(/<\?xml[\s\S]*?\?>/gi, "")
    .replace(/<!DOCTYPE[\s\S]*?>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .trim();

  if (!cleaned) return null;

  const tokenRegex = /<(\/?)([a-zA-Z0-9_.-]+)(\s[^>]*)?(\/?)>|([^<]+)/g;
  type Token =
    | { kind: "open"; tag: string }
    | { kind: "close"; tag: string }
    | { kind: "self"; tag: string }
    | { kind: "text"; text: string };

  const tokens: Token[] = [];
  let m: RegExpExecArray | null;
  while ((m = tokenRegex.exec(cleaned)) !== null) {
    if (m[5] !== undefined) {
      tokens.push({ kind: "text", text: m[5] });
    } else {
      const isClosing = m[1] === "/";
      const tag = m[2];
      const isSelfClosing = m[4] === "/";
      if (isSelfClosing) {
        tokens.push({ kind: "self", tag });
      } else if (isClosing) {
        tokens.push({ kind: "close", tag });
      } else {
        tokens.push({ kind: "open", tag });
      }
    }
  }

  let pos = 0;

  function readTextUntilClose(expectedTag: string): string {
    let acc = "";
    while (pos < tokens.length) {
      const tk = tokens[pos++];
      if (tk.kind === "close" && tk.tag === expectedTag) {
        break;
      }
      if (tk.kind === "text") {
        acc += tk.text;
      }
    }
    return decodeXmlEntities(acc);
  }

  function parseValue(): unknown {
    while (pos < tokens.length) {
      const tk = tokens[pos++];
      if (tk.kind === "text") {
        continue; // 忽略节点间空白换行
      }
      if (tk.kind === "self") {
        if (tk.tag === "true") return true;
        if (tk.tag === "false") return false;
        if (tk.tag === "string" || tk.tag === "key" || tk.tag === "data" || tk.tag === "date") return "";
        if (tk.tag === "dict") return {};
        if (tk.tag === "array") return [];
        return null;
      }
      if (tk.kind === "open") {
        if (tk.tag === "plist") {
          const val = parseValue();
          while (pos < tokens.length) {
            const endTk = tokens[pos++];
            if (endTk.kind === "close" && endTk.tag === "plist") break;
          }
          return val;
        }
        if (tk.tag === "dict") {
          const dict: Record<string, unknown> = {};
          while (pos < tokens.length) {
            const next = tokens[pos];
            if (next.kind === "text") {
              pos++;
              continue;
            }
            if (next.kind === "close" && next.tag === "dict") {
              pos++;
              break;
            }
            // 读取 <key>
            if (next.kind === "open" && next.tag === "key") {
              pos++;
              const keyStr = readTextUntilClose("key");
              const val = parseValue();
              dict[keyStr] = val;
            } else if (next.kind === "self" && next.tag === "key") {
              pos++;
              dict[""] = parseValue();
            } else {
              pos++;
            }
          }
          return dict;
        }
        if (tk.tag === "array") {
          const arr: unknown[] = [];
          while (pos < tokens.length) {
            const next = tokens[pos];
            if (next.kind === "text") {
              pos++;
              continue;
            }
            if (next.kind === "close" && next.tag === "array") {
              pos++;
              break;
            }
            arr.push(parseValue());
          }
          return arr;
        }
        if (tk.tag === "string" || tk.tag === "key" || tk.tag === "date") {
          return readTextUntilClose(tk.tag);
        }
        if (tk.tag === "data") {
          // 跳过二进制 base64 块内容，仅保留占位标记避免占用内存
          readTextUntilClose("data");
          return "<NSData>";
        }
        if (tk.tag === "integer" || tk.tag === "real") {
          const numText = readTextUntilClose(tk.tag).trim();
          const n = Number(numText);
          return Number.isNaN(n) ? 0 : n;
        }
        if (tk.tag === "true") {
          readTextUntilClose("true");
          return true;
        }
        if (tk.tag === "false") {
          readTextUntilClose("false");
          return false;
        }
      }
      if (tk.kind === "close") {
        return null;
      }
    }
    return null;
  }

  return parseValue();
}

function decodeXmlEntities(str: string): string {
  return str
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

/**
 * 还原 NSKeyedArchiver 对象图（解引用 `$top` 与 `$objects` 中的 `CF$UID`，支持 NSDictionary / NSArray / NSSet / Rule）
 */
export function unarchiveNsKeyedPlist(parsed: unknown): unknown {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return parsed;
  }

  const root = parsed as Record<string, unknown>;
  if (root.$archiver !== "NSKeyedArchiver" || !Array.isArray(root.$objects)) {
    return parsed;
  }

  const objects = root.$objects as unknown[];
  const top = (root.$top && typeof root.$top === "object" ? root.$top : {}) as Record<string, unknown>;
  const topEntry = "root" in top ? top.root : Object.values(top)[0];
  if (topEntry === undefined) return parsed;

  const memo = new Map<number, unknown>();
  const visiting = new Set<number>();

  function resolveNode(node: unknown, depth: number): unknown {
    if (depth > 24 || node === null || node === undefined) return null;
    if (typeof node !== "object") {
      return node === "$null" ? null : node;
    }
    if (Array.isArray(node)) {
      return node.map((item) => resolveNode(item, depth + 1));
    }

    const rec = node as Record<string, unknown>;
    const keys = Object.keys(rec);

    // CF$UID 指针解引用
    if (keys.length === 1 && keys[0] === "CF$UID" && typeof rec["CF$UID"] === "number") {
      const uid = rec["CF$UID"];
      if (uid < 0 || uid >= objects.length) return null;
      const target = objects[uid];
      if (target === "$null" || target === null || target === undefined) return null;
      if (memo.has(uid)) return memo.get(uid);
      if (visiting.has(uid)) return null;

      visiting.add(uid);
      const resolved = resolveNode(target, depth + 1);
      visiting.delete(uid);
      memo.set(uid, resolved);
      return resolved;
    }

    // NSDictionary / NSMutableDictionary
    if (Array.isArray(rec["NS.keys"]) && Array.isArray(rec["NS.objects"])) {
      const nsKeys = rec["NS.keys"] as unknown[];
      const nsVals = rec["NS.objects"] as unknown[];
      const outDict: Record<string, unknown> = {};
      const len = Math.min(nsKeys.length, nsVals.length);
      for (let i = 0; i < len; i++) {
        const k = resolveNode(nsKeys[i], depth + 1);
        const v = resolveNode(nsVals[i], depth + 1);
        if (typeof k === "string" || typeof k === "number") {
          outDict[String(k)] = v;
        }
      }
      return outDict;
    }

    // NSArray / NSMutableArray / NSSet / NSMutableSet
    if (Array.isArray(rec["NS.objects"]) && !("NS.keys" in rec)) {
      return (rec["NS.objects"] as unknown[]).map((el) => resolveNode(el, depth + 1));
    }

    // NSMutableString / NSString 包装
    if (typeof rec["NS.string"] === "string") {
      return rec["NS.string"];
    }

    // 自定义归档对象（如 LuLu 的 Rule 对象）
    const outObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) {
      if (k === "$class" || k === "$classes" || k === "$classname") continue;
      outObj[k] = resolveNode(v, depth + 1);
    }
    return outObj;
  }

  return resolveNode(topEntry, 0);
}

/**
 * 纯只读解析 LuLu rules.plist（支持 `plutil -convert xml1` 输出的 XML1 NSKeyedArchiver 以及导出/导入 JSON 格式）
 * 按每个进程组下的生效 Rule 对象精确核验阻断/放行逻辑与 Fake-IP CIDR 模式
 */
export function parseLuluRules(rawInput: string): LuluCoverageSummary {
  const summary: LuluCoverageSummary = {
    totalRuleEntries: 0,
    claudeRuleEntries: 0,
    coversClaudeAppMain: false,
    coversClaudeHelpers: false,
    coversAppSupportClaudeCode: false,
    coversAnthropicSigningId: false,
    hasBlockActionForClaude: false,
    cidrMisconfiguredRules: [],
  };

  const trimmed = rawInput.trim();
  if (!trimmed) return summary;

  let rootData: unknown;
  if (trimmed.startsWith("<")) {
    const parsedXml = parseAppleXmlPlist(trimmed);
    rootData = unarchiveNsKeyedPlist(parsedXml);
  } else {
    try {
      const parsedJson = JSON.parse(trimmed);
      rootData = unarchiveNsKeyedPlist(parsedJson);
    } catch {
      return summary;
    }
  }

  if (!rootData || typeof rootData !== "object" || Array.isArray(rootData)) {
    return summary;
  }

  const rootDict = rootData as Record<string, unknown>;

  // 按目标分类聚合该目标上所有生效的规则，用于精确判断「存在生效默认阻断 && 不存在生效全局放行」
  const targetRules: Record<
    "appMain" | "helpers" | "appSupportCli" | "signingId",
    RawLuluRule[]
  > = {
    appMain: [],
    helpers: [],
    appSupportCli: [],
    signingId: [],
  };

  for (const [entryKey, entryVal] of Object.entries(rootDict)) {
    const extracted = extractRulesAndIndicatorsFromEntry(entryKey, entryVal);
    const activeRules = extracted.rules.filter((r) => !isRuleDisabled(r.isDisabled));
    summary.totalRuleEntries += activeRules.length;

    if (activeRules.length === 0) continue;

    // 结合 entry 级别与单条 rule 级别的标识符定位归属目标
    const entryTargets = classifyClaudeTargets(extracted.indicators);
    let countedEntryForClaude = false;

    for (const rule of activeRules) {
      const ruleIndicators = [
        ...extracted.indicators,
        typeof rule.key === "string" ? rule.key : "",
        typeof rule.path === "string" ? rule.path : "",
        typeof rule.name === "string" ? rule.name : "",
        ...extractCsInfoStrings(rule.csInfo),
      ].filter(Boolean);

      const matched = mergeTargets(entryTargets, classifyClaudeTargets(ruleIndicators));
      const isClaudeRelated =
        matched.appMain || matched.helpers || matched.appSupportCli || matched.signingId;

      if (!isClaudeRelated) continue;

      if (!countedEntryForClaude) {
        countedEntryForClaude = true;
      }
      summary.claudeRuleEntries += 1;

      if (matched.appMain) targetRules.appMain.push(rule);
      if (matched.helpers) targetRules.helpers.push(rule);
      if (matched.appSupportCli) targetRules.appSupportCli.push(rule);
      if (matched.signingId) targetRules.signingId.push(rule);

      // 校验 Fake-IP / 网段 CIDR 放行规则是否误设为了 isEndpointAddrRegex = 0 (字面量模式)
      const addr = typeof rule.endpointAddr === "string" ? rule.endpointAddr.trim() : "";
      if (isCidrNotation(addr) && isLiteralEndpointMode(rule.isEndpointAddrRegex)) {
        const safeCidr = sanitizeCidrDisplay(addr);
        const label = `${safeCidr} (isEndpointAddrRegex=0)`;
        if (!summary.cidrMisconfiguredRules.includes(label)) {
          summary.cidrMisconfiguredRules.push(label);
        }
      }
    }
  }

  const appMainLocked = isRuleSetEffectivelyLocked(targetRules.appMain);
  const helpersLocked = isRuleSetEffectivelyLocked(targetRules.helpers);
  const appSupportLocked = isRuleSetEffectivelyLocked(targetRules.appSupportCli);
  const signingLocked = isRuleSetEffectivelyLocked(targetRules.signingId);

  summary.coversClaudeAppMain = appMainLocked;
  summary.coversClaudeHelpers = helpersLocked;
  summary.coversAppSupportClaudeCode = appSupportLocked || signingLocked;
  summary.coversAnthropicSigningId = signingLocked;
  summary.hasBlockActionForClaude =
    appMainLocked || helpersLocked || appSupportLocked || signingLocked;

  // 为了让外部统计看到直观的已保护 Claude 规则条数，若存在 Claude 规则则优先展示该精确计数
  if (summary.claudeRuleEntries > 0) {
    summary.totalRuleEntries = summary.claudeRuleEntries;
  } else {
    summary.totalRuleEntries = 0;
  }

  return summary;
}

/** 保持向后兼容导出别名 */
export const parseLuluRulesJson = parseLuluRules;

function extractRulesAndIndicatorsFromEntry(
  entryKey: string,
  entryVal: unknown
): { rules: RawLuluRule[]; indicators: string[] } {
  const indicators: string[] = [entryKey];
  const rules: RawLuluRule[] = [];

  if (Array.isArray(entryVal)) {
    for (const item of entryVal) {
      if (isRuleLike(item)) rules.push(item);
    }
    return { rules, indicators };
  }

  if (entryVal && typeof entryVal === "object") {
    const rec = entryVal as Record<string, unknown>;
    // LuLu v4.x 结构: { rules: [...], signingInfo: {...}, paths: [...] }
    if (Array.isArray(rec.rules)) {
      for (const r of rec.rules) {
        if (isRuleLike(r)) rules.push(r);
      }
    } else if (isRuleLike(rec)) {
      rules.push(rec);
    }

    if (Array.isArray(rec.paths)) {
      for (const p of rec.paths) {
        if (typeof p === "string") indicators.push(p);
      }
    }
    indicators.push(...extractCsInfoStrings(rec.signingInfo));
    indicators.push(...extractCsInfoStrings(rec.csInfo));
  }

  return { rules, indicators };
}

function extractCsInfoStrings(csInfo: unknown): string[] {
  if (!csInfo) return [];
  if (typeof csInfo === "string") return [csInfo];
  if (typeof csInfo === "object" && !Array.isArray(csInfo)) {
    const out: string[] = [];
    const rec = csInfo as Record<string, unknown>;
    for (const field of ["signatureIdentifier", "signingID", "csReq", "teamID", "signatureSigner"]) {
      if (typeof rec[field] === "string") out.push(rec[field] as string);
    }
    if (Array.isArray(rec.signatureAuthorities)) {
      for (const auth of rec.signatureAuthorities) {
        if (typeof auth === "string") out.push(auth);
      }
    }
    return out;
  }
  return [];
}

function isRuleLike(val: unknown): val is RawLuluRule {
  return Boolean(
    val &&
      typeof val === "object" &&
      !Array.isArray(val) &&
      ("action" in (val as Record<string, unknown>) || "endpointAddr" in (val as Record<string, unknown>))
  );
}

function isRuleDisabled(val: unknown): boolean {
  return val === true || val === 1 || val === "1";
}

interface TargetMatchFlags {
  appMain: boolean;
  helpers: boolean;
  appSupportCli: boolean;
  signingId: boolean;
}

function mergeTargets(a: TargetMatchFlags, b: TargetMatchFlags): TargetMatchFlags {
  return {
    appMain: a.appMain || b.appMain,
    helpers: a.helpers || b.helpers,
    appSupportCli: a.appSupportCli || b.appSupportCli,
    signingId: a.signingId || b.signingId,
  };
}

function classifyClaudeTargets(indicators: string[]): TargetMatchFlags {
  const flags: TargetMatchFlags = {
    appMain: false,
    helpers: false,
    appSupportCli: false,
    signingId: false,
  };

  for (const raw of indicators) {
    const s = raw.trim();
    if (!s) continue;
    const lower = s.toLowerCase();

    // 目录通配符：兼容 `/Applications/Claude.app/*`（标准 LuLu 目录通配）与 `/Applications/Claude.app*`
    if (
      lower.includes("/applications/claude.app/*") ||
      lower.endsWith("/applications/claude.app*")
    ) {
      flags.appMain = true;
      flags.helpers = true;
    }

    // 主程序路径或 Bundle ID
    if (
      lower === "/applications/claude.app" ||
      lower === "/applications/claude.app/contents/macos/claude" ||
      lower === "com.anthropic.claudefordesktop"
    ) {
      flags.appMain = true;
    }

    // 内部 Helpers / ShipIt / coworkd / disclaimer
    if (
      lower.includes("/applications/claude.app/contents/frameworks/") ||
      lower.includes("/applications/claude.app/contents/helpers/") ||
      lower.includes("/applications/claude.app/contents/resources/") ||
      lower.includes("claude helper") ||
      lower.includes("com.anthropic.claudefordesktop.helper") ||
      (lower.includes("claude") && (lower.includes("shipit") || lower.includes("coworkd")))
    ) {
      flags.helpers = true;
    }

    // Application Support 下的后台 claude-code 目录或二进制
    if (
      lower.includes("application support/claude") ||
      lower.includes("/claude-code/") ||
      lower.endsWith("/claude-code")
    ) {
      flags.appSupportCli = true;
    }

    // Anthropic CLI 代码签名或团队签名标识
    if (
      lower.includes("com.anthropic.claude-code") ||
      s.includes("Q6L2SF6YDW")
    ) {
      flags.signingId = true;
      flags.appSupportCli = true;
    }
  }

  return flags;
}

function isWildcardEndpoint(addr: unknown): boolean {
  if (addr === undefined || addr === null) return true;
  const s = String(addr).trim().toLowerCase();
  return s === "" || s === "*" || s === "any" || s === "0.0.0.0/0";
}

function isWildcardPort(port: unknown): boolean {
  if (port === undefined || port === null) return true;
  const s = String(port).trim().toLowerCase();
  return s === "" || s === "*" || s === "any" || s === "0";
}

/**
 * 严格判定一组 Claude 规则是否真正形成断网兜底：
 * 1) 必须包含至少一条生效的全局默认阻断规则 (action == 0 && endpointAddr == '*' && endpointPort == '*')
 * 2) 绝不能包含生效的全局无条件放行规则 (action == 1 && endpointAddr == '*' && endpointPort == '*')
 */
function isRuleSetEffectivelyLocked(rules: RawLuluRule[]): boolean {
  if (rules.length === 0) return false;
  let hasDefaultBlock = false;
  let hasWildcardAllow = false;

  for (const r of rules) {
    const act = Number(r.action);
    const wildAddr = isWildcardEndpoint(r.endpointAddr);
    const wildPort = isWildcardPort(r.endpointPort);

    if (act === 0 && wildAddr && wildPort) {
      hasDefaultBlock = true;
    } else if (act === 1 && wildAddr && wildPort) {
      hasWildcardAllow = true;
    }
  }

  return hasDefaultBlock && !hasWildcardAllow;
}

function isCidrNotation(addr: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(addr)) return true;
  if (addr.includes(":") && /\/\d{1,3}$/.test(addr)) return true;
  return false;
}

function isLiteralEndpointMode(mode: unknown): boolean {
  return mode === 0 || mode === "0" || mode === false;
}

function sanitizeCidrDisplay(cidr: string): string {
  const slashIdx = cidr.indexOf("/");
  if (slashIdx <= 0) return maskIp(cidr);
  const ipPart = cidr.slice(0, slashIdx);
  const prefix = cidr.slice(slashIdx);
  if (isFakeIpv4(ipPart) || isPrivateOrLoopbackIpv4(ipPart)) {
    return `${ipPart}${prefix}`;
  }
  return `${maskIp(ipPart)}${prefix}`;
}

/**
 * 检测 PF 配置文件或防漏守护脚本中是否包含引发 macOS 内核 socket 锁死机的 `user != root` 反模式
 */
export function hasMacosPfDeadlockPattern(content: string): boolean {
  const uncommentedLines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  for (const line of uncommentedLines) {
    if (
      /\b(pass|block)\b.*\b(out|in)?\b.*\buser\s*(\{\s*)?(!=|><)\s*(root|0)\b/i.test(line) ||
      /\buser\s*!=\s*(root|0)\b/i.test(line)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * 解析 LaunchDaemon XML1 plist 中的 Label 与其引用的外部本地脚本路径（/Library/, /usr/local/, /opt/）
 */
export function extractLaunchDaemonLabelAndScripts(plistXmlOrObj: string | unknown): {
  label?: string;
  scriptPaths: string[];
} {
  const parsed = typeof plistXmlOrObj === "string" ? parseAppleXmlPlist(plistXmlOrObj) : plistXmlOrObj;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { scriptPaths: [] };
  }

  const rec = parsed as Record<string, unknown>;
  const label = typeof rec.Label === "string" && rec.Label.trim() ? rec.Label.trim() : undefined;
  const rawArgs: string[] = [];

  if (typeof rec.Program === "string") {
    rawArgs.push(rec.Program);
  }
  if (Array.isArray(rec.ProgramArguments)) {
    for (const arg of rec.ProgramArguments) {
      if (typeof arg === "string") rawArgs.push(arg);
    }
  }

  const allowedPrefixes = ["/Library/", "/usr/local/", "/opt/"];
  const foundPaths = new Set<string>();

  for (const arg of rawArgs) {
    const trimmed = arg.trim();
    if (allowedPrefixes.some((p) => trimmed.startsWith(p))) {
      foundPaths.add(trimmed);
      continue;
    }
    // 兼容 sh -c '"/Library/Application Support/clash-guard/guard.sh" --daemon' 等内嵌命令字符串
    const quotedRe = /["'](\/(?:Library|usr\/local|opt)\/[^"']+)["']/g;
    let qm: RegExpExecArray | null;
    while ((qm = quotedRe.exec(trimmed)) !== null) {
      foundPaths.add(qm[1]);
    }
    const bareRe = /(\/(?:Library|usr\/local|opt)\/[^\s"';&|]+)/g;
    let bm: RegExpExecArray | null;
    while ((bm = bareRe.exec(trimmed)) !== null) {
      foundPaths.add(bm[1]);
    }
  }

  return { label, scriptPaths: [...foundPaths] };
}

/**
 * 根据 `/bin/launchctl print system/<label>` 的只读输出判定守护服务是否正在活跃运行
 */
export function isLaunchDaemonActive(launchctlOutput: string): boolean {
  if (!launchctlOutput || /Could not find service|Bad request/i.test(launchctlOutput)) {
    return false;
  }
  if (/\bstate\s*=\s*running\b/i.test(launchctlOutput)) {
    return true;
  }
  if (/\bpid\s*=\s*[1-9]\d*\b/i.test(launchctlOutput)) {
    return true;
  }
  return false;
}

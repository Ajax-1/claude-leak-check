export interface SettingsAndProxyEnvInput {
  settingsJsonRaw?: string;
  processEnv: Record<string, string | undefined>;
  launchctlBaseUrl?: string;
  systemProxyPort?: number;
  proxyConfigListenerPorts: number[];
  activeListeningLoopbackPorts: number[];
}

export interface SettingsAndProxyEnvResult {
  hasAnthropicBaseUrl: boolean;
  anthropicBaseUrlIsCustomThirdParty: boolean;
  settingsHasCustomBaseUrl: boolean;
  proxyEnvVarsPresent: string[];
  proxyEnvConflictsWithSystem: boolean;
  dedicatedLoopbackProxyPorts: number[];
  deadLoopbackProxyPorts: number[];
  suspiciousSettingsEnvKeys: string[];
}

const PROXY_ENV_KEYS = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
];

function isOfficialAnthropicUrlHost(rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl.trim());
    const h = u.hostname.toLowerCase();
    return (
      h === "anthropic.com" ||
      h.endsWith(".anthropic.com") ||
      h === "claude.com" ||
      h.endsWith(".claude.com") ||
      h === "claude.ai" ||
      h.endsWith(".claude.ai")
    );
  } catch {
    return false;
  }
}

function parseProxyEndpointSafely(rawProxy: string): { isLoopback: boolean; port?: number } | null {
  const trimmed = rawProxy.trim();
  if (!trimmed) return null;
  try {
    const normalized = trimmed.includes("://") ? trimmed : `http://${trimmed}`;
    const u = new URL(normalized);
    const host = u.hostname.toLowerCase();
    const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
    const port = u.port ? Number(u.port) : undefined;
    return { isLoopback, port: port && port > 0 && port <= 65535 ? port : undefined };
  } catch {
    return null;
  }
}

/**
 * 零凭证读取原则：仅检查 `~/.claude/settings.json -> env` 的键名结构、
 * `ANTHROPIC_BASE_URL` 的域名归属，以及 `HTTP(S)_PROXY / ALL_PROXY` 的本地回环监听端口有效性。
 * 绝不读取、存储或输出任何 API Key / OAuth Token 值！
 */
export function inspectClaudeSettingsAndProxyEnv(
  input: SettingsAndProxyEnvInput
): SettingsAndProxyEnvResult {
  const suspiciousSettingsEnvKeys: string[] = [];
  const proxyEnvVarsPresent: string[] = [];
  const dedicatedLoopbackSet = new Set<number>();
  const deadLoopbackSet = new Set<number>();

  const knownAliveProxyPorts = new Set<number>([
    ...input.proxyConfigListenerPorts,
    ...input.activeListeningLoopbackPorts,
  ]);
  if (input.systemProxyPort) {
    knownAliveProxyPorts.add(input.systemProxyPort);
  }

  let settingsBaseUrl = "";
  const settingsProxyValues: { key: string; val: string }[] = [];

  if (input.settingsJsonRaw) {
    try {
      const parsed = JSON.parse(input.settingsJsonRaw) as Record<string, unknown>;
      if (parsed && parsed.env && typeof parsed.env === "object" && !Array.isArray(parsed.env)) {
        const envObj = parsed.env as Record<string, unknown>;
        for (const key of Object.keys(envObj)) {
          // 1. 检查键名是否误放入备用号备忘字段（绝不读取其值）
          if (key.startsWith("_") || /account|backup|token_?\d|old|bak/i.test(key)) {
            suspiciousSettingsEnvKeys.push(key.slice(0, 32));
          }

          // 2. 仅针对明确的路由/代理非凭证字段解析主机与端口
          if (key === "ANTHROPIC_BASE_URL" && typeof envObj[key] === "string") {
            settingsBaseUrl = (envObj[key] as string).trim();
          } else if (PROXY_ENV_KEYS.includes(key) && typeof envObj[key] === "string") {
            const v = (envObj[key] as string).trim();
            if (v) {
              settingsProxyValues.push({ key: `settings.env.${key}`, val: v });
            }
          }
        }
      }
    } catch {
      // JSON 语法损坏或非对象时静默跳过
    }
  }

  const shellBaseUrl = (input.processEnv.ANTHROPIC_BASE_URL || input.launchctlBaseUrl || "").trim();
  const hasAnthropicBaseUrl = Boolean(shellBaseUrl || settingsBaseUrl);
  const settingsHasCustomBaseUrl = Boolean(settingsBaseUrl) && !isOfficialAnthropicUrlHost(settingsBaseUrl);
  const shellHasCustomBaseUrl = Boolean(shellBaseUrl) && !isOfficialAnthropicUrlHost(shellBaseUrl);
  const anthropicBaseUrlIsCustomThirdParty = settingsHasCustomBaseUrl || shellHasCustomBaseUrl;

  let proxyEnvConflictsWithSystem = false;

  const allProxyEntries: { label: string; val: string }[] = [];
  for (const k of PROXY_ENV_KEYS) {
    const v = input.processEnv[k]?.trim();
    if (v) allProxyEntries.push({ label: k, val: v });
  }
  for (const item of settingsProxyValues) {
    allProxyEntries.push({ label: item.key, val: item.val });
  }

  for (const entry of allProxyEntries) {
    if (!proxyEnvVarsPresent.includes(entry.label)) {
      proxyEnvVarsPresent.push(entry.label);
    }
    const ep = parseProxyEndpointSafely(entry.val);
    if (!ep) {
      proxyEnvConflictsWithSystem = true;
      continue;
    }

    if (ep.isLoopback && ep.port) {
      // 若回环端口属于 Clash/Mihomo 配置监听端口 (含 listeners 专属端口) 或当前本机正处于 LISTEN 状态，
      // 则视为合法的本机专属代理端口配置，绝不误报冲突扣分！
      if (knownAliveProxyPorts.has(ep.port)) {
        dedicatedLoopbackSet.add(ep.port);
      } else {
        deadLoopbackSet.add(ep.port);
        proxyEnvConflictsWithSystem = true;
      }
    } else if (!ep.isLoopback) {
      // 指向非本机外部远程代理地址，若与系统代理不一致则提示核查
      if (input.systemProxyPort) {
        proxyEnvConflictsWithSystem = true;
      }
    }
  }

  return {
    hasAnthropicBaseUrl,
    anthropicBaseUrlIsCustomThirdParty,
    settingsHasCustomBaseUrl,
    proxyEnvVarsPresent,
    proxyEnvConflictsWithSystem,
    dedicatedLoopbackProxyPorts: [...dedicatedLoopbackSet].sort((a, b) => a - b),
    deadLoopbackProxyPorts: [...deadLoopbackSet].sort((a, b) => a - b),
    suspiciousSettingsEnvKeys,
  };
}

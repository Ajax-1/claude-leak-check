import { execFile } from "node:child_process";
import { writeFileSync } from "node:fs";
import { platform } from "node:os";
import { resolve } from "node:path";
import { BRAND } from "./config/brand.js";
import { runFullAudit, stripLocalToggleRawFields } from "./core/engine.js";
import type { DemoScenario } from "./platforms/mock.js";
import { startLocalReportServer } from "./server/local-server.js";
import { formatMarkdownReport, formatTerminalSummary } from "./ui/format-terminal.js";
import { renderReportHtml } from "./ui/render-html.js";

interface CliFlags {
  json: boolean;
  markdown: boolean;
  noOpen: boolean;
  deepProbe: boolean;
  noProxyConfig: boolean;
  exportPath?: string;
  demo?: DemoScenario;
  lang: "zh" | "en";
  help: boolean;
  version: boolean;
}

function parseCliArgs(argv: string[]): CliFlags {
  const flags: CliFlags = {
    json: false,
    markdown: false,
    noOpen: false,
    deepProbe: false,
    noProxyConfig: false,
    lang: "zh",
    help: false,
    version: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--json") flags.json = true;
    else if (arg === "--markdown" || arg === "--md") flags.markdown = true;
    else if (arg === "--no-open") flags.noOpen = true;
    else if (arg === "--deep-probe") flags.deepProbe = true;
    else if (arg === "--no-proxy-config") flags.noProxyConfig = true;
    else if (arg === "--help" || arg === "-h") flags.help = true;
    else if (arg === "--version" || arg === "-v") flags.version = true;
    else if (arg === "--export" && argv[i + 1]) {
      flags.exportPath = argv[++i];
    } else if (arg.startsWith("--export=")) {
      flags.exportPath = arg.slice("--export=".length);
    } else if (arg === "--demo" && argv[i + 1]) {
      const val = argv[++i];
      if (val === "safe" || val === "leak") flags.demo = val;
    } else if (arg.startsWith("--demo=")) {
      const val = arg.slice("--demo=".length);
      if (val === "safe" || val === "leak") flags.demo = val;
    } else if (arg === "--lang" && argv[i + 1]) {
      const val = argv[++i];
      if (val === "en" || val === "zh") flags.lang = val;
    } else if (arg.startsWith("--lang=")) {
      const val = arg.slice("--lang=".length);
      if (val === "en" || val === "zh") flags.lang = val;
    }
  }

  return flags;
}

function printHelp(): void {
  console.log(`
${BRAND.packageName} v${BRAND.version}
100% Read-Only Local IP Leak, Stealth Domain & Kill-Switch Auditor for Claude Desktop / Claude Code

Usage:
  npx ${BRAND.packageName} [options]

Options:
  --json               Output redacted JSON diagnostic report and exit (for Agent Skills / CI)
  --markdown, --md     Output redacted Markdown report and exit (for Claude Code / Codex / Cursor)
  --export <path>      Save standalone offline single-file HTML report and exit
  --no-open            Start local interactive report server without auto-opening browser
  --deep-probe         Enable zero-credential edge trace on non-Anthropic third-party domains
  --no-proxy-config    Skip static proxy YAML metadata check (network & OS checks only)
  --demo <safe|leak>   Launch synthetic demo report without probing local network/configs
  --lang <zh|en>       Set CLI output language (default: zh)
  -v, --version        Show version
  -h, --help           Show this help
`);
}

function openInDefaultBrowser(url: string): void {
  const osPlat = platform();
  if (osPlat === "darwin") {
    execFile("/usr/bin/open", [url], () => {});
  } else if (osPlat === "win32") {
    execFile("cmd", ["/c", "start", "", url], () => {});
  } else {
    execFile("xdg-open", [url], () => {});
  }
}

async function main(): Promise<void> {
  const flags = parseCliArgs(process.argv.slice(2));

  if (flags.version) {
    console.log(BRAND.version);
    return;
  }

  if (flags.help) {
    printHelp();
    return;
  }

  if (!flags.json && !flags.markdown) {
    process.stderr.write(
      flags.lang === "zh"
        ? "[*] 正在执行本地只读体检（不读取账号凭证、不修改系统配置）...\n"
        : "[*] Running local read-only audit (zero credential access, zero config changes)...\n"
    );
  }

  const { report, adapter, sessionSalt } = await runFullAudit({
    demo: flags.demo,
    deepProbe: flags.deepProbe,
    skipProxyFileRead: flags.noProxyConfig,
  });

  // 纯 JSON 输出模式（强制擦除本地原始切换字段）
  if (flags.json) {
    const clean = stripLocalToggleRawFields(report);
    console.log(JSON.stringify(clean, null, 2));
    return;
  }

  // 纯 Markdown 输出模式（适合 Agent Skill 直接引用汇报）
  if (flags.markdown) {
    const clean = stripLocalToggleRawFields(report);
    console.log(formatMarkdownReport(clean, flags.lang));
    return;
  }

  // 打印终端彩色摘要
  console.log(formatTerminalSummary(report, flags.lang));

  // 单文件静态导出模式
  if (flags.exportPath) {
    const absOut = resolve(flags.exportPath);
    const clean = stripLocalToggleRawFields(report);
    writeFileSync(absOut, renderReportHtml(clean, { interactiveToken: "" }), "utf8");
    console.log(
      flags.lang === "zh"
        ? `[+] 已导出脱敏离线报告: ${absOut}\n`
        : `[+] Exported standalone redacted HTML report: ${absOut}\n`
    );
    return;
  }

  // 默认交互式本地报告页模式（支撑浏览器 vs CLI 实时比对与断网防漏演练）
  const serverHandle = await startLocalReportServer(report, adapter, sessionSalt);

  console.log(
    flags.lang === "zh"
      ? `[+] 本地体检报告已启动:\n    ${serverHandle.url}\n\n    (按 Ctrl+C 结束本地预览服务)\n`
      : `[+] Local interactive report ready:\n    ${serverHandle.url}\n\n    (Press Ctrl+C to stop local server)\n`
  );

  if (!flags.noOpen) {
    openInDefaultBrowser(serverHandle.url);
  }

  const shutdown = async (): Promise<void> => {
    await serverHandle.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Audit failed:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});

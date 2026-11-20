import { BRAND } from "../config/brand.js";
import type { AuditReport } from "../types/report.js";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

export function formatTerminalSummary(report: AuditReport, lang: "zh" | "en" = "zh"): string {
  const pick = (bi: { zh: string; en: string }) => (lang === "zh" ? bi.zh : bi.en);
  const gradeColor =
    report.redlineTriggered || report.grade === "F"
      ? C.red
      : report.finalScore >= 80
        ? C.green
        : C.yellow;

  const lines: string[] = [];
  lines.push("");
  lines.push(
    `${C.bold}claude-leak-check${C.reset} ${C.dim}v${BRAND.version} · ${
      lang === "zh" ? "本地只读分流与泄漏体检" : "Read-Only Local Audit"
    }${C.reset}`
  );
  lines.push(`${C.dim}────────────────────────────────────────────────────────────────${C.reset}`);

  lines.push(
    `${C.bold}${lang === "zh" ? "综合评分" : "Score"}:${C.reset} ${gradeColor}${C.bold}${
      report.finalScore
    }/100 (${report.grade})${C.reset} ${C.dim}[${report.durationMs}ms]${C.reset}`
  );

  if (report.primaryExit) {
    lines.push(
      `${C.bold}${lang === "zh" ? "主出口(脱敏)" : "Primary Exit"}:${C.reset} ${
        report.primaryExit.countryCode
      } · ${report.primaryExit.ipMasked} (${report.primaryExit.asnType.toUpperCase()})`
    );
  } else {
    lines.push(
      `${C.bold}${lang === "zh" ? "主出口" : "Primary Exit"}:${C.reset} ${C.red}Unreachable / Offline${C.reset}`
    );
  }

  const passDom = report.domainMatrix.filter((d) => d.status === "pass").length;
  const critDom = report.domainMatrix.filter((d) => d.status === "critical").length;
  lines.push(
    `${C.bold}${lang === "zh" ? "关联域名矩阵" : "Domain Matrix"}:${C.reset} ${
      critDom > 0 ? C.red : C.green
    }${passDom}/${report.domainMatrix.length} PASS${C.reset}${
      critDom > 0 ? ` (${C.red}${critDom} CRITICAL${C.reset})` : ""
    }`
  );

  if (report.redlineTriggered) {
    lines.push("");
    lines.push(
      `${C.red}${C.bold}[!] ${
        lang === "zh" ? "检测到高危泄漏项 (总分上限锁定 45):" : "Critical Leak Detected (Score capped at 45):"
      }${C.reset}`
    );
    for (const reason of report.redlineReasons) {
      lines.push(`   ${C.red}- ${pick(reason)}${C.reset}`);
    }
  }

  lines.push("");
  lines.push(`${C.bold}${lang === "zh" ? "分项得分:" : "Modules:"}${C.reset}`);
  for (const mod of report.modules) {
    const icon = mod.status === "critical" ? "✗" : mod.status === "warn" ? "!" : "✓";
    const col = mod.status === "critical" ? C.red : mod.status === "warn" ? C.yellow : C.green;
    lines.push(
      `  ${col}${icon}${C.reset} ${pick(mod.name).padEnd(lang === "zh" ? 18 : 28)} ${C.bold}${String(
        mod.earnedPoints
      ).padStart(2)}/${mod.maxPoints}${C.reset}  ${C.dim}${pick(mod.summary)}${C.reset}`
    );
  }

  lines.push(`${C.dim}────────────────────────────────────────────────────────────────${C.reset}`);
  return lines.join("\n");
}

export function formatMarkdownReport(report: AuditReport, lang: "zh" | "en" = "zh"): string {
  const pick = (bi: { zh: string; en: string }) => (lang === "zh" ? bi.zh : bi.en);
  const passDom = report.domainMatrix.filter((d) => d.status === "pass").length;
  const lines: string[] = [];

  lines.push(
    `# claude-leak-check — ${
      lang === "zh" ? "本地分流与泄漏体检报告" : "Local Routing & Leak Audit Report"
    }`
  );
  lines.push("");
  lines.push(`> ${pick(report.privacyNote)}`);
  lines.push("");
  lines.push(
    `- **${lang === "zh" ? "综合得分" : "Score"}**: **${report.finalScore} / 100** (\`${report.grade}\`)`
  );
  lines.push(
    `- **${lang === "zh" ? "底层主出口 (脱敏)" : "Primary Exit (Redacted)"}**: \`${
      report.primaryExit
        ? `${report.primaryExit.countryCode} · ${report.primaryExit.ipMasked} (${report.primaryExit.asnType.toUpperCase()})`
        : "Offline"
    }\``
  );
  lines.push(
    `- **${lang === "zh" ? "活跃 TUN 网卡" : "Active TUN"}**: \`${
      report.environmentSummary.activeUtunInterfaces.join(", ") || "NONE (OFF)"
    }\``
  );
  lines.push(
    `- **${lang === "zh" ? "关联域名同源率" : "Domain Matrix"}**: **${passDom} / ${
      report.domainMatrix.length
    }**`
  );
  lines.push(`- **${lang === "zh" ? "系统时区" : "System Timezone"}**: \`${report.environmentSummary.systemTimezone}\``);
  lines.push("");

  if (report.redlineTriggered) {
    lines.push(`## ${lang === "zh" ? "高危风险项" : "Critical Alerts"}`);
    lines.push("");
    for (const r of report.redlineReasons) {
      lines.push(`- **${pick(r)}**`);
    }
    lines.push("");
  }

  lines.push(`## ${lang === "zh" ? "分项检查明细" : "Module Breakdown"}`);
  lines.push("");
  for (const mod of report.modules) {
    const tag = mod.status === "critical" ? "[CRITICAL]" : mod.status === "warn" ? "[WARN]" : "[PASS]";
    lines.push(`### ${tag} ${pick(mod.name)} (${mod.earnedPoints}/${mod.maxPoints})`);
    for (const f of mod.findings) {
      const pts = f.pointsDeducted > 0 ? `[-${f.pointsDeducted} pts]` : `[${f.severity.toUpperCase()}]`;
      lines.push(`- **${pts} ${pick(f.title)}**`);
      lines.push(`  - ${pick(f.detail)}`);
      if (f.pointsDeducted > 0 || f.severity === "info") {
        lines.push(`  - *${lang === "zh" ? "排查方向" : "Remediation"}*: ${pick(f.remediation)}`);
      }
    }
    lines.push("");
  }

  const leakedDomains = report.domainMatrix.filter((d) => d.status !== "pass");
  if (leakedDomains.length > 0) {
    lines.push(`## ${lang === "zh" ? "未通过或未启用 Fake-IP 的域名" : "Non-Pass Domains"}`);
    lines.push("");
    lines.push("| Host | NIC | Fake-IP | Status | Reason |");
    lines.push("| :--- | :--- | :--- | :--- | :--- |");
    for (const d of leakedDomains) {
      lines.push(
        `| \`${d.host}\` | \`${d.routeInterface}\` | ${d.isFakeIp ? "Yes" : "No"} | **${d.status.toUpperCase()}** | ${pick(
          d.statusReason
        )} |`
      );
    }
    lines.push("");
  }

  lines.push(`## ${lang === "zh" ? "本机 Claude 组件与防火墙覆盖状态" : "Local Claude Binaries & Firewall"}`);
  lines.push("");
  if (report.binaries.length === 0) {
    lines.push(lang === "zh" ? "- 未在标准路径检测到本地安装组件。" : "- No standard local installations found.");
  } else {
    for (const b of report.binaries) {
      const lockTag = b.firewallCovered ? "[LOCKED]" : "[OPEN]";
      lines.push(`- \`${lockTag}\` **${b.name}** (\`${b.displayPath}\`) — ${pick(b.note)}`);
    }
  }
  lines.push("");

  return lines.join("\n");
}

export { BRAND, type BrandConfig } from "./config/brand.js";
export { DOMAIN_MATRIX, RESTRICTED_REGIONS, REGION_NAMES } from "./core/domains.js";
export { runFullAudit, stripLocalToggleRawFields, type RunAuditConfig } from "./core/engine.js";
export {
  maskIp,
  sanitizePath,
  scrubFreeText,
  parseClashYamlMetadataSafely,
} from "./core/privacy.js";
export {
  inspectClaudeSettingsAndProxyEnv,
  type SettingsAndProxyEnvInput,
  type SettingsAndProxyEnvResult,
} from "./core/settings-env-inspector.js";
export { evaluateAuditScores } from "./core/scorer.js";
export {
  classifyAsnOrg,
  extractListeningLoopbackPortsMac,
  inspectCliBinaryKind,
  type CliBinaryInspection,
} from "./platforms/darwin.js";
export {
  parseAppleXmlPlist,
  unarchiveNsKeyedPlist,
  parseLuluRules,
  parseLuluRulesJson,
  hasMacosPfDeadlockPattern,
  extractLaunchDaemonLabelAndScripts,
  isLaunchDaemonActive,
} from "./platforms/lulu-parser.js";
export { startLocalReportServer, type LocalServerHandle } from "./server/local-server.js";
export { renderReportHtml } from "./ui/render-html.js";
export { formatMarkdownReport, formatTerminalSummary } from "./ui/format-terminal.js";
export type * from "./types/report.js";

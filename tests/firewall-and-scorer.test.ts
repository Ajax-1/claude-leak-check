import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DOMAIN_MATRIX } from "../src/core/domains.js";
import { runFullAudit } from "../src/core/engine.js";
import { evaluateAuditScores } from "../src/core/scorer.js";
import { inspectCliBinaryKind, verifyAnthropicCodesignOutput } from "../src/platforms/darwin.js";
import {
  extractLaunchDaemonLabelAndScripts,
  hasMacosPfDeadlockPattern,
  isLaunchDaemonActive,
  parseLuluRules,
} from "../src/platforms/lulu-parser.js";

test("inspectCliBinaryKind & verifyAnthropicCodesignOutput accurately handle 4 CLI states and codesign stderr", () => {
  const dir = mkdtempSync(join(tmpdir(), "cc-bin-test-"));
  try {
    // 构造模拟的 Mach-O 64-bit arm64 原生二进制头 (0xcffaedfe)
    const pkgBinDir = join(dir, "lib/node_modules/@anthropic-ai/claude-code/bin");
    mkdirSync(pkgBinDir, { recursive: true });
    const nativeExe = join(pkgBinDir, "claude.exe");
    const machoHeader = Buffer.alloc(32);
    machoHeader.writeUInt32BE(0xcffaedfe, 0);
    writeFileSync(nativeExe, machoHeader);

    // 1. 新版 npm 全局软链 -> node_modules/@anthropic-ai/claude-code/bin/claude.exe (原生 Mach-O)
    const npmBinDir = join(dir, "bin");
    mkdirSync(npmBinDir, { recursive: true });
    const npmLink = join(npmBinDir, "claude");
    symlinkSync("../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", npmLink);

    const npmInspected = inspectCliBinaryKind(npmLink);
    assert.equal(npmInspected.classification, "native-macho");
    assert.equal(npmInspected.isMachO, true);
    assert.equal(npmInspected.isNodeScript, false);

    // 2. 新版 pnpm `.bin/claude` Shell 启动脚本 -> exec 原生 Mach-O 二进制（无 node 调用）
    const pnpmShim = join(dir, "pnpm-claude");
    writeFileSync(
      pnpmShim,
      `#!/bin/sh\nbasedir=$(dirname "$(echo "$0" | sed -e 's,\\\\,/,g')")\nexec "$basedir/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe" "$@"\n`,
      "utf8"
    );
    const pnpmInspected = inspectCliBinaryKind(pnpmShim);
    assert.equal(pnpmInspected.classification, "native-macho");
    assert.equal(pnpmInspected.isMachO, true);
    assert.equal(pnpmInspected.isNodeScript, false);
    assert.equal(pnpmInspected.viaShellExecWrapper, true);
    assert.ok(pnpmInspected.resolvedBinaryPath.endsWith("bin/claude.exe"));

    // 3. 旧版纯 JS 包 -> #!/usr/bin/env node cli.js
    const legacyJs = join(pkgBinDir, "cli.js");
    writeFileSync(legacyJs, "#!/usr/bin/env node\nconsole.log('legacy');\n", "utf8");
    const legacyLink = join(npmBinDir, "claude-legacy");
    symlinkSync("../lib/node_modules/@anthropic-ai/claude-code/bin/cli.js", legacyLink);

    const legacyInspected = inspectCliBinaryKind(legacyLink);
    assert.equal(legacyInspected.classification, "node-script");
    assert.equal(legacyInspected.isNodeScript, true);
    assert.equal(legacyInspected.isMachO, false);

    // 4. Shell 包装器显式调用 exec node ... cli-wrapper.cjs
    const nodeShim = join(dir, "pnpm-node-claude");
    writeFileSync(
      nodeShim,
      `#!/bin/sh\nbasedir=$(dirname "$0")\nexec node "$basedir/lib/node_modules/@anthropic-ai/claude-code/cli-wrapper.cjs" "$@"\n`,
      "utf8"
    );
    const nodeShimInspected = inspectCliBinaryKind(nodeShim);
    assert.equal(nodeShimInspected.classification, "node-script");
    assert.equal(nodeShimInspected.isNodeScript, true);
    assert.equal(nodeShimInspected.isMachO, false);

    // 5. pnpm v10 拦截 postinstall 或 --ignore-scripts 残留的 9 行无 #! 报错桩文件（含直接软链与 pnpm 包装器两层场景）
    const stubExe = join(pkgBinDir, "claude-stub.exe");
    writeFileSync(
      stubExe,
      [
        'echo "Error: claude native binary not installed." >&2',
        'echo "Your package manager may have blocked lifecycle scripts during install." >&2',
        "exit 1",
      ].join("\n"),
      "utf8"
    );
    const stubDirect = inspectCliBinaryKind(stubExe);
    assert.equal(stubDirect.classification, "uninstalled-stub");
    assert.equal(stubDirect.isMachO, false);
    assert.equal(stubDirect.isNodeScript, false);

    const pnpmStubWrapper = join(dir, "pnpm-stub-claude");
    writeFileSync(
      pnpmStubWrapper,
      `#!/bin/sh\nbasedir=$(dirname "$0")\nexec "$basedir/lib/node_modules/@anthropic-ai/claude-code/bin/claude-stub.exe" "$@"\n`,
      "utf8"
    );
    const stubWrapped = inspectCliBinaryKind(pnpmStubWrapper);
    assert.equal(stubWrapped.classification, "uninstalled-stub");
    assert.equal(stubWrapped.viaShellExecWrapper, true);

    // 6. asdf / mise 动态垫片脚本（无法静态确认最终落点签名，绝不能误判为原生签名 Mach-O）
    const asdfShim = join(dir, "asdf-claude");
    writeFileSync(
      asdfShim,
      `#!/usr/bin/env bash\n# asdf-plugin: nodejs\nexec /opt/homebrew/opt/asdf/libexec/bin/asdf exec "claude" "$@"\n`,
      "utf8"
    );
    const asdfInspected = inspectCliBinaryKind(asdfShim);
    assert.equal(asdfInspected.classification, "unknown-shim");
    assert.equal(asdfInspected.isMachO, false);
    assert.equal(asdfInspected.isNodeScript, false);

    const miseShim = join(dir, "mise-claude");
    writeFileSync(
      miseShim,
      `#!/bin/sh\nexport MISE_DATA_DIR="$HOME/.local/share/mise"\nexec "/opt/homebrew/bin/mise" x -- claude "$@"\n`,
      "utf8"
    );
    const miseInspected = inspectCliBinaryKind(miseShim);
    assert.equal(miseInspected.classification, "unknown-shim");
    assert.equal(miseInspected.isMachO, false);
    assert.equal(miseInspected.isNodeScript, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // 7. codesign -dv stderr 输出校验（区分 Anthropic 官方签名 vs Volta 二进制垫片 vs 空输出/未签名）
  const anthropicCliStderr = [
    "Executable=/Users/demo/.local/share/claude/versions/2.1.330",
    "Identifier=com.anthropic.claude-code",
    "Format=Mach-O thin (arm64)",
    "CodeDirectory v=20500 size=123456 flags=0x10000(runtime) hashes=3850+7 location=embedded",
    "Signature size=9051",
    "Timestamp=20 Nov 2026 at 10:00:00",
    "TeamIdentifier=Q6L2SF6YDW",
  ].join("\n");
  const verifiedCli = verifyAnthropicCodesignOutput(anthropicCliStderr);
  assert.equal(verifiedCli.signedByAnthropic, true);
  assert.equal(verifiedCli.teamId, "Q6L2SF6YDW");
  assert.equal(verifiedCli.identifier, "com.anthropic.claude-code");

  const voltaShimStderr = [
    "Executable=/Users/demo/.volta/bin/volta-shim",
    "Identifier=volta-shim-55554944ab12cd34",
    "Format=Mach-O thin (arm64)",
    "Signature=adhoc",
    "TeamIdentifier=not set",
  ].join("\n");
  const verifiedVolta = verifyAnthropicCodesignOutput(voltaShimStderr);
  assert.equal(verifiedVolta.signedByAnthropic, false);

  assert.equal(verifyAnthropicCodesignOutput("").signedByAnthropic, false);
  assert.equal(
    verifyAnthropicCodesignOutput("/tmp/fake: code object is not signed at all").signedByAnthropic,
    false
  );
});

test("DOMAIN_MATRIX contains 27 targets including assets-proxy and bridge subdomains", () => {
  assert.equal(DOMAIN_MATRIX.length, 27);
  assert.ok(DOMAIN_MATRIX.some((d) => d.host === "assets-proxy.anthropic.com"));
  assert.ok(DOMAIN_MATRIX.some((d) => d.host === "bridge.claudeusercontent.com"));
});

test("parseLuluRules accurately unarchives real LuLu v4.5.7 XML1 NSKeyedArchiver plist with CF$UID, NSDate, NSData, and `/Applications/Claude.app/*`", () => {
  // 真实复刻 LuLu v4.5.7 `plutil -convert xml1 -o - rules.plist` 的 NSKeyedArchiver 结构
  const realisticXmlPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>$archiver</key>
  <string>NSKeyedArchiver</string>
  <key>$objects</key>
  <array>
    <string>$null</string>
    <!-- 1: root NSMutableDictionary -->
    <dict>
      <key>$class</key><dict><key>CF$UID</key><integer>20</integer></dict>
      <key>NS.keys</key>
      <array>
        <dict><key>CF$UID</key><integer>2</integer></dict>
        <dict><key>CF$UID</key><integer>3</integer></dict>
      </array>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>4</integer></dict>
        <dict><key>CF$UID</key><integer>10</integer></dict>
      </array>
    </dict>
    <!-- 2: key 1: directory wildcard with slash! -->
    <string>/Applications/Claude.app/*</string>
    <!-- 3: key 2: Anthropic CLI signing ID -->
    <string>com.anthropic.claude-code</string>
    <!-- 4: entry wrapper for /Applications/Claude.app/* -->
    <dict>
      <key>NS.keys</key>
      <array>
        <dict><key>CF$UID</key><integer>5</integer></dict>
        <dict><key>CF$UID</key><integer>6</integer></dict>
      </array>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>7</integer></dict>
        <dict><key>CF$UID</key><integer>9</integer></dict>
      </array>
    </dict>
    <!-- 5 & 6 -->
    <string>rules</string>
    <string>paths</string>
    <!-- 7: NSMutableArray of rules for Claude.app/* -->
    <dict>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>8</integer></dict>
        <dict><key>CF$UID</key><integer>14</integer></dict>
      </array>
    </dict>
    <!-- 8: Rule 1: Allow Fake-IP CIDR (isEndpointAddrRegex = 2) -->
    <dict>
      <key>action</key><integer>1</integer>
      <key>endpointAddr</key><dict><key>CF$UID</key><integer>15</integer></dict>
      <key>endpointPort</key><dict><key>CF$UID</key><integer>16</integer></dict>
      <key>isDisabled</key><integer>0</integer>
      <key>isEndpointAddrRegex</key><integer>2</integer>
      <key>path</key><dict><key>CF$UID</key><integer>2</integer></dict>
      <key>creation</key><dict><key>NS.time</key><real>785299200.0</real></dict>
      <key>uuid</key><data>AQIDBA==</data>
    </dict>
    <!-- 9: paths NSMutableSet -->
    <dict>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>2</integer></dict>
      </array>
    </dict>
    <!-- 10: entry wrapper for com.anthropic.claude-code -->
    <dict>
      <key>NS.keys</key>
      <array>
        <dict><key>CF$UID</key><integer>5</integer></dict>
        <dict><key>CF$UID</key><integer>11</integer></dict>
      </array>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>12</integer></dict>
        <dict><key>CF$UID</key><integer>13</integer></dict>
      </array>
    </dict>
    <!-- 11 -->
    <string>signingInfo</string>
    <!-- 12: rules array for claude-code -->
    <dict>
      <key>NS.objects</key>
      <array>
        <dict><key>CF$UID</key><integer>17</integer></dict>
      </array>
    </dict>
    <!-- 13: signingInfo dict -->
    <dict>
      <key>NS.keys</key><array><dict><key>CF$UID</key><integer>18</integer></dict></array>
      <key>NS.objects</key><array><dict><key>CF$UID</key><integer>3</integer></dict></array>
    </dict>
    <!-- 14: Rule 2: Default Block *:* for Claude.app/* -->
    <dict>
      <key>action</key><integer>0</integer>
      <key>endpointAddr</key><dict><key>CF$UID</key><integer>16</integer></dict>
      <key>endpointPort</key><dict><key>CF$UID</key><integer>16</integer></dict>
      <key>isDisabled</key><integer>0</integer>
      <key>isEndpointAddrRegex</key><integer>0</integer>
      <key>path</key><dict><key>CF$UID</key><integer>2</integer></dict>
    </dict>
    <!-- 15 & 16 -->
    <string>198.18.0.0/15</string>
    <string>*</string>
    <!-- 17: Default Block *:* for com.anthropic.claude-code -->
    <dict>
      <key>action</key><integer>0</integer>
      <key>endpointAddr</key><dict><key>CF$UID</key><integer>16</integer></dict>
      <key>endpointPort</key><dict><key>CF$UID</key><integer>16</integer></dict>
      <key>isDisabled</key><integer>0</integer>
      <key>key</key><dict><key>CF$UID</key><integer>3</integer></dict>
    </dict>
    <!-- 18 -->
    <string>signatureIdentifier</string>
  </array>
  <key>$top</key>
  <dict>
    <key>root</key>
    <dict><key>CF$UID</key><integer>1</integer></dict>
  </dict>
  <key>$version</key>
  <integer>100000</integer>
</dict>
</plist>`;

  const summary = parseLuluRules(realisticXmlPlist);
  assert.equal(summary.coversClaudeAppMain, true);
  assert.equal(summary.coversClaudeHelpers, true);
  assert.equal(summary.coversAppSupportClaudeCode, true);
  assert.equal(summary.coversAnthropicSigningId, true);
  assert.equal(summary.hasBlockActionForClaude, true);
  assert.equal(summary.claudeRuleEntries, 3);
  assert.equal(summary.totalRuleEntries, 3);
  assert.deepEqual(summary.cidrMisconfiguredRules, []);
});

test("parseLuluRules rejects unrelated app Block rules, disabled Claude rules, wildcard Allow overrides, and flags CIDR literal mode 0", () => {
  const trickyRulesJson = JSON.stringify({
    // 无关软件有 Block *:*，绝不能误判为保护了 Claude
    "/Applications/SomeOtherApp.app": [
      { action: 0, endpointAddr: "*", endpointPort: "*", isDisabled: 0 },
    ],
    // Claude 的阻断规则被禁用 (isDisabled = 1)，且有一条全局 Allow *:*，外加一条 isEndpointAddrRegex = 0 的错误 CIDR 规则
    "/Applications/Claude.app/*": [
      { action: 0, endpointAddr: "*", endpointPort: "*", isDisabled: 1 },
      { action: 1, endpointAddr: "*", endpointPort: "*", isDisabled: 0 },
      { action: 1, endpointAddr: "198.18.0.0/16", endpointPort: "*", isDisabled: 0, isEndpointAddrRegex: 0 },
    ],
  });

  const summary = parseLuluRules(trickyRulesJson);
  assert.equal(summary.coversClaudeAppMain, false);
  assert.equal(summary.coversClaudeHelpers, false);
  assert.equal(summary.hasBlockActionForClaude, false);
  assert.deepEqual(summary.cidrMisconfiguredRules, ["198.18.0.0/16 (isEndpointAddrRegex=0)"]);
});

test("extractLaunchDaemonLabelAndScripts & isLaunchDaemonActive handle external PF scripts and service status", () => {
  const daemonPlistXml = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>local.clash-guard</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>/Library/Application Support/clash-guard/guard.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>`;

  const extracted = extractLaunchDaemonLabelAndScripts(daemonPlistXml);
  assert.equal(extracted.label, "local.clash-guard");
  assert.deepEqual(extracted.scriptPaths, ["/Library/Application Support/clash-guard/guard.sh"]);

  assert.equal(isLaunchDaemonActive("\tstate = running\n\tpid = 412\n"), true);
  assert.equal(isLaunchDaemonActive("\tstate = not running\n\tlast exit code = 0\n"), false);
  assert.equal(
    isLaunchDaemonActive('Could not find service "local.clash-guard" in domain for system'),
    false
  );

  const dangerousPf = `pass out quick on en0 proto { tcp, udp } from any to any user != root`;
  assert.equal(hasMacosPfDeadlockPattern(dangerousPf), true);
});

test("Scorer does not penalize residual inactive PF files or manual select Clash groups, but warns on CIDR=0", async () => {
  const { report } = await runFullAudit({ demo: "safe" });

  // 注入：已停用 PF 残留脚本 + 手动 select 组含 DIRECT + 满分状态下不应扣分
  const scoredResidualAndManual = evaluateAuditScores({
    netSnap: {
      activeUtunInterfaces: ["utun5"],
      defaultRouteInterface: "utun5",
      dnsServers: ["198.18.0.2"],
      dnsServersMasked: ["198.18.*.* (Fake-IP)"],
      tailscaleMagicDns: false,
      icloudPrivateRelaySuspected: false,
      competingVpns: [],
      systemProxy: { httpEnabled: false, httpsEnabled: false, socksEnabled: false },
      publicIpv6Interfaces: [],
    },
    primaryExit: report.primaryExit,
    domainMatrix: report.domainMatrix,
    binaries: report.binaries,
    proxyAudit: {
      ...report.proxyAudit,
      claudeTargetGroups: ["节点选择"],
      autoFallbackRiskGroups: [],
      manualSelectCautionGroups: ["节点选择"],
    },
    firewallAudit: {
      ...report.firewallAudit,
      pfDeadlockRiskDetected: false,
      pfDeadlockFiles: [],
      pfDeadlockResidualFiles: ["/Library/Application Support/clash-guard/guard.sh (local.clash-guard: not running)"],
      luluCidrMisconfiguredRules: [],
    },
    envSnap: {
      systemTimezone: "Asia/Taipei",
      isMainlandTimezone: false,
      systemLocale: "en_US.UTF-8",
      defaultBrowser: "Brave Browser",
      hasAnthropicBaseUrl: false,
      anthropicBaseUrlIsCustomThirdParty: false,
      settingsHasCustomBaseUrl: false,
      proxyEnvVarsPresent: ["settings.env.HTTPS_PROXY"],
      proxyEnvConflictsWithSystem: false,
      dedicatedLoopbackProxyPorts: [7897],
      deadLoopbackProxyPorts: [],
      riskyReverseProxies: [],
      mcpServerCount: 0,
      mcpCommands: [],
      suspiciousSettingsEnvKeys: [],
    },
    browserSync: report.browserSync,
    killSwitchDrill: report.killSwitchDrill,
  });

  assert.equal(scoredResidualAndManual.finalScore, 100);
  assert.equal(scoredResidualAndManual.grade, "A+");
  const m4 = scoredResidualAndManual.modules.find((m) => m.id === "app_footprint")!;
  assert.ok(m4.findings.some((f) => f.id === "pf-kernel-deadlock-residual" && f.pointsDeducted === 0));
  assert.ok(m4.findings.some((f) => f.id === "proxy-group-manual-select-note" && f.pointsDeducted === 0));

  // 若出现 LuLu CIDR `isEndpointAddrRegex = 0` 误配，扣 6 分告警
  const scoredCidrWarn = evaluateAuditScores({
    netSnap: {
      activeUtunInterfaces: ["utun5"],
      defaultRouteInterface: "utun5",
      dnsServers: ["198.18.0.2"],
      dnsServersMasked: ["198.18.*.* (Fake-IP)"],
      tailscaleMagicDns: false,
      icloudPrivateRelaySuspected: false,
      competingVpns: [],
      systemProxy: { httpEnabled: false, httpsEnabled: false, socksEnabled: false },
      publicIpv6Interfaces: [],
    },
    primaryExit: report.primaryExit,
    domainMatrix: report.domainMatrix,
    binaries: report.binaries,
    proxyAudit: report.proxyAudit,
    firewallAudit: {
      ...report.firewallAudit,
      luluCidrMisconfiguredRules: ["198.18.0.0/16 (isEndpointAddrRegex=0)"],
    },
    envSnap: {
      systemTimezone: "Asia/Taipei",
      isMainlandTimezone: false,
      systemLocale: "en_US.UTF-8",
      defaultBrowser: "Brave Browser",
      hasAnthropicBaseUrl: false,
      anthropicBaseUrlIsCustomThirdParty: false,
      settingsHasCustomBaseUrl: false,
      proxyEnvVarsPresent: [],
      proxyEnvConflictsWithSystem: false,
      dedicatedLoopbackProxyPorts: [],
      deadLoopbackProxyPorts: [],
      riskyReverseProxies: [],
      mcpServerCount: 0,
      mcpCommands: [],
      suspiciousSettingsEnvKeys: [],
    },
    browserSync: report.browserSync,
    killSwitchDrill: report.killSwitchDrill,
  });
  assert.equal(scoredCidrWarn.finalScore, 94);
});

test("Scoring engine awards A+ on safe baseline and caps at <=45 (F) on fatal redlines", async () => {
  const safeRes = await runFullAudit({ demo: "safe" });
  assert.equal(safeRes.report.redlineTriggered, false);
  assert.equal(safeRes.report.finalScore, 100);
  assert.equal(safeRes.report.grade, "A+");
  assert.equal(safeRes.report.domainMatrix.length, 27);
  assert.ok(safeRes.report.domainMatrix.every((d) => d.status === "pass"));

  const leakRes = await runFullAudit({ demo: "leak" });
  assert.equal(leakRes.report.redlineTriggered, true);
  assert.ok(leakRes.report.finalScore <= 45);
  assert.equal(leakRes.report.grade, "F");
  assert.ok(leakRes.report.redlineReasons.length >= 3);
});

test("Scorer handles global-cli-stub (info, 0 pts) and global-cli-unverified-shim (warn, -4 pts) without misreporting", async () => {
  const { report } = await runFullAudit({ demo: "safe" });
  const baseNet = {
    activeUtunInterfaces: ["utun5"],
    defaultRouteInterface: "utun5",
    dnsServers: ["198.18.0.2"],
    dnsServersMasked: ["198.18.*.* (Fake-IP)"],
    tailscaleMagicDns: false,
    icloudPrivateRelaySuspected: false,
    competingVpns: [],
    systemProxy: { httpEnabled: false, httpsEnabled: false, socksEnabled: false },
    publicIpv6Interfaces: [],
  };
  const baseEnv = {
    systemTimezone: "Asia/Taipei",
    isMainlandTimezone: false,
    systemLocale: "en_US.UTF-8",
    defaultBrowser: "Brave Browser",
    hasAnthropicBaseUrl: false,
    anthropicBaseUrlIsCustomThirdParty: false,
    settingsHasCustomBaseUrl: false,
    proxyEnvVarsPresent: [],
    proxyEnvConflictsWithSystem: false,
    dedicatedLoopbackProxyPorts: [],
    deadLoopbackProxyPorts: [],
    riskyReverseProxies: [],
    mcpServerCount: 0,
    mcpCommands: [],
    suspiciousSettingsEnvKeys: [],
  };

  // 1. 存在未完成 postinstall 的占位桩文件时：给 info 提示（0 分），且不连坐破坏已锁定的真实二进制
  const withStub = evaluateAuditScores({
    netSnap: baseNet,
    primaryExit: report.primaryExit,
    domainMatrix: report.domainMatrix,
    binaries: [
      ...report.binaries,
      {
        id: "global-stub-test",
        name: "全局终端 claude (未完成 postinstall 占位脚本)",
        displayPath: "~/Library/pnpm/claude",
        kind: "global-cli-stub",
        exists: true,
        signedByAnthropic: false,
        firewallCovered: false,
        riskLevel: "warn",
        note: { zh: "stub", en: "stub" },
      },
    ],
    proxyAudit: report.proxyAudit,
    firewallAudit: report.firewallAudit,
    envSnap: baseEnv,
    browserSync: report.browserSync,
    killSwitchDrill: report.killSwitchDrill,
  });
  assert.equal(withStub.finalScore, 100);
  const stubM4 = withStub.modules.find((m) => m.id === "app_footprint")!;
  assert.ok(stubM4.findings.some((f) => f.id === "cli-uninstalled-stub" && f.pointsDeducted === 0));
  assert.ok(stubM4.findings.some((f) => f.id === "firewall-all-locked"));

  // 2. 存在 Volta / asdf / mise 等未核验垫片时：给 warn 提示（轻扣 4 分），绝不谎报已确认为官方签名 Mach-O
  const withShim = evaluateAuditScores({
    netSnap: baseNet,
    primaryExit: report.primaryExit,
    domainMatrix: report.domainMatrix,
    binaries: [
      ...report.binaries,
      {
        id: "global-shim-test",
        name: "全局终端 claude (版本管理器二进制垫片 / 非官方签名)",
        displayPath: "~/.volta/bin/claude",
        kind: "global-cli-unverified-shim",
        exists: true,
        signedByAnthropic: false,
        firewallCovered: false,
        riskLevel: "warn",
        note: { zh: "shim", en: "shim" },
      },
    ],
    proxyAudit: report.proxyAudit,
    firewallAudit: { ...report.firewallAudit, claudeCliLocked: false },
    envSnap: baseEnv,
    browserSync: report.browserSync,
    killSwitchDrill: report.killSwitchDrill,
  });
  assert.equal(withShim.finalScore, 96);
  const shimM4 = withShim.modules.find((m) => m.id === "app_footprint")!;
  assert.ok(shimM4.findings.some((f) => f.id === "cli-unverified-shim" && f.pointsDeducted === 4));
});

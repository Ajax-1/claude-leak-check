import assert from "node:assert/strict";
import test from "node:test";
import {
  isFakeIpv4,
  isMainlandCarrierIpv6,
  maskIp,
  parseClashYamlMetadataSafely,
  sanitizePath,
  scrubFreeText,
} from "../src/core/privacy.js";
import { inspectClaudeSettingsAndProxyEnv } from "../src/core/settings-env-inspector.js";
import { runFullAudit, stripLocalToggleRawFields } from "../src/core/engine.js";
import { classifyAsnOrg, extractListeningLoopbackPortsMac } from "../src/platforms/darwin.js";

test("maskIp properly masks IPv4, Fake-IP, and IPv6 addresses", () => {
  assert.equal(maskIp("198.51.100.42"), "198.51.*.*");
  assert.equal(maskIp("198.18.0.88"), "198.18.*.* (Fake-IP)");
  assert.equal(maskIp("240e:3b7:3271:88a0:1234:5678:abcd:ef01"), "240e:3b7:*:*::*");
  assert.equal(maskIp("1.1.1.1"), "1.1.1.1");
  assert.equal(isFakeIpv4("198.18.1.9"), true);
  assert.equal(isFakeIpv4("198.51.100.1"), false);
  assert.equal(isMainlandCarrierIpv6("240e:3b7:1111::1%en0"), true);
  assert.equal(isMainlandCarrierIpv6("2606:4700:4700::1111"), false);
});

test("sanitizePath and scrubFreeText redact usernames and raw IPs", () => {
  assert.equal(
    sanitizePath("/Users/testuser_xyz/Library/Application Support/Claude"),
    "~/Library/Application Support/Claude"
  );
  assert.equal(
    scrubFreeText("Connected via 203.0.113.77 from /Users/alice/.claude"),
    "Connected via 203.0.*.* from ~/.claude"
  );
});

test("classifyAsnOrg classifies AS174 Cogent as business rather than hosting", () => {
  assert.equal(classifyAsnOrg("AS174 Cogent Communications"), "business");
  assert.equal(classifyAsnOrg("AS14061 DigitalOcean, LLC"), "hosting");
  assert.equal(classifyAsnOrg("AS7922 Comcast Cable Communications, LLC"), "isp");
});

test("parseClashYamlMetadataSafely skips secrets, parses listeners, and distinguishes auto vs manual select groups", () => {
  // 场景 A：手选 select 策略组（如「节点选择」）含 DIRECT，且存在无关的自动切换香港组（Bilibili），不应误报扣分！
  const manualSelectYaml = `
mixed-port: 7897
mode: rule
ipv6: false
secret: "SUPER_SECRET_CONTROLLER_TOKEN_999"
authentication:
  - "admin:TOP_SECRET_PASS_888"
listeners:
  - name: claude-dedicated-in
    type: mixed
    port: 7899
    users:
      - username: u1
        password: LISTENER_SECRET_PASSWORD_111
tun:
  enable: true
  stack: gvisor
  strict-route: true
dns:
  enable: true
  enhanced-mode: fake-ip
  ipv6: false
proxy-providers:
  my-sub:
    type: http
    url: "https://sub.synthetic-example.invalid/api/v1/client/subscribe?token=FAKE_SUB_TOKEN_777"
proxies:
  - name: "US-Dedicated-Node"
    type: trojan
    server: "secret-node.synthetic-example.invalid"
    port: 443
    password: "FAKE_NODE_PASSWORD_666"
  - name: "203.0.113.250-RawServer"
    type: ss
    server: 203.0.113.250
    password: "FAKE_SS_PASSWORD_555"
proxy-groups:
  - name: "节点选择"
    type: select
    proxies:
      - "US-Dedicated-Node"
      - DIRECT
  - name: "无关港台自动组"
    type: url-test
    proxies:
      - "香港高速-01"
      - DIRECT
rules:
  - DOMAIN-SUFFIX,bilibili.com,无关港台自动组
  - IN-PORT,7899,节点选择
  - MATCH,节点选择
`;

  const manualAudit = parseClashYamlMetadataSafely(manualSelectYaml, ["Clash Verge Rev (Mock)"]);
  const serialized = JSON.stringify(manualAudit);

  assert.deepEqual(manualAudit.localListenerPorts, [7897, 7899]);
  assert.deepEqual(manualAudit.claudeTargetGroups, ["节点选择"]);
  assert.deepEqual(manualAudit.autoFallbackRiskGroups, []);
  assert.deepEqual(manualAudit.manualSelectCautionGroups, ["节点选择"]);
  assert.equal(manualAudit.hasDirectInProxyGroups, false);
  assert.equal(manualAudit.hasRestrictedRegionInGroups, false);

  // 确保零敏感信息残留
  assert.equal(serialized.includes("SUPER_SECRET_CONTROLLER_TOKEN_999"), false);
  assert.equal(serialized.includes("TOP_SECRET_PASS_888"), false);
  assert.equal(serialized.includes("LISTENER_SECRET_PASSWORD_111"), false);
  assert.equal(serialized.includes("FAKE_SUB_TOKEN_777"), false);
  assert.equal(serialized.includes("synthetic-example.invalid"), false);
  assert.equal(serialized.includes("FAKE_NODE_PASSWORD_666"), false);
  assert.equal(serialized.includes("203.0.113.250"), false);
  assert.equal(serialized.includes("FAKE_SS_PASSWORD_555"), false);

  // 场景 B：承载 Claude 的规则（含嵌套子组）指向了 url-test / fallback 自动切换且含香港/DIRECT，应精准告警
  const autoRiskYaml = `
mode: rule
proxy-groups:
  - name: "Claude入口组"
    type: select
    proxies:
      - "自动故障转移组"
  - name: "自动故障转移组"
    type: fallback
    proxies:
      - "US-Node"
      - "香港备用-02"
      - DIRECT
rules:
  - PROCESS-PATH-REGEX,.*Claude.*,Claude入口组
  - DOMAIN-SUFFIX,siftscience.com,DIRECT
  - MATCH,Claude入口组
`;
  const autoAudit = parseClashYamlMetadataSafely(autoRiskYaml, []);
  assert.deepEqual(autoAudit.autoFallbackRiskGroups, ["自动故障转移组"]);
  assert.equal(autoAudit.hasDirectInProxyGroups, true);
  assert.equal(autoAudit.hasRestrictedRegionInGroups, true);
  assert.equal(autoAudit.hasStealthDomainDirectRule, true);
});

test("inspectClaudeSettingsAndProxyEnv recognizes Clash listener ports and never leaks tokens", () => {
  const settingsRaw = JSON.stringify({
    _ACCOUNT_1: "sk-ant-oat01-SAFE_OUTSIDE_ENV",
    env: {
      CLAUDE_CODE_OAUTH_TOKEN: "sk-ant-oat01-SECRET_TOKEN_99999",
      ANTHROPIC_BASE_URL: "https://relay.example-mirror.invalid/v1",
      HTTPS_PROXY: "http://127.0.0.1:7899",
      _ACCOUNT_2_MISTAKE: "sk-ant-oat01-MISTAKE_IN_ENV",
    },
  });

  const resOk = inspectClaudeSettingsAndProxyEnv({
    settingsJsonRaw: settingsRaw,
    processEnv: {},
    systemProxyPort: 7890, // 系统代理端口是 7890，但 7899 在 Clash listeners 中活跃监听
    proxyConfigListenerPorts: [7897, 7899],
    activeListeningLoopbackPorts: [7890, 7897, 7899],
  });

  const dumped = JSON.stringify(resOk);
  assert.equal(dumped.includes("SECRET_TOKEN_99999"), false);
  assert.equal(dumped.includes("MISTAKE_IN_ENV"), false);
  assert.equal(resOk.settingsHasCustomBaseUrl, true);
  assert.equal(resOk.anthropicBaseUrlIsCustomThirdParty, true);
  assert.equal(resOk.proxyEnvConflictsWithSystem, false);
  assert.deepEqual(resOk.dedicatedLoopbackProxyPorts, [7899]);
  assert.deepEqual(resOk.deadLoopbackProxyPorts, []);
  assert.deepEqual(resOk.suspiciousSettingsEnvKeys, ["_ACCOUNT_2_MISTAKE"]);

  // 当指向未监听的死端口 18888 时应标记异常
  const resDead = inspectClaudeSettingsAndProxyEnv({
    settingsJsonRaw: JSON.stringify({ env: { HTTPS_PROXY: "http://127.0.0.1:18888" } }),
    processEnv: {},
    proxyConfigListenerPorts: [7897],
    activeListeningLoopbackPorts: [7897],
  });
  assert.equal(resDead.proxyEnvConflictsWithSystem, true);
  assert.deepEqual(resDead.deadLoopbackProxyPorts, [18888]);
});

test("extractListeningLoopbackPortsMac parses macOS netstat -an -p tcp LISTEN lines", () => {
  const sampleNetstat = `
tcp4       0      0  127.0.0.1.7897         *.*                    LISTEN
tcp46      0      0  *.7899                 *.*                    LISTEN
tcp4       0      0  192.168.1.5.52341      1.1.1.1.443            ESTABLISHED
`;
  const ports = extractListeningLoopbackPortsMac(sampleNetstat);
  assert.deepEqual(ports.sort((a, b) => a - b), [7897, 7899]);
});

test("stripLocalToggleRawFields removes ipRawForLocalToggle completely", async () => {
  const { report } = await runFullAudit({ demo: "safe" });
  assert.equal(report.primaryExit?.ipRawForLocalToggle, "198.51.100.42");

  const stripped = stripLocalToggleRawFields(report);
  const rawJson = JSON.stringify(stripped);
  assert.equal(stripped.primaryExit?.ipRawForLocalToggle, undefined);
  assert.equal(rawJson.includes("198.51.100.42"), false);
  assert.equal(rawJson.includes("198.51.*.*"), true);
});

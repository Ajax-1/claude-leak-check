---
name: claude-leak-check
description: 本地只读检测 Claude Desktop 与 Claude Code 的分流完整性、关联遥测域名出口、OAuth 双端一致性、防火墙规则覆盖与本地环境配置。当用户需要排查 Claude 封号隐患、IP/DNS/IPv6/WebRTC 泄漏或断代理保护状态时调用。
---

# claude-leak-check

用于对本机 **Claude Desktop** 和 **Claude Code** 的网络出口与防泄漏状态做纯只读检查。

## 安全约束（执行前必读）

1. **严格只读**：检查过程中不修改用户的代理配置、系统网络设置、防火墙规则或 `~/.claude` 目录下的任何文件。
2. **严禁在已登录的 Claude Code 会话内重启代理**：如果当前正在运行的宿主就是已登录账号的 Claude Code，绝不要在会话内重载、重启或关闭 Clash / Mihomo / Surge / TUN。代理闪断的 1~2 秒内，底层重连会直接回落本地宽带 IP。
3. **不要直接读取代理订阅文件**：不要用 `cat` 或文件读取工具去翻用户的 Clash profile、节点列表、订阅链接或密钥。统一调用下方命令获取已自动脱敏的结构化结果。

## 调用方式

### 1. 输出 Markdown 诊断结果（适合在对话中直接展示）

```bash
npx claude-leak-check --markdown
```

如果用户的代理部署在 OpenWrt 软路由 / 旁路由透明网关上（本机未安装代理客户端），工具默认会自动识别透明网关拓扑，也可显式加上 `--router` 参数：

```bash
npx claude-leak-check --router --markdown
```

如果在已克隆的仓库目录内运行，可执行：

```bash
node ./dist/cli.js --markdown
```

### 2. 输出 JSON 结构化数据

```bash
npx claude-leak-check --json
```

`--markdown` 与 `--json` 输出中的所有公网 IP 与用户目录均已自动脱敏（如 `198.51.*.*`、`~/...`）。

### 3. 打开本地交互报告页（含浏览器双端比对与断代理实测）

如果用户需要核对默认浏览器与终端的出口是否一致、检测浏览器 WebRTC UDP 穿透，或者手动关掉 TUN 做一次断网防漏实测并导出体检图片，在终端执行：

```bash
npx claude-leak-check
```

## 结果解读重点

1. **优先提示高危项（`redlineTriggered: true`，评级 `F`）**：
   - 底层无环境变量 Socket 出口位于不支持地区（如 `CN` / `HK` / `MO` / `RU`）。
   - 未开启 TUN 虚拟网卡接管默认路由（终端进程和桌面端后台子进程默认不走系统 HTTP 代理）。
   - 27 个核心与第三方关联域名（如 `assets-proxy.anthropic.com`、`bridge.claudeusercontent.com`、`us5.datadoghq.com`、`browser-intake-us5-datadoghq.com`、`o1158394.ingest.us.sentry.io`、`statsig.anthropic.com`、`featuregates.org`、`prodregistryv2.org`、`siftscience.com`、`js.stripe.com` 等）绕过虚拟网卡或命中 `DIRECT`。
   - 物理网卡存在可直通外网的国内运营商公网 IPv6（`240e:` / `2408:` / `2409:`）。
   - 默认浏览器出口与终端出口不一致（OAuth 授权跳回桌面端时产生双 IP 切换）。
2. **次要风险与加固建议**：
   - 全局 `claude` 若仍为旧版纯 JS 脚本或未完成原生替换的 `node` 包装器（底层驻留进程为 `node`），应用防火墙无法按 Anthropic 签名单独隔离，建议升级至包含原生 Mach-O 二进制的新版或改用官方独立安装器；若为新版原生二进制，则需确认防火墙已按 `com.anthropic.claude-code` 代码签名锁定。
   - 若检测到运行中的旧版 `user != root` PF 脚本，提醒其在 macOS 上容易触发内核 socket 锁死锁导致 Wi-Fi 卡死，建议改用 LuLu 等 Network Extension 防火墙。
   - 若用户决定修改网络或防火墙规则，提醒先退出 Claude Desktop 与所有登录态的 Claude Code 终端再操作。

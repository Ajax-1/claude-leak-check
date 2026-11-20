import { BRAND } from "../config/brand.js";
import type { AuditReport } from "../types/report.js";
import { CLIENT_SCRIPT } from "./client-script.js";
import { REPORT_STYLES } from "./styles.js";

export interface RenderHtmlOptions {
  interactiveToken?: string;
}

function safeJsonEmbed(data: unknown): string {
  return JSON.stringify(data).replace(/</g, "\\u003c").replace(/-->/g, "--\\>");
}

export function renderReportHtml(report: AuditReport, options: RenderHtmlOptions = {}): string {
  const token = options.interactiveToken || "";
  const guideLinkHtml = BRAND.guideUrl
    ? `<a href="${BRAND.guideUrl}" target="_blank" rel="noopener noreferrer">进阶防封指南 ↗</a> · `
    : "";

  return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Claude Leak Check — 本地防封与分流泄漏体检报告 (${report.finalScore}/100 · ${report.grade})</title>
  <style>${REPORT_STYLES}</style>
</head>
<body>
  <!-- 断网演练后防忘开梯子置顶安全横幅 -->
  <div id="restoreBanner" class="restore-alert-banner">
    <span id="restoreBannerMsg"></span>
    <button id="restoreBannerBtn" class="chip-btn" style="background:#fff;color:#b91c1c;border:none"></button>
  </div>

  <!-- Detached Fluid Island Topbar -->
  <header class="nav-wrap">
    <nav class="fluid-island" aria-label="Report Controls">
      <div class="brand-cluster">
        <span class="brand-dot"></span>
        <span class="brand-title">claude-leak-check</span>
      </div>
      <span id="navEyebrow" class="eyebrow-pill"></span>
      <div class="nav-actions">
        <button id="maskBtn" class="chip-btn" type="button">
          <span style="font-family:var(--font-mono)">*</span>
          <span id="maskBtnLabel"></span>
        </button>
        <button id="langBtn" class="chip-btn" type="button">EN / 中文</button>
        <button id="themeBtn" class="chip-btn" type="button">Light</button>
        <button id="shareBtn" class="cta-island-btn" type="button">
          <span id="shareBtnText"></span>
          <span class="btn-icon-circle">↗</span>
        </button>
      </div>
    </nav>
  </header>

  <main class="container">
    <section class="hero-header reveal">
      <h1 id="heroTitle" class="hero-headline"></h1>
      <p id="heroSub" class="hero-sub"></p>
    </section>

    <!-- 致命红线警告框 -->
    <section id="redlineWrap" class="redline-banner reveal" style="display:none">
      <div class="bezel-shell">
        <div class="bezel-core">
          <div class="redline-title">
            <span class="tabular">[!]</span>
            <span id="redlineTitleText"></span>
          </div>
          <ul id="redlineList" class="redline-list"></ul>
        </div>
      </div>
    </section>

    <!-- 第一屏不对称双卡片：左侧总分仪表盘 (5 cols) + 右侧断网防漏演练舱 (7 cols) -->
    <section class="bento-top reveal">
      <div class="bezel-shell col-score">
        <div class="bezel-core">
          <div class="score-top-row">
            <div class="score-ring-box">
              <svg class="score-ring-svg" viewBox="0 0 120 120">
                <circle class="score-ring-bg" cx="60" cy="60" r="52"></circle>
                <circle id="scoreRingFg" class="score-ring-fg" cx="60" cy="60" r="52"></circle>
              </svg>
              <div class="score-ring-center">
                <span id="scoreNum" class="score-num tabular"></span>
                <span id="scoreDenom" class="score-denom"></span>
              </div>
            </div>
            <div class="grade-meta">
              <span id="gradePill" class="grade-pill"></span>
              <span class="card-subtitle tabular" style="font-size:11.5px">
                ID: #${report.reportId} · ${report.platform}/${report.arch} · ${report.durationMs}ms
              </span>
            </div>
          </div>
          <div id="postureMiniGrid" class="posture-pills-grid"></div>
          <div id="scoreKvStack" class="exit-capsule-stack"></div>
        </div>
      </div>

      <div class="bezel-shell col-drill">
        <div class="bezel-core">
          <div class="drill-header">
            <div>
              <h2 id="drillTitle" class="card-title"></h2>
              <p id="drillSub" class="card-subtitle"></p>
            </div>
          </div>
          <div id="drillSteps" class="drill-steps"></div>
          <div id="drillResultBox" class="drill-result-box"></div>
          <div id="drillActions" class="drill-action-bar"></div>
        </div>
      </div>
    </section>

    <!-- 第二屏：五大评分维度拆解卡片 -->
    <section class="section-block reveal">
      <div class="section-heading-row">
        <h2 id="secModulesTitle" class="section-title"></h2>
        <span id="secModulesCap" class="section-caption"></span>
      </div>
      <div id="modulesGrid" class="modules-grid"></div>
    </section>

    <!-- 第三屏：25 个暗桩域名出口热力矩阵 -->
    <section class="section-block reveal">
      <div class="section-heading-row">
        <h2 id="secMatrixTitle" class="section-title"></h2>
        <span id="secMatrixCap" class="section-caption"></span>
      </div>
      <div class="bezel-shell">
        <div class="bezel-core">
          <div id="domainFilterBar" class="domain-filter-bar"></div>
          <div id="domainGrid" class="domain-grid"></div>
        </div>
      </div>
    </section>

    <!-- 第四屏：本机 Claude 全家桶入口与防火墙覆盖盘点 -->
    <section class="section-block reveal">
      <div class="section-heading-row">
        <h2 id="secBinTitle" class="section-title"></h2>
        <span id="secBinCap" class="section-caption"></span>
      </div>
      <div class="bezel-shell">
        <div class="bezel-core">
          <div id="binList" class="bin-list"></div>
        </div>
      </div>
    </section>

    <footer class="footer-bar">
      <div class="tabular">
        <code>$ ${BRAND.cliCommand}</code> · v${BRAND.version}
      </div>
      <div>
        ${guideLinkHtml}<a href="${BRAND.repoUrl}" target="_blank" rel="noopener noreferrer">${BRAND.repoShort} ↗</a>
      </div>
    </footer>
  </main>

  <!-- 100% 强制脱敏晒图海报弹窗 -->
  <div id="posterModal" class="modal-backdrop" role="dialog" aria-modal="true">
    <div class="modal-dialog bezel-shell">
      <div class="bezel-core">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
          <div>
            <h3 id="modalTitle" class="card-title"></h3>
            <p id="modalSub" class="card-subtitle"></p>
          </div>
          <button id="btnCloseModal" class="chip-btn" type="button"></button>
        </div>

        <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
          <button id="btnRatio169" class="chip-btn" type="button"></button>
          <button id="btnRatio34" class="chip-btn" type="button"></button>
        </div>

        <div class="poster-preview-wrap">
          <canvas id="posterCanvas"></canvas>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:space-between;align-items:center">
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button id="btnCopyImg" class="cta-island-btn cta-accent" type="button">
              <span id="btnCopyImgText"></span>
              <span class="btn-icon-circle">↗</span>
            </button>
            <button id="btnDownloadPng" class="chip-btn" type="button"></button>
            <button id="btnCopyText" class="chip-btn" type="button"></button>
          </div>
          <button id="btnExportHtml" class="chip-btn" type="button"></button>
        </div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    window.__AUDIT_REPORT__ = ${safeJsonEmbed(report)};
    window.__BRAND_CONFIG__ = ${safeJsonEmbed(BRAND)};
    window.__INTERACTIVE_TOKEN__ = ${safeJsonEmbed(token)};
  </script>
  <script>${CLIENT_SCRIPT}</script>
</body>
</html>`;
}

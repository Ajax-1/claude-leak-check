export const REPORT_STYLES = `
:root {
  --bg-canvas: #09090b;
  --bg-ambient-1: rgba(217, 119, 87, 0.08);
  --bg-ambient-2: rgba(16, 185, 129, 0.05);
  --shell-bg: rgba(255, 250, 244, 0.032);
  --shell-border: rgba(255, 248, 240, 0.085);
  --core-bg: #111115;
  --core-bg-elevated: #17171d;
  --core-border: rgba(255, 255, 255, 0.06);
  --core-highlight: inset 0 1px 0 rgba(255, 255, 255, 0.08);
  --nav-glass: rgba(17, 17, 21, 0.78);
  --text-primary: #f5f2eb;
  --text-secondary: #a6a097;
  --text-muted: #6e6a63;
  --accent: #d97757;
  --accent-soft: rgba(217, 119, 87, 0.14);
  --pass: #10b981;
  --pass-soft: rgba(16, 185, 129, 0.13);
  --warn: #f59e0b;
  --warn-soft: rgba(245, 158, 11, 0.14);
  --crit: #ef4444;
  --crit-soft: rgba(239, 68, 68, 0.14);
  --gold: #eab308;
  --gold-soft: rgba(234, 179, 8, 0.16);
  --font-sans: "Avenir Next", "Plus Jakarta Sans", "SF Pro Display", -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  --font-mono: "SF Mono", "JetBrains Mono", "Menlo", "Consolas", ui-monospace, monospace;
  --spring: cubic-bezier(0.32, 0.72, 0, 1);
}

[data-theme="light"] {
  --bg-canvas: #f6f3ec;
  --bg-ambient-1: rgba(198, 97, 63, 0.07);
  --bg-ambient-2: rgba(16, 185, 129, 0.05);
  --shell-bg: rgba(24, 20, 16, 0.038);
  --shell-border: rgba(24, 20, 16, 0.08);
  --core-bg: #ffffff;
  --core-bg-elevated: #faf8f4;
  --core-border: rgba(24, 20, 16, 0.07);
  --core-highlight: 0 10px 30px -12px rgba(24, 20, 16, 0.07);
  --nav-glass: rgba(255, 253, 249, 0.84);
  --text-primary: #171512;
  --text-secondary: #57524a;
  --text-muted: #8a8379;
  --accent: #c6613f;
  --accent-soft: rgba(198, 97, 63, 0.11);
  --pass: #059669;
  --pass-soft: rgba(5, 150, 105, 0.11);
  --warn: #d97706;
  --warn-soft: rgba(217, 119, 6, 0.12);
  --crit: #dc2626;
  --crit-soft: rgba(220, 38, 38, 0.11);
  --gold: #ca8a04;
  --gold-soft: rgba(202, 138, 4, 0.14);
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  background: var(--bg-canvas);
  color: var(--text-primary);
  font-family: var(--font-sans);
  -webkit-font-smoothing: antialiased;
  scroll-behavior: smooth;
}

body {
  min-height: 100dvh;
  background:
    radial-gradient(circle at 14% 8%, var(--bg-ambient-1), transparent 42%),
    radial-gradient(circle at 86% 14%, var(--bg-ambient-2), transparent 38%),
    var(--bg-canvas);
  padding-bottom: 96px;
  transition: background-color 0.5s var(--spring), color 0.5s var(--spring);
}

/* Fixed ultra-subtle grain overlay */
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 40;
  opacity: 0.025;
  background-image: radial-gradient(var(--text-primary) 0.75px, transparent 0.75px);
  background-size: 16px 16px;
}

.tabular {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

/* Safety restore banner after drill */
.restore-alert-banner {
  position: sticky;
  top: 0;
  z-index: 60;
  background: #dc2626;
  color: #fff;
  padding: 10px 20px;
  font-size: 13px;
  font-weight: 600;
  display: none;
  align-items: center;
  justify-content: center;
  gap: 12px;
}
.restore-alert-banner.visible {
  display: flex;
}

/* Detached Fluid Island Navbar */
.nav-wrap {
  position: sticky;
  top: 18px;
  z-index: 50;
  display: flex;
  justify-content: center;
  padding: 0 16px;
  margin-top: 18px;
}

.fluid-island {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  padding: 8px 10px 8px 18px;
  border-radius: 9999px;
  background: var(--nav-glass);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--shell-border);
  box-shadow: 0 18px 40px -16px rgba(0, 0, 0, 0.35);
}

.brand-cluster {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-right: 8px;
}

.brand-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: var(--accent);
  box-shadow: 0 0 12px var(--accent);
}

.brand-title {
  font-weight: 700;
  font-size: 14px;
  letter-spacing: -0.01em;
}

.eyebrow-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 11px;
  border-radius: 9999px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  background: var(--shell-bg);
  border: 1px solid var(--shell-border);
  color: var(--text-secondary);
}

.nav-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.chip-btn {
  appearance: none;
  border: 1px solid var(--shell-border);
  background: var(--core-bg-elevated);
  color: var(--text-primary);
  border-radius: 9999px;
  padding: 7px 13px;
  font-size: 12px;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: transform 0.35s var(--spring), background-color 0.35s var(--spring), border-color 0.35s var(--spring);
}
.chip-btn:hover {
  border-color: var(--accent);
  transform: translateY(-1px);
}
.chip-btn:active {
  transform: scale(0.97);
}

/* Button-in-Button CTA */
.cta-island-btn {
  appearance: none;
  border: none;
  background: var(--text-primary);
  color: var(--bg-canvas);
  border-radius: 9999px;
  padding: 6px 6px 6px 16px;
  font-size: 12.5px;
  font-weight: 700;
  font-family: inherit;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  transition: transform 0.4s var(--spring), opacity 0.4s var(--spring);
}
.cta-island-btn:hover {
  transform: translateY(-1px);
}
.cta-island-btn:active {
  transform: scale(0.98);
}
.cta-island-btn .btn-icon-circle {
  width: 26px;
  height: 26px;
  border-radius: 9999px;
  background: rgba(128, 128, 128, 0.22);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: transform 0.4s var(--spring);
}
.cta-island-btn:hover .btn-icon-circle {
  transform: translate(2px, -1px) scale(1.06);
}

.cta-accent {
  background: var(--accent);
  color: #fff;
}
.cta-accent .btn-icon-circle {
  background: rgba(255, 255, 255, 0.2);
}

/* Container & Macro Rhythm */
.container {
  max-width: 1220px;
  margin: 0 auto;
  padding: 36px 24px 0;
}

.hero-header {
  margin-bottom: 28px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.hero-headline {
  font-size: clamp(26px, 3.4vw, 40px);
  font-weight: 750;
  letter-spacing: -0.03em;
  line-height: 1.15;
}

.hero-sub {
  color: var(--text-secondary);
  font-size: 14.5px;
  max-width: 780px;
  line-height: 1.6;
}

/* Double-Bezel (Doppelrand) Hardware Card Architecture */
.bezel-shell {
  background: var(--shell-bg);
  border: 1px solid var(--shell-border);
  border-radius: 28px;
  padding: 6px;
  transition: transform 0.55s var(--spring), border-color 0.45s var(--spring);
}

.bezel-core {
  background: var(--core-bg);
  border: 1px solid var(--core-border);
  box-shadow: var(--core-highlight);
  border-radius: 22px;
  padding: 26px;
  height: 100%;
  display: flex;
  flex-direction: column;
}

/* Entry Reveal */
.reveal {
  opacity: 0;
  transform: translateY(18px);
  transition: opacity 0.7s var(--spring), transform 0.7s var(--spring);
}
.reveal.in-view {
  opacity: 1;
  transform: translateY(0);
}

/* Redline Alert Box */
.redline-banner {
  margin-bottom: 22px;
}
.redline-banner .bezel-shell {
  background: var(--crit-soft);
  border-color: rgba(239, 68, 68, 0.35);
}
.redline-banner .bezel-core {
  padding: 20px 24px;
  border-color: rgba(239, 68, 68, 0.25);
}
.redline-title {
  color: var(--crit);
  font-weight: 700;
  font-size: 15px;
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.redline-list {
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13.5px;
  color: var(--text-primary);
}
.redline-list li::before {
  content: "▸ ";
  color: var(--crit);
  font-weight: bold;
}

/* Asymmetric Top Bento Grid (5 cols + 7 cols) */
.bento-top {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 18px;
  margin-bottom: 22px;
}
.col-score {
  grid-column: span 5;
}
.col-drill {
  grid-column: span 7;
}

@media (max-width: 920px) {
  .col-score,
  .col-drill {
    grid-column: span 12;
  }
  .container {
    padding: 24px 16px 0;
  }
}

/* Score Gauge & Badges */
.score-top-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
}

.score-ring-box {
  position: relative;
  width: 132px;
  height: 132px;
  flex-shrink: 0;
}
.score-ring-svg {
  width: 132px;
  height: 132px;
  transform: rotate(-90deg);
}
.score-ring-bg {
  fill: none;
  stroke: var(--shell-border);
  stroke-width: 9;
}
.score-ring-fg {
  fill: none;
  stroke-width: 9;
  stroke-linecap: round;
  transition: stroke-dashoffset 0.9s var(--spring), stroke 0.5s var(--spring);
}
.score-ring-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.score-num {
  font-size: 38px;
  font-weight: 800;
  line-height: 1;
  letter-spacing: -0.04em;
}
.score-denom {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}

.grade-meta {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.grade-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  align-self: flex-start;
  padding: 6px 14px;
  border-radius: 999px;
  font-weight: 800;
  font-size: 14px;
  letter-spacing: 0.02em;
}
.grade-splus {
  background: var(--gold-soft);
  color: var(--gold);
  border: 1px solid rgba(234, 179, 8, 0.4);
}
.grade-pass {
  background: var(--pass-soft);
  color: var(--pass);
  border: 1px solid rgba(16, 185, 129, 0.32);
}
.grade-warn {
  background: var(--warn-soft);
  color: var(--warn);
  border: 1px solid rgba(245, 158, 11, 0.32);
}
.grade-crit {
  background: var(--crit-soft);
  color: var(--crit);
  border: 1px solid rgba(239, 68, 68, 0.35);
}

.posture-pills-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  margin-bottom: 16px;
}
.posture-mini-card {
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
  border-radius: 12px;
  padding: 9px 12px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.posture-mini-k {
  font-size: 10.5px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.posture-mini-v {
  font-size: 12.5px;
  font-weight: 700;
}

.exit-capsule-stack {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid var(--core-border);
}

.kv-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  font-size: 12.5px;
}
.kv-label {
  color: var(--text-secondary);
}
.kv-val {
  font-weight: 600;
  text-align: right;
}

/* Status Pill */
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 650;
}
.st-pass {
  background: var(--pass-soft);
  color: var(--pass);
}
.st-warn {
  background: var(--warn-soft);
  color: var(--warn);
}
.st-crit {
  background: var(--crit-soft);
  color: var(--crit);
}
.st-info {
  background: var(--accent-soft);
  color: var(--accent);
}

/* Kill-Switch Interactive Drill Cabin */
.drill-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}
.card-title {
  font-size: 17px;
  font-weight: 700;
  letter-spacing: -0.015em;
}
.card-subtitle {
  font-size: 13px;
  color: var(--text-secondary);
  margin-top: 4px;
  line-height: 1.5;
}

.drill-steps {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
  margin-bottom: 16px;
}
@media (max-width: 640px) {
  .drill-steps {
    grid-template-columns: 1fr;
  }
}

.drill-step-card {
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
  border-radius: 14px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.drill-step-card.active {
  border-color: var(--accent);
}
.drill-step-card.done {
  border-color: rgba(16, 185, 129, 0.4);
}
.step-num {
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
}
.step-title {
  font-size: 13px;
  font-weight: 650;
}
.step-desc {
  font-size: 11.5px;
  color: var(--text-secondary);
  line-height: 1.45;
}

.drill-action-bar {
  margin-top: auto;
  padding-top: 14px;
  border-top: 1px solid var(--core-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}

.drill-result-box {
  margin-bottom: 12px;
  padding: 12px 14px;
  border-radius: 14px;
  font-size: 12.5px;
  line-height: 1.55;
  border: 1px solid var(--core-border);
  background: var(--core-bg-elevated);
}

/* 5 Module Breakdown Cards */
.section-block {
  margin-bottom: 26px;
}
.section-heading-row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
  padding: 0 4px;
}
.section-title {
  font-size: 19px;
  font-weight: 750;
  letter-spacing: -0.02em;
}
.section-caption {
  font-size: 12.5px;
  color: var(--text-secondary);
}

.modules-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}
.mod-card-wide {
  grid-column: span 6;
}
.mod-card-third {
  grid-column: span 4;
}
@media (max-width: 920px) {
  .mod-card-wide,
  .mod-card-third {
    grid-column: span 12;
  }
}

.mod-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 12px;
}
.mod-score-pill {
  font-size: 13px;
  font-weight: 700;
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
}
.mod-bar-track {
  height: 5px;
  border-radius: 99px;
  background: var(--shell-border);
  overflow: hidden;
  margin-bottom: 16px;
}
.mod-bar-fill {
  height: 100%;
  border-radius: 99px;
  transition: width 0.8s var(--spring);
}

.finding-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.finding-item {
  padding: 11px 13px;
  border-radius: 13px;
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
}
.finding-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
  font-size: 13px;
  font-weight: 650;
  line-height: 1.4;
}
.finding-detail {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 5px;
  line-height: 1.5;
}
.finding-fix {
  font-size: 11.5px;
  color: var(--accent);
  margin-top: 6px;
  line-height: 1.45;
}

/* 25 Stealth Domain Matrix Grid */
.domain-filter-bar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.domain-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(265px, 1fr));
  gap: 10px;
}
.domain-cell {
  padding: 12px 14px;
  border-radius: 14px;
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
  display: flex;
  flex-direction: column;
  gap: 6px;
  transition: transform 0.35s var(--spring), border-color 0.35s var(--spring);
}
.domain-cell:hover {
  transform: translateY(-2px);
  border-color: var(--shell-border);
}
.domain-cell.dom-crit {
  border-color: rgba(239, 68, 68, 0.42);
  background: var(--crit-soft);
}
.domain-cell.dom-warn {
  border-color: rgba(245, 158, 11, 0.35);
}
.dom-host-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.dom-host {
  font-size: 12.5px;
  font-weight: 700;
  word-break: break-all;
}
.dom-dot {
  width: 8px;
  height: 8px;
  border-radius: 99px;
  flex-shrink: 0;
}
.dom-label {
  font-size: 11.5px;
  color: var(--text-secondary);
}
.dom-meta-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  font-size: 11px;
  color: var(--text-muted);
  padding-top: 4px;
  border-top: 1px dashed var(--core-border);
}

/* Binaries & Host Footprint Table */
.bin-list {
  display: flex;
  flex-direction: column;
  gap: 9px;
}
.bin-row {
  padding: 13px 16px;
  border-radius: 14px;
  background: var(--core-bg-elevated);
  border: 1px solid var(--core-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}
.bin-path {
  font-size: 11.5px;
  color: var(--text-muted);
  margin-top: 2px;
  word-break: break-all;
}
.bin-note {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

/* Share Poster Modal */
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 80;
  background: rgba(5, 5, 7, 0.78);
  backdrop-filter: blur(22px);
  -webkit-backdrop-filter: blur(22px);
  display: none;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.modal-backdrop.open {
  display: flex;
}
.modal-dialog {
  max-width: 900px;
  width: 100%;
  max-height: 92dvh;
  overflow-y: auto;
}
.poster-preview-wrap {
  margin: 16px 0;
  display: flex;
  justify-content: center;
  background: rgba(0, 0, 0, 0.28);
  border-radius: 16px;
  padding: 14px;
  border: 1px solid var(--core-border);
}
#posterCanvas {
  max-width: 100%;
  max-height: 54dvh;
  height: auto;
  border-radius: 12px;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
}

.toast {
  position: fixed;
  bottom: 26px;
  left: 50%;
  transform: translateX(-50%) translateY(24px);
  opacity: 0;
  pointer-events: none;
  z-index: 95;
  background: var(--text-primary);
  color: var(--bg-canvas);
  padding: 10px 20px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 650;
  transition: opacity 0.35s var(--spring), transform 0.35s var(--spring);
}
.toast.show {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}

.footer-bar {
  margin-top: 44px;
  padding-top: 22px;
  border-top: 1px solid var(--shell-border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  color: var(--text-muted);
}
.footer-bar a {
  color: var(--text-secondary);
  text-decoration: none;
}
.footer-bar a:hover {
  color: var(--accent);
}
`;

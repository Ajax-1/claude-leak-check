export interface BrandConfig {
  packageName: string;
  cliCommand: string;
  repoUrl: string;
  repoShort: string;
  authorHandle: string;
  guideUrl?: string;
  version: string;
}

export const BRAND: BrandConfig = {
  packageName: "claude-leak-check",
  cliCommand: "npx claude-leak-check",
  repoUrl: "https://github.com/Ajax-1/claude-leak-check",
  repoShort: "github.com/Ajax-1/claude-leak-check",
  authorHandle: "@Ajax-1",
  // 可选：后续可填入防封配置指南长文或社群链接，留空则界面隐藏外链按钮
  guideUrl: "",
  version: "0.1.3",
};

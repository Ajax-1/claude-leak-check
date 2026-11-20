import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const cliPath = resolve("dist/cli.js");
const current = readFileSync(cliPath, "utf8");
if (!current.startsWith("#!/usr/bin/env node")) {
  writeFileSync(cliPath, `#!/usr/bin/env node\n${current}`, "utf8");
}
chmodSync(cliPath, 0o755);

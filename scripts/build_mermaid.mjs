import { copyFile, mkdir, rm } from "node:fs/promises";

const mermaidOutputDirectory = "static/vendor/mermaid";

await rm(mermaidOutputDirectory, { recursive: true, force: true });
await mkdir(mermaidOutputDirectory, { recursive: true });

await Promise.all([
  copyFile(
    "node_modules/mermaid/dist/mermaid.min.js",
    `${mermaidOutputDirectory}/mermaid.min.js`,
  ),
  copyFile(
    "node_modules/mermaid/LICENSE",
    `${mermaidOutputDirectory}/LICENSE`,
  ),
]);

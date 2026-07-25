import { copyFile, mkdir, rm } from "node:fs/promises";

const outputDirectory = "static/vendor/mermaid";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await Promise.all([
  copyFile(
    "node_modules/mermaid/dist/mermaid.min.js",
    `${outputDirectory}/mermaid.min.js`,
  ),
  copyFile(
    "node_modules/mermaid/LICENSE",
    `${outputDirectory}/LICENSE`,
  ),
]);

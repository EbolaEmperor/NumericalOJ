import { copyFile, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "static/vendor/shiki-bash";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await build({
  entryPoints: ["frontend/markdown/bash-highlighter.js"],
  outfile: `${outputDirectory}/highlighter.js`,
  bundle: true,
  minify: true,
  legalComments: "linked",
  logLevel: "info",
  format: "iife",
  globalName: "NumOJBashHighlighter",
});

await copyFile(
  "node_modules/shiki/LICENSE",
  `${outputDirectory}/LICENSE`,
);

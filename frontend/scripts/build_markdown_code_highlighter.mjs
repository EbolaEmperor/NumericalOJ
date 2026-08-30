import { copyFile, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "public/static/vendor/shiki-markdown";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await build({
  entryPoints: ["markdown/code-highlighter.js"],
  outfile: `${outputDirectory}/highlighter.js`,
  bundle: true,
  minify: true,
  legalComments: "linked",
  logLevel: "info",
  format: "iife",
  globalName: "NumOJMarkdownCodeHighlighter",
});

await copyFile(
  "node_modules/shiki/LICENSE",
  `${outputDirectory}/LICENSE`,
);

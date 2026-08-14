import { copyFile, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "static/vendor/monaco";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const shared = {
  bundle: true,
  minify: true,
  legalComments: "linked",
  logLevel: "info",
};

await build({
  ...shared,
  entryPoints: ["frontend/monaco/editor.js"],
  outfile: `${outputDirectory}/editor.js`,
  format: "iife",
  globalName: "NumericalOJMonaco",
  loader: {
    ".ttf": "file",
  },
  assetNames: "assets/[name]-[hash]",
});

await build({
  ...shared,
  entryPoints: ["node_modules/monaco-editor/esm/vs/editor/editor.worker.js"],
  outfile: `${outputDirectory}/editor.worker.js`,
  format: "iife",
});

await copyFile(
  "node_modules/@leanprover/unicode-input/LICENSE",
  `${outputDirectory}/lean4-unicode-input.LICENSE`,
);

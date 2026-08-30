import { copyFile, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "public/static/vendor/monaco";

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const shared = {
  bundle: true,
  minify: true,
  legalComments: "linked",
  logLevel: "info",
};

for (const [entryPoint, outputName] of [
  ["monaco/editor.js", "editor"],
  ["monaco/editor-minimal.js", "editor-minimal"],
]) {
  await build({
    ...shared,
    entryPoints: [entryPoint],
    outfile: `${outputDirectory}/${outputName}.js`,
    format: "iife",
    globalName: "NumericalOJMonaco",
    loader: {
      ".ttf": "file",
    },
    assetNames: "assets/[name]-[hash]",
  });
}

await build({
  ...shared,
  entryPoints: ["node_modules/monaco-editor/esm/vs/editor/editor.worker.js"],
  outfile: `${outputDirectory}/editor.worker.js`,
  format: "iife",
});

await Promise.all([
  copyFile(
    "node_modules/monaco-editor/LICENSE",
    `${outputDirectory}/LICENSE`,
  ),
  copyFile(
    "node_modules/monaco-editor/ThirdPartyNotices.txt",
    `${outputDirectory}/ThirdPartyNotices.txt`,
  ),
  copyFile(
    "node_modules/@leanprover/unicode-input/LICENSE",
    `${outputDirectory}/lean4-unicode-input.LICENSE`,
  ),
]);

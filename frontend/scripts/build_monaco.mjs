import { copyFile, mkdir, readFile, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "public/static/vendor/monaco";
const eduOutputDirectory = "../vibehub_examples/dynamic-balance/static/editor";

const safariClipboardGuard = {
  name: "monaco-safari-clipboard-guard",
  setup(buildContext) {
    buildContext.onLoad({
      filter: /monaco-editor\/esm\/vs\/platform\/clipboard\/browser\/clipboardService\.js$/,
    }, async ({ path }) => {
      const source = await readFile(path, "utf8");
      const unguarded = "if (isSafari || isWebkitWebView) {";
      const guarded = "if ((isSafari || isWebkitWebView) && mainWindow.navigator.clipboard?.write && typeof ClipboardItem !== 'undefined') {";
      if (!source.includes(unguarded)) {
        throw new Error("Monaco Safari clipboard guard target changed; update build_monaco.mjs before publishing.");
      }
      return {
        contents: source.replace(unguarded, guarded),
        loader: "js",
      };
    });
  },
};

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const shared = {
  bundle: true,
  minify: true,
  legalComments: "linked",
  logLevel: "info",
  plugins: [safariClipboardGuard],
};

for (const [entryPoint, outputName] of [
  ["monaco/editor.js", "editor"],
  ["monaco/editor-minimal.js", "editor-minimal"],
]) {
  await build({
    ...shared,
    entryPoints: [entryPoint],
    outfile: `${outputDirectory}/${outputName}.js`,
    format: "esm",
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
  format: "esm",
});

// 教学作品用经典脚本加载同一套编辑器，避免 opaque iframe 的模块 CORS 限制。
// Worker 内嵌为经典 IIFE，运行时只创建当前 iframe 所有的 Blob URL。
const eduWorker = await build({
  ...shared,
  entryPoints: ["node_modules/monaco-editor/esm/vs/editor/editor.worker.js"],
  format: "iife",
  legalComments: "inline",
  write: false,
});
if (eduWorker.outputFiles.length !== 1) {
  throw new Error("教学编辑器 Worker 必须是自包含脚本");
}
await rm(eduOutputDirectory, { recursive: true, force: true });
await mkdir(eduOutputDirectory, { recursive: true });
await build({
  ...shared,
  entryPoints: ["monaco/edu-editor.js"],
  outfile: `${eduOutputDirectory}/editor.js`,
  format: "iife",
  globalName: "NumOJEduEditor",
  define: {
    __NUMOJ_EDU_WORKER_SOURCE__: JSON.stringify(eduWorker.outputFiles[0].text),
  },
  loader: {
    ".ttf": "dataurl",
  },
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
  copyFile(
    "node_modules/monaco-editor/LICENSE",
    `${eduOutputDirectory}/LICENSE`,
  ),
  copyFile(
    "node_modules/monaco-editor/ThirdPartyNotices.txt",
    `${eduOutputDirectory}/ThirdPartyNotices.txt`,
  ),
  copyFile(
    "node_modules/@leanprover/unicode-input/LICENSE",
    `${eduOutputDirectory}/lean4-unicode-input.LICENSE`,
  ),
]);

import { copyFile, mkdir, readFile, rm } from "node:fs/promises";
import { build } from "esbuild";

const outputDirectory = "public/static/vendor/monaco";

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

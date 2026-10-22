// 教学作品复用 OJ 的 Monaco 与 C++ grammar；不连接需要 OJ 登录态的语言服务。
import * as monaco from "./editor-minimal.js";
import { monacoOptions, prepareMonaco } from "../src/editor/codeEditorRuntime.ts";

let workerUrl;

// sandbox iframe 的 origin 为 null，不能从站点 URL 直接启动 Worker。
// Worker 与编辑器一起构建并内嵌，Blob 由当前 iframe 创建，不需要外网或额外权限。
globalThis.MonacoEnvironment = {
  getWorker(_moduleId, label) {
    if (!workerUrl) {
      workerUrl = URL.createObjectURL(new Blob([__NUMOJ_EDU_WORKER_SOURCE__], {
        type: "application/javascript",
      }));
    }
    return new Worker(workerUrl, { name: label });
  },
};

globalThis.addEventListener("pagehide", () => {
  if (workerUrl) URL.revokeObjectURL(workerUrl);
  workerUrl = undefined;
});

export function create(host, { onRun } = {}) {
  const editor = monaco.editor.create(host, monacoOptions({
    value: "",
    language: "cpp",
    theme: prepareMonaco(monaco),
    readOnly: true,
    lineNumbers: "on",
    tabSize: 4,
    insertSpaces: true,
    detectIndentation: false,
    quickSuggestions: false,
    suggestOnTriggerCharacters: false,
    wordBasedSuggestions: "off",
    links: false,
    colorDecorators: false,
    "semanticHighlighting.enabled": false,
  }));
  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
    if (!editor.getOption(monaco.editor.EditorOption.readOnly) && typeof onRun === "function") {
      onRun();
    }
  });
  return editor;
}

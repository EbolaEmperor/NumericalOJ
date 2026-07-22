// 只打包编辑器交互能力与 NumericalOJ 当前支持的通用语言，不引入 LSP。
import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import c from "@shikijs/langs/c";
import cpp from "@shikijs/langs/cpp";
import matlab from "@shikijs/langs/matlab";
import python from "@shikijs/langs/python";
import darkPlus from "@shikijs/themes/dark-plus";
import { shikiToMonaco, textmateThemeToMonacoTheme } from "@shikijs/monaco";
import "monaco-editor/languages/definitions/cpp/register.js";
import "monaco-editor/languages/definitions/python/register.js";
import * as monaco from "monaco-editor/editor/editor.main.js";

let textMateReadyPromise;

// Monaco Standalone 不会像完整 VS Code 那样自动把 LSP semantic token type
// 映射回 TextMate scope。显式补齐 Dark+ 的语义颜色，否则语言服务器已经识别
// 的 class/method 仍会被默认前景色画成白色。
const darkPlusSemanticRules = [
  { token: "namespace", foreground: "4EC9B0" },
  { token: "type", foreground: "4EC9B0" },
  { token: "class", foreground: "4EC9B0" },
  { token: "interface", foreground: "4EC9B0" },
  { token: "enum", foreground: "4EC9B0" },
  { token: "typeParameter", foreground: "4EC9B0" },
  { token: "concept", foreground: "4EC9B0" },
  { token: "enumMember", foreground: "4FC1FF" },
  { token: "function", foreground: "DCDCAA" },
  { token: "method", foreground: "DCDCAA" },
  { token: "decorator", foreground: "DCDCAA" },
  { token: "variable", foreground: "9CDCFE" },
  { token: "variable.readonly", foreground: "4FC1FF" },
  { token: "parameter", foreground: "9CDCFE" },
  { token: "selfParameter", foreground: "9CDCFE" },
  { token: "clsParameter", foreground: "9CDCFE" },
  { token: "property", foreground: "9CDCFE" },
  { token: "keyword", foreground: "569CD6" },
  { token: "macro", foreground: "C586C0" },
  { token: "modifier", foreground: "569CD6" },
  { token: "label", foreground: "C8C8C8" },
  { token: "comment", foreground: "6A9955" },
];

export function prepareTextMateHighlighting() {
  if (!textMateReadyPromise) {
    textMateReadyPromise = createHighlighterCore({
      langs: [c, cpp, matlab, python],
      themes: [darkPlus],
      engine: createJavaScriptRegexEngine(),
    }).then((highlighter) => {
      shikiToMonaco(highlighter, monaco);
      const theme = textmateThemeToMonacoTheme(darkPlus);
      monaco.editor.defineTheme("dark-plus", {
        ...theme,
        rules: [...theme.rules, ...darkPlusSemanticRules],
      });
      return highlighter;
    });
  }
  return textMateReadyPromise;
}

export * from "monaco-editor/editor/editor.main.js";

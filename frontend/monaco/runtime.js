import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import { shikiToMonaco, textmateThemeToMonacoTheme } from "@shikijs/monaco";
import * as monaco from "monaco-editor/editor/editor.api.js";

import darkPlus from "../lean4-theme.js";
import {
  attachLean4UnicodeInput as attachUnicodeInput,
  getLean4UnicodeAbbreviations,
} from "../lean4-unicode-input.js";

let textMateLanguages = [];
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
  { token: "dependentType", foreground: "4EC9B0" },
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
  { token: "lean4.keyword", foreground: "C586C0" },
  { token: "lean4.variable", foreground: "9CDCFE" },
  { token: "lean4.variable.readonly", foreground: "4FC1FF" },
  { token: "lean4.parameter", foreground: "9CDCFE" },
  { token: "lean4.property", foreground: "4FC1FF" },
  { token: "lean4.function", foreground: "DCDCAA" },
  {
    token: "lean4.function.declaration",
    foreground: "DCDCAA",
    fontStyle: "bold",
  },
  {
    token: "lean4.function.definition",
    foreground: "DCDCAA",
    fontStyle: "bold",
  },
  { token: "lean4.namespace", foreground: "4EC9B0" },
  {
    token: "lean4.namespace.declaration",
    foreground: "4EC9B0",
    fontStyle: "bold",
  },
  { token: "lean4.type", foreground: "4EC9B0" },
  {
    token: "lean4.type.declaration",
    foreground: "4EC9B0",
    fontStyle: "bold",
  },
  { token: "lean4.class", foreground: "4EC9B0" },
  { token: "lean4.class.declaration", foreground: "4EC9B0", fontStyle: "bold" },
  { token: "lean4.struct", foreground: "4EC9B0" },
  { token: "lean4.struct.declaration", foreground: "4EC9B0", fontStyle: "bold" },
  { token: "lean4.enum", foreground: "4EC9B0" },
  { token: "lean4.interface", foreground: "4EC9B0" },
  { token: "lean4.typeParameter", foreground: "4EC9B0", fontStyle: "italic" },
  { token: "lean4.enumMember", foreground: "4FC1FF" },
  { token: "lean4.method", foreground: "DCDCAA" },
  { token: "lean4.macro", foreground: "D7BA7D" },
  { token: "lean4.modifier", foreground: "C586C0" },
  { token: "lean4.operator", foreground: "D7BA7D" },
  { token: "lean4.decorator", foreground: "D7BA7D" },
  { token: "lean4.comment", foreground: "6A9955", fontStyle: "italic" },
  { token: "lean4.string", foreground: "CE9178" },
  { token: "lean4.number", foreground: "B5CEA8" },
  {
    token: "lean4.leanSorryLike",
    foreground: "F44747",
    fontStyle: "bold underline",
  },
];

export function configureTextMateLanguages(languages) {
  if (textMateReadyPromise) {
    throw new Error("TextMate 高亮初始化后不能更换语言集合");
  }
  textMateLanguages = [...languages];
}

export function registerTextMateOnlyLanguage(id, extensions, aliases) {
  if (monaco.languages.getLanguages().some((language) => language.id === id)) return;
  monaco.languages.register({ id, extensions, aliases });
}

export function prepareTextMateHighlighting() {
  if (!textMateReadyPromise) {
    textMateReadyPromise = createHighlighterCore({
      langs: textMateLanguages,
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

export function attachLean4UnicodeInput(editor) {
  return attachUnicodeInput(monaco, editor);
}

export { getLean4UnicodeAbbreviations };

// 只打包编辑器交互能力与 NumericalOJ 当前支持的通用语言，不引入 LSP。
import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import c from "@shikijs/langs/c";
import bat from "@shikijs/langs/bat";
import asm from "@shikijs/langs/asm";
import cmake from "@shikijs/langs/cmake";
import clojure from "@shikijs/langs/clojure";
import coffeescript from "@shikijs/langs/coffeescript";
import cpp from "@shikijs/langs/cpp";
import csharp from "@shikijs/langs/csharp";
import css from "@shikijs/langs/css";
import dart from "@shikijs/langs/dart";
import dockerfile from "@shikijs/langs/dockerfile";
import elixir from "@shikijs/langs/elixir";
import erlang from "@shikijs/langs/erlang";
import fsharp from "@shikijs/langs/fsharp";
import go from "@shikijs/langs/go";
import graphql from "@shikijs/langs/graphql";
import groovy from "@shikijs/langs/groovy";
import haskell from "@shikijs/langs/haskell";
import html from "@shikijs/langs/html";
import ini from "@shikijs/langs/ini";
import java from "@shikijs/langs/java";
import javascript from "@shikijs/langs/javascript";
import json from "@shikijs/langs/json";
import jsx from "@shikijs/langs/jsx";
import julia from "@shikijs/langs/julia";
import kotlin from "@shikijs/langs/kotlin";
import latex from "@shikijs/langs/latex";
import less from "@shikijs/langs/less";
import lua from "@shikijs/langs/lua";
import makefile from "@shikijs/langs/makefile";
import matlab from "@shikijs/langs/matlab";
import objectiveC from "@shikijs/langs/objective-c";
import pascal from "@shikijs/langs/pascal";
import perl from "@shikijs/langs/perl";
import php from "@shikijs/langs/php";
import powershell from "@shikijs/langs/powershell";
import protobuf from "@shikijs/langs/protobuf";
import python from "@shikijs/langs/python";
import r from "@shikijs/langs/r";
import ruby from "@shikijs/langs/ruby";
import rust from "@shikijs/langs/rust";
import scala from "@shikijs/langs/scala";
import scss from "@shikijs/langs/scss";
import scheme from "@shikijs/langs/scheme";
import shellscript from "@shikijs/langs/shellscript";
import solidity from "@shikijs/langs/solidity";
import sql from "@shikijs/langs/sql";
import swift from "@shikijs/langs/swift";
import systemVerilog from "@shikijs/langs/system-verilog";
import tcl from "@shikijs/langs/tcl";
import toml from "@shikijs/langs/toml";
import tsx from "@shikijs/langs/tsx";
import typescript from "@shikijs/langs/typescript";
import vb from "@shikijs/langs/vb";
import verilog from "@shikijs/langs/verilog";
import xml from "@shikijs/langs/xml";
import yaml from "@shikijs/langs/yaml";
import { shikiToMonaco, textmateThemeToMonacoTheme } from "@shikijs/monaco";
import lean4 from "../lean4-grammar.js";
import darkPlus from "../lean4-theme.js";
import {
  attachLean4UnicodeInput as attachUnicodeInput,
  getLean4UnicodeAbbreviations,
} from "../lean4-unicode-input.js";
import "monaco-editor/languages/definitions/bat/register.js";
import "monaco-editor/languages/definitions/clojure/register.js";
import "monaco-editor/languages/definitions/coffee/register.js";
import "monaco-editor/languages/definitions/cpp/register.js";
import "monaco-editor/languages/definitions/csharp/register.js";
import "monaco-editor/languages/definitions/css/register.js";
import "monaco-editor/languages/definitions/dart/register.js";
import "monaco-editor/languages/definitions/dockerfile/register.js";
import "monaco-editor/languages/definitions/elixir/register.js";
import "monaco-editor/languages/definitions/fsharp/register.js";
import "monaco-editor/languages/definitions/go/register.js";
import "monaco-editor/languages/definitions/graphql/register.js";
import "monaco-editor/languages/definitions/html/register.js";
import "monaco-editor/languages/definitions/ini/register.js";
import "monaco-editor/languages/definitions/java/register.js";
import "monaco-editor/languages/definitions/javascript/register.js";
import "monaco-editor/languages/definitions/julia/register.js";
import "monaco-editor/languages/definitions/kotlin/register.js";
import "monaco-editor/languages/definitions/less/register.js";
import "monaco-editor/languages/definitions/lua/register.js";
import "monaco-editor/languages/definitions/objective-c/register.js";
import "monaco-editor/languages/definitions/pascal/register.js";
import "monaco-editor/languages/definitions/perl/register.js";
import "monaco-editor/languages/definitions/php/register.js";
import "monaco-editor/languages/definitions/powershell/register.js";
import "monaco-editor/languages/definitions/protobuf/register.js";
import "monaco-editor/languages/definitions/python/register.js";
import "monaco-editor/languages/definitions/r/register.js";
import "monaco-editor/languages/definitions/ruby/register.js";
import "monaco-editor/languages/definitions/rust/register.js";
import "monaco-editor/languages/definitions/scala/register.js";
import "monaco-editor/languages/definitions/scss/register.js";
import "monaco-editor/languages/definitions/scheme/register.js";
import "monaco-editor/languages/definitions/shell/register.js";
import "monaco-editor/languages/definitions/solidity/register.js";
import "monaco-editor/languages/definitions/sql/register.js";
import "monaco-editor/languages/definitions/swift/register.js";
import "monaco-editor/languages/definitions/systemverilog/register.js";
import "monaco-editor/languages/definitions/tcl/register.js";
import "monaco-editor/languages/definitions/typescript/register.js";
import "monaco-editor/languages/definitions/vb/register.js";
import "monaco-editor/languages/definitions/xml/register.js";
import "monaco-editor/languages/definitions/yaml/register.js";
import * as monaco from "monaco-editor/editor/editor.main.js";

function registerTextMateOnlyLanguage(id, extensions, aliases) {
  if (monaco.languages.getLanguages().some((language) => language.id === id)) return;
  monaco.languages.register({ id, extensions, aliases });
}

registerTextMateOnlyLanguage("jsx", [".jsx"], ["JSX", "jsx"]);
registerTextMateOnlyLanguage("tsx", [".tsx"], ["TSX", "tsx"]);
registerTextMateOnlyLanguage("json", [".json", ".jsonc", ".jsonl"], ["JSON", "json"]);
registerTextMateOnlyLanguage("latex", [".tex", ".sty", ".cls", ".bib"], ["LaTeX", "latex", "tex"]);
registerTextMateOnlyLanguage("cmake", [".cmake"], ["CMake", "cmake"]);
registerTextMateOnlyLanguage("makefile", [], ["Makefile", "makefile"]);
registerTextMateOnlyLanguage("asm", [".asm", ".s"], ["Assembly", "asm"]);
registerTextMateOnlyLanguage("erlang", [".erl", ".hrl"], ["Erlang", "erlang"]);
registerTextMateOnlyLanguage("groovy", [".groovy"], ["Groovy", "groovy"]);
registerTextMateOnlyLanguage("haskell", [".hs", ".lhs"], ["Haskell", "haskell"]);
registerTextMateOnlyLanguage("toml", [".toml"], ["TOML", "toml"]);

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

export function prepareTextMateHighlighting() {
  if (!textMateReadyPromise) {
    textMateReadyPromise = createHighlighterCore({
      langs: [
        asm, bat, c, cmake, clojure, coffeescript, cpp, csharp, css, dart,
        dockerfile, elixir, erlang, fsharp, go, graphql, groovy, haskell,
        html, ini, java, javascript, json, jsx, julia, kotlin, latex, lean4,
        less, lua, makefile, matlab, objectiveC, pascal, perl, php, powershell,
        protobuf, python, r, ruby, rust, scala, scheme, scss, shellscript,
        solidity, sql, swift, systemVerilog, tcl, toml, tsx, typescript,
        vb, verilog, xml, yaml,
      ],
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

export * from "monaco-editor/editor/editor.main.js";

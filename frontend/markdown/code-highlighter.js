import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import bash from "@shikijs/langs/bash";
import c from "@shikijs/langs/c";
import cpp from "@shikijs/langs/cpp";
import matlab from "@shikijs/langs/matlab";
import python from "@shikijs/langs/python";
import lean4 from "../lean4-grammar.js";
import githubLight from "./github-light-theme.js";

let highlighterPromise;

const LANGUAGE_ALIASES = Object.freeze({
  bash: "bash",
  sh: "bash",
  shell: "bash",
  shellscript: "bash",
  zsh: "bash",
  ksh: "bash",
  openrc: "bash",
  c: "c",
  cpp: "cpp",
  "c++": "cpp",
  cc: "cpp",
  cxx: "cpp",
  py: "python",
  py3: "python",
  python: "python",
  python3: "python",
  m: "matlab",
  matlab: "matlab",
  octave: "matlab",
  lean: "lean4",
  lean4: "lean4",
});

function getHighlighter() {
  if (!highlighterPromise) {
    highlighterPromise = createHighlighterCore({
      langs: [bash, c, cpp, lean4, matlab, python],
      themes: [githubLight],
      engine: createJavaScriptRegexEngine(),
    }).catch((error) => {
      highlighterPromise = null;
      throw error;
    });
  }
  return highlighterPromise;
}

/**
 * 使用与 Monaco 编辑器相同的 TextMate grammar 和 GitHub Light 主题返回
 * 最小化 token 数据。编辑器本身仍可保持 Dark+；这里只改变 Markdown 画布。
 *
 * DOM 由共享 Markdown 渲染器通过 createTextNode 构造，避免把用户源码重新
 * 作为 HTML 注入；这里只返回颜色、字体样式和原始文本。
 */
export async function tokenize(source, language) {
  const normalized = LANGUAGE_ALIASES[String(language || "").toLowerCase()];
  if (!normalized) throw new Error("该语言不支持 Markdown TextMate 高亮");
  const highlighter = await getHighlighter();
  const result = highlighter.codeToTokens(String(source ?? ""), {
    lang: normalized,
    theme: "github-light-default",
  });
  return {
    tokens: result.tokens.map((line) => line.map((token) => ({
      color: token.color || "",
      content: token.content,
      fontStyle: Number(token.fontStyle || 0),
    }))),
  };
}

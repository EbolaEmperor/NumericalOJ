import { createHighlighterCore } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import bash from "@shikijs/langs/bash";
import darkPlus from "@shikijs/themes/dark-plus";

let highlighterPromise;

function getHighlighter() {
  if (!highlighterPromise) {
    highlighterPromise = createHighlighterCore({
      langs: [bash],
      themes: [darkPlus],
      engine: createJavaScriptRegexEngine(),
    }).catch((error) => {
      highlighterPromise = null;
      throw error;
    });
  }
  return highlighterPromise;
}

/**
 * 使用 Bash TextMate grammar 返回最小化 token 数据。
 *
 * DOM 由共享 Markdown 渲染器通过 createTextNode 构造，避免把用户源码重新
 * 作为 HTML 注入；这里只返回颜色、字体样式和原始文本。
 */
export async function tokenize(source) {
  const highlighter = await getHighlighter();
  const result = highlighter.codeToTokens(String(source ?? ""), {
    lang: "bash",
    theme: "dark-plus",
  });
  return {
    tokens: result.tokens.map((line) => line.map((token) => ({
      color: token.color || "",
      content: token.content,
      fontStyle: Number(token.fontStyle || 0),
    }))),
  };
}

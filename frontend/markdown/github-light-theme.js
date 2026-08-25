import githubLightDefault from "@shikijs/themes/github-light-default";

/*
 * GitHub Light Default 对通用 TextMate scope 的覆盖已经足够完整；这里只
 * 补上 Lean grammar 的结构化 scope。颜色限定在 GitHub 当前默认浅色调色板
 * 中，确保词法层和后端 semantic token 层使用同一组静态 CSP class。
 */
const markdownGithubLight = Object.freeze({
  ...githubLightDefault,
  tokenColors: [
    ...githubLightDefault.tokenColors,
    {
      scope: [
        "entity.name.type.lean4",
        "entity.name.namespace.lean4",
        "support.type.lean4",
        "support.type.namespace.lean4",
      ],
      settings: { foreground: "#0550AE" },
    },
    {
      scope: [
        "entity.name.function.lean4",
        "support.function.lean4",
      ],
      settings: { foreground: "#8250DF" },
    },
    {
      scope: "meta.definitioncommand.lean4 entity.name.function.lean4",
      settings: { foreground: "#8250DF", fontStyle: "bold" },
    },
    {
      scope: ["entity.name.type.lean4", "entity.name.namespace.lean4"],
      settings: { foreground: "#0550AE", fontStyle: "bold" },
    },
    {
      scope: "variable.parameter.lean4",
      settings: { foreground: "#953800" },
    },
    {
      scope: [
        "keyword.control.tactic.lean4",
        "keyword.other.definitioncommand.lean4",
        "keyword.other.lean4",
        "storage.modifier.lean4",
      ],
      settings: { foreground: "#CF222E" },
    },
    {
      scope: "keyword.operator.lean4",
      settings: { foreground: "#0550AE" },
    },
    {
      scope: "comment.block.documentation.lean4",
      settings: { foreground: "#6E7781", fontStyle: "italic" },
    },
    {
      scope: "invalid.illegal.lean4",
      settings: { foreground: "#82071E", fontStyle: "underline" },
    },
  ],
});

export default markdownGithubLight;

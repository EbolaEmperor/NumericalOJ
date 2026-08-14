import darkPlus from "@shikijs/themes/dark-plus";

// 在 Dark+ 的稳定色板上补充 Lean 专用 scope。主题名保持 dark-plus，
// 让 Monaco 与 Markdown 共用同一份 TextMate 结果。
const lean4DarkPlus = Object.freeze({
  ...darkPlus,
  tokenColors: [
    ...darkPlus.tokenColors,
    {
      scope: [
        "entity.name.type.lean4",
        "entity.name.namespace.lean4",
        "support.type.lean4",
        "support.type.namespace.lean4",
      ],
      settings: { foreground: "#4EC9B0" },
    },
    {
      scope: [
        "entity.name.function.lean4",
        "support.function.lean4",
      ],
      settings: { foreground: "#DCDCAA" },
    },
    {
      scope: "meta.definitioncommand.lean4 entity.name.function.lean4",
      settings: { foreground: "#DCDCAA", fontStyle: "bold" },
    },
    {
      scope: ["entity.name.type.lean4", "entity.name.namespace.lean4"],
      settings: { foreground: "#4EC9B0", fontStyle: "bold" },
    },
    {
      scope: "variable.parameter.lean4",
      settings: { foreground: "#9CDCFE" },
    },
    {
      scope: [
        "keyword.control.tactic.lean4",
        "keyword.other.definitioncommand.lean4",
      ],
      settings: { foreground: "#C586C0" },
    },
    {
      scope: "keyword.operator.lean4",
      settings: { foreground: "#D7BA7D" },
    },
    {
      scope: "comment.block.documentation.lean4",
      settings: { foreground: "#6A9955", fontStyle: "italic" },
    },
    {
      scope: "invalid.illegal.lean4",
      settings: { foreground: "#F44747", fontStyle: "underline" },
    },
  ],
});

export default lean4DarkPlus;

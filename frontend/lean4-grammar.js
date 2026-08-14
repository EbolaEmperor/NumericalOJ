import lean from "@shikijs/langs/lean";

const tacticKeywords = [
  "aesop",
  "all_goals",
  "apply",
  "apply_assumption",
  "assumption",
  "by_cases",
  "by_contra",
  "case",
  "cases",
  "change",
  "constructor",
  "contradiction",
  "decide",
  "exact",
  "exact_mod_cast",
  "exfalso",
  "first",
  "fun_prop",
  "generalize",
  "induction",
  "infer_instance",
  "intro",
  "intros",
  "left",
  "linarith",
  "next",
  "norm_num",
  "obtain",
  "omega",
  "rcases",
  "refine",
  "repeat",
  "rfl",
  "right",
  "ring",
  "ring_nf",
  "rintro",
  "rw",
  "simp",
  "simp_all",
  "simpa",
  "specialize",
  "subst",
  "tauto",
  "trivial",
  "use",
];

const base = lean[0];

// Lean 的语法可扩展，官方 TextMate grammar 不会把第三方 tactic 当成关键字；
// 这里补齐课程中最常见的一组，并修复上游 grammar 未着色的行注释。
const lean4Grammar = [{
  ...base,
  patterns: [
    {
      match: "--.*$",
      name: "comment.line.double-dash.lean4",
    },
    {
      match: `\\b(?:${tacticKeywords.join("|")})\\b`,
      name: "keyword.control.tactic.lean4",
    },
    ...base.patterns,
  ],
}];

export default lean4Grammar;

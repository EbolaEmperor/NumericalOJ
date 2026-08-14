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
const identifierStart = "[\\p{L}\\p{Nl}_]";
const identifierRest =
  "[\\p{L}\\p{Nl}\\p{Nd}_'\\u2080-\\u209f\\u2070-\\u207f]*";
const identifier = `${identifierStart}${identifierRest}`;
const upperIdentifier = `[\\p{Lu}\\p{Lt}]${identifierRest}`;
const lowerIdentifier = `[\\p{Ll}_]${identifierRest}`;
const identifierCharacter =
  "[\\p{L}\\p{Nl}\\p{Nd}_'\\u2080-\\u209f\\u2070-\\u207f]";
const identifierBoundaryStart = `(?<!${identifierCharacter})`;
const identifierBoundaryEnd = `(?!${identifierCharacter})`;

// Lean 的语法可扩展，官方 TextMate grammar 不会把第三方 tactic 与普通
// 标识符完整分类；这里补齐课程常用 tactic 和稳定的结构形态。
const lean4Grammar = [{
  ...base,
  patterns: [
    {
      match: "--.*$",
      name: "comment.line.double-dash.lean4",
    },
    {
      captures: {
        1: { name: "keyword.other.definitioncommand.lean4" },
        3: { name: "entity.name.type.lean4" },
      },
      match: `\\b(structure|class|inductive|coinductive)(\\s+)(?:\\{[^}]*\\}\\s*)?(${identifier})`,
    },
    {
      captures: {
        1: { name: "keyword.other.lean4" },
        3: { name: "entity.name.namespace.lean4" },
      },
      match: `\\b(namespace|section)(\\s+)(${identifier}(?:\\.${identifier})*)`,
    },
    {
      match: "\\bby\\b",
      name: "keyword.control.tactic.lean4",
    },
    {
      match: `\\b(?:${tacticKeywords.join("|")})\\b`,
      name: "keyword.control.tactic.lean4",
    },
    ...base.patterns,
    {
      captures: {
        1: { name: "support.type.namespace.lean4" },
        2: { name: "support.function.lean4" },
      },
      match: `${identifierBoundaryStart}((?:${upperIdentifier}\\.)+)(${lowerIdentifier})${identifierBoundaryEnd}`,
    },
    {
      match: `${identifierBoundaryStart}(?:${upperIdentifier}\\.)+${upperIdentifier}${identifierBoundaryEnd}`,
      name: "support.type.lean4",
    },
    {
      match: `${identifierBoundaryStart}${upperIdentifier}${identifierBoundaryEnd}`,
      name: "support.type.lean4",
    },
    {
      match: `${identifierBoundaryStart}${identifier}(?=\\s*:(?!=))`,
      name: "variable.parameter.lean4",
    },
    {
      match: "[!#$%&*+\\-./:;<=>?@\\\\^|~·×\\u2190-\\u22ff]+",
      name: "keyword.operator.lean4",
    },
  ],
}];

export default lean4Grammar;

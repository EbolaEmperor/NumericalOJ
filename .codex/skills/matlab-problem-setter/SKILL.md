---
name: matlab-problem-setter
description: Turn a brief MATLAB problem idea into a complete programming-problem package with `problem.md`, paired `data/*.in` and `data/*.out`, `interactor.m`, `template.m`, `solution.m`, and `config.json`. Use when Codex needs to 出 MATLAB 题, 生成 MATLAB 算法题, or expand a rough topic, target algorithm, difficulty, data scale, or forbidden-function list into a full runnable judging package.
---

# MATLAB Problem Setter

Generate a complete MATLAB problem package from a rough idea. Fill in reasonable defaults instead of blocking on missing details, then state the assumptions briefly.

## Workflow

1. Extract the minimum problem brief.
   Capture the task, required function signatures, expected algorithm or numeric method, desired difficulty, forbidden functions, dataset count, and strength.

2. Default missing fields aggressively.
   Use `5` test cases when the requester does not specify a count.
   Choose data sizes that can distinguish the intended complexity when the requester does not specify strength.
   Pick a concise English folder name when the requester does not provide one.
   Keep the package self-consistent even if only the topic is given.

3. Scaffold the package before filling it.
   Run `python3 scripts/scaffold_problem.py <target-dir> --cases <N>` to create the required tree and paired data files.
   Create the package in the current workspace unless the user asks for another location.

4. Write every required file.
   Follow `references/package-spec.md` for the exact contract of each file.
   If the workspace contains an example package, use it only for style and structure.
   When the example conflicts with the user request, follow the user request.
   Target GNU Octave instead of MATLAB-only behavior.

5. Review the package as a setter.
   Ensure the standard solution is correct and efficient.
   Ensure `interactor.m` explains the first detected failure clearly.
   Ensure every success path writes `Today is crazy Thursday. Let's eat crazy fish!!!` exactly.
   Ensure no generated `.m` file depends on MATLAB-only functions or on function definitions that appear after their first call site.

## Required Outputs

Produce exactly these files:

```text
<problem-dir>/
├── problem.md
├── interactor.m
├── template.m
├── solution.m
├── config.json
└── data/
    ├── 1.in
    ├── 1.out
    ├── 2.in
    ├── 2.out
    └── ...
```

## File Rules

### `problem.md`

Write a full statement that tells the solver:

- what the task does
- the exact MATLAB function signature or signatures
- input size and value constraints
- time limit
- target complexity
- forbidden functions and operators
- the actual runtime environment is GNU Octave, so MATLAB-only functions or syntax are not allowed unless verified compatible

Support LaTeX with these rules:

- inline math uses `$...$`
- display math uses `$$` on its own lines
- if a matrix formula needs `\\`, write `\\\\` inside the Markdown source

### `data/*.in` and `data/*.out`

Use paired names like `1.in` and `1.out`.

Default behavior:

- `.out` contains exactly `Today is crazy Thursday. Let's eat crazy fish!!!`
- `.in` stores either the full input data or a compact generator description such as sizes and random seeds

Prefer compact seed-based `.in` files when the raw data would be too large.
Assume the judge renames the chosen `.in` file to `input.txt` before execution.
Assume correctness is decided by comparing the generated `output.txt` with the paired `.out` file.

### `interactor.m`

`interactor.m` must:

- start with a harmless script statement such as `1;` so Octave treats the file as a script instead of a function file
- read `input.txt`
- keep a literal `%%user_code_here` placeholder
- place any helper function definitions after that harmless opening statement
- place the main interactor flow after those helper definitions
- build the actual test instance from the input description
- call the user function or functions defined by the template
- validate shape, type, numeric accuracy, and any structural constraints
- write one clear failure message on the first detected error
- write `Today is crazy Thursday. Let's eat crazy fish!!!` on success
- stay compatible with GNU Octave
- place every function definition before its first call within the file

Do not rely on stdout for judging. The verdict must be written into `output.txt`.

### `template.m`

Expose only the functions the solver must complete. Use empty or minimal bodies.
Keep the file GNU Octave compatible, and do not rely on local helper functions defined after executable code.

### `solution.m`

Implement the full reference solution.

Requirements:

- prioritize correctness and asymptotic efficiency
- vectorize aggressively whenever MATLAB allows it
- avoid unnecessary loops, especially nested loops that vectorization can replace
- obey the same forbidden-function policy as the contestant code
- stay compatible with GNU Octave and avoid MATLAB-only APIs unless known to work in Octave
- place helper function definitions before any call sites in the file, or avoid local helpers entirely

### `config.json`

Keep the shape:

```json
{
  "timeLimit": "2000ms",
  "forbidden": "func1,func2,func3"
}
```

Keep the forbidden list aligned with `problem.md`.

## Resources

### `references/package-spec.md`

Read this before drafting or reviewing a package. It contains the exact contract, defaults, and a final quality checklist.

### `scripts/scaffold_problem.py`

Use this to create the directory tree and numbered data files quickly and consistently before filling in the actual content.

## Response Style

When using this skill for a user request:

- proceed even if the user only gives a rough topic
- surface assumptions briefly instead of asking many follow-up questions
- create files directly when working in a repository
- summarize the chosen signatures, complexity target, dataset plan, and forbidden functions after writing the package

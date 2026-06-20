# MATLAB Problem Package Spec

Read this file before generating or reviewing a package.

## Required Tree

```text
problem-dir/
├── problem.md
├── interactor.m
├── template.m
├── solution.m
├── config.json
└── data/
    ├── 1.in
    ├── 1.out
    ├── ...
```

Use paired names only. Do not invent alternative filenames.

## Defaults

- Default number of test cases: `5`
- Default success output: `Today is crazy Thursday. Let's eat crazy fish!!!`
- Default behavior for unspecified data strength: choose scales that can distinguish the intended complexity
- Default output location: current workspace
- Default execution environment: GNU Octave

If the user only provides a broad idea, infer:

- function names and signatures
- input bounds
- time limit
- target complexity
- forbidden functions
- dataset scaling strategy

State the assumptions briefly, then continue.

## Octave Compatibility

Assume the online judge runs GNU Octave, not desktop MATLAB.

Rules:

- avoid MATLAB-only functions, toolboxes, classes, or syntax
- prefer core matrix and numeric operations known to exist in Octave
- if a function is questionable, replace it with a simpler portable formulation
- mention the Octave environment in `problem.md` when it affects solver choices

Function-order rule:

- in every generated `.m` file, place function definitions before their first call site
- do not rely on newer MATLAB/Octave behavior that permits calling local functions before their textual definition
- if that ordering would be awkward, inline the logic instead of adding a trailing helper

## `problem.md`

Include:

1. Problem goal
2. Function signature or signatures
3. Input constraints and data ranges
4. Time limit
5. Complexity target
6. Forbidden functions and operators
7. Any special numeric tolerance or output format rules

LaTeX rules:

- inline math uses `$...$`
- display math uses:

```text
$$
...
$$
```

- if the formula contains matrix line breaks, write `\\\\` in the source

Also state that the judge environment is GNU Octave when compatibility constraints matter.

## `data/*.in`

Choose one of these patterns:

1. Store the full input directly.
2. Store a compact recipe such as matrix size, sparsity, condition-control parameters, and random seed.

Use recipe-style inputs when the actual data would be too large or expensive to store repeatedly.
The judge will rename the selected `.in` file to `input.txt` before running `interactor.m`.

## `data/*.out`

Unless the user explicitly asks for a different judging protocol, every `.out` file should contain exactly:

```text
Today is crazy Thursday. Let's eat crazy fish!!!
```

The interactor should emit the same string on success.
The judge decides pass or fail by comparing `output.txt` with the paired `.out` file as plain text.

## `interactor.m`

Hard requirements:

- begin with a harmless script statement such as `1;` so Octave does not parse the file as a function file
- read from `input.txt`
- keep a literal `%%user_code_here`
- place helper function definitions immediately after that opening script statement when helpers are needed
- place the main interactor flow after those helper definitions
- reconstruct or load the real test instance
- call the solver-facing functions from `template.m`
- validate the answer and stop at the first clear failure
- write to `output.txt`
- treat `output.txt` as the only judged output channel
- use only GNU Octave compatible syntax and functions
- place every local function definition before any call site in the file

Interactor failure messages should be specific, for example:

- wrong output shape
- returned matrix is not lower triangular
- residual is too large
- algorithm violates a stated structural constraint

Success must write the exact success string.
Do not make `interactor.m` start with `function`.

If the problem uses randomized generation:

- make generation deterministic from the seed in `.in`
- use the same generation logic in `solution.m` reasoning and `interactor.m`
- avoid hidden nondeterminism

## `template.m`

Define only the public solver API. Keep bodies empty or minimal.

Good pattern:

```matlab
function x = solveSomething(A, b)
    % Your code here
end
```

If multiple functions are required, define all of them in the template.
Keep the template valid in GNU Octave.

## `solution.m`

The reference solution must:

- pass all generated data
- respect the advertised complexity target
- use vectorized operations wherever they replace inner loops cleanly
- avoid banned functions and operators
- stay readable enough for later maintenance
- stay compatible with GNU Octave
- keep function definitions before any call sites in the file

Prefer:

- matrix-vector or block updates over elementwise inner loops
- preallocation over dynamic growth
- numerically stable formulations where relevant

## `config.json`

Use this shape:

```json
{
  "timeLimit": "2000ms",
  "forbidden": "func1,func2,func3"
}
```

Rules:

- keep `timeLimit` as a string with `ms`
- keep `forbidden` as a comma-separated string
- match the forbidden list in `problem.md`

## Example Conflicts

If a repository example disagrees with the current request, prefer the current request.

Important known conflict:

- some existing examples may use a different success phrase in `interactor.m`
- for this skill, the correct success phrase is `Today is crazy Thursday. Let's eat crazy fish!!!`

## Final Checklist

Before finishing, verify:

1. All required files exist.
2. Data filenames are paired correctly.
3. `problem.md` includes signatures, limits, complexity, and forbidden functions.
4. `interactor.m` contains `%%user_code_here`.
5. `template.m` matches the signatures promised in `problem.md`.
6. `solution.m` matches the same API and is meaningfully optimized.
7. `config.json` matches the statement.
8. Every success path writes the exact success string.
9. All generated `.m` files are GNU Octave compatible.
10. No generated `.m` file calls a function before that function is defined textually.
11. `interactor.m` starts with a harmless script statement rather than `function`.

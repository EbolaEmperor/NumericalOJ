---
name: numoj-user
description: A skill to use NumericalOJ/NumOJ. Use when the user asks you to do something on NumOJ as a student. For example, submit a problem in NumOJ, view submission status, etc.
---

# NumOJ User

Use the bundled script `scripts/numoj_user.py` for NumOJ user workflows. Resolve
it relative to this `SKILL.md`, save that resolved absolute path as
`NUMOJ_USER_CLI`, and invoke it without changing the current working directory:
Never `cd` into the skill directory; keep the task workspace as the current
working directory and call the CLI by its resolved absolute path.

```bash
NUMOJ_USER_CLI=/absolute/path/to/numoj-user/scripts/numoj_user.py
python3 "$NUMOJ_USER_CLI" auth status
```

## First-Time Setup

If the auth status is not authenticated, require the user to run initialization before any
operation:

```bash
python3 /path/to/numoj-user/scripts/numoj_user.py init
```

The command prompts for:

- NumOJ URL, such as `https://oj.example.com` or `127.0.0.1:2025`
- username
- password

It logs in through NumOJ's existing `/login` route and writes a local JSON config to `~/.numoj-user/config.json` by default. Treat that JSON as a secret because it contains the Flask session cookie. Use `--config <path>` or `NUMOJ_USER_CONFIG=<path>` only when the user wants a different config file.

Verify access:

```bash
python3 /path/to/numoj-user/scripts/numoj_user.py auth status
```

Proceed only if the result reports `authenticated: true`.

## Agent Workflow

1. Resolve the absolute CLI path relative to this `SKILL.md`: `scripts/numoj_user.py`.
2. If config is missing or `auth status` fails, stop and tell the user to run `init`; do not ask them to reveal the password in chat.
3. Before using a command area for the first time in the current task, run `python3 "$NUMOJ_USER_CLI" <command_area> --help` to fetch the real subcommand list and descriptions. Do not guess subcommands from memory or from the high-level Command Areas summary.
4. Run `python3 "$NUMOJ_USER_CLI" <command_area> <subcommand> --help` before using unfamiliar subcommands. Every command supports `--help`.
5. Execute the narrowest command matching the user's request.
6. Summarize submitted IDs, current statuses, exported files, or visible scores.

For a different NumOJ instance, set the address through `init --base-url <url>` or pass the CLI-level `--base-url <url>` option.

JSON inspection commands print JSON to stdout. To save them, use shell redirection. The `-o/--output` option is reserved for commands that download or export real files, such as output images, ranking submission archives, or repository file contents.

## Command Areas

- `auth`: login status, local token cleanup, registration/password-reset pages, verification-code requests, registration, and password change.
- `me`: view own classes, join or leave classes, view own submissions, and summarize visible grades from submission history.
- `problem`: list homework/problem rows, view details, download user-visible problem resources, fetch submit contexts, and submit programming code, Lean workspaces, Promptly prompts, or written-homework PDF/ZIP files.
- `submission`: list personal submissions, list submissions for one problem, inspect details/status/stream, fetch last submitted code, and download output images.
- `forum`: list forum threads, view threads and replies, fetch new-thread field metadata, create threads, and reply.
- `repository`: use the personal code repository: list/get/save/delete/upload files, inspect repository context, build/rebuild index jobs, check job status, search indexed code, and list indexed classes.
- `ai`: call existing AI tutor routes for code marks, ordinary tutor feedback, and AC-oriented feedback. These may call configured model services.
- `ranking`: list/view ranking competitions, submit by upload or Git, view personal ranking submissions, view leaderboards, inspect matches/match details/judge streams (including reverse-judge four-step progress), submit/check appeals, and download own visible ranking submission files.
- `vibehub`: fetch the current developer guide, list public works, inspect owned versions, create or update complete container packages with automatic review submission, edit versioned metadata, and permanently delete owned works. Featured status is assigned only by administrators and cannot be requested by users.

This skill deliberately excludes administrator actions such as creating/editing problems, assigning homework, exporting class scores, managing users/classes, rejudging, AIGC detection administration, Agent-as-Judge configuration, batch evaluation, and deleting submissions.

For Lean 4 proof-problem resource, verification, and submission workflows, read [references/lean4-problems.md](references/lean4-problems.md) before acting.

## Examples

List all the problems:

```bash
python3 "$NUMOJ_USER_CLI" problem list
```

Read problem details:

```bash
python3 "$NUMOJ_USER_CLI" problem detail <problem_id>
python3 "$NUMOJ_USER_CLI" problem download <problem_id> -o /workspace
```

Search your existing submissions for some problem:

```bash
python3 "$NUMOJ_USER_CLI" submission problem <problem_id>
```

Submit a programming problem and wait for the result:

```bash
python3 "$NUMOJ_USER_CLI" problem submit <problem_id> --code-file solution.m
python3 "$NUMOJ_USER_CLI" submission status <submission_id>
python3 "$NUMOJ_USER_CLI" submission stream <submission_id> --max-lines 10
```

Export the latest submitted code for a problem:

```bash
python3 "$NUMOJ_USER_CLI" submission last-code <problem_id> -o solution.m
```

Submit a Promptly problem:

```bash
python3 "$NUMOJ_USER_CLI" problem submit <problem_id> --prompt-file prompt.txt
```

Submit a written problem:

```bash
python3 "$NUMOJ_USER_CLI" problem submit <problem_id> --file homework.pdf
```

Inspect personal history and visible grades:

```bash
python3 "$NUMOJ_USER_CLI" me submissions --limit 10
python3 "$NUMOJ_USER_CLI" me grades --pages 5
```

Submit and inspect a ranking competition:

```bash
python3 "$NUMOJ_USER_CLI" ranking submit <competition_id> --base-model "qwen3" --answer-file answer.json --code-zip code.zip
python3 "$NUMOJ_USER_CLI" ranking detail <reverse_competition_id> --tab submit
python3 "$NUMOJ_USER_CLI" ranking submit <reverse_competition_id> --code-zip reverse_problem.zip --agent-endpoint-id <answer_endpoint_id>
python3 "$NUMOJ_USER_CLI" ranking reverse-stream <reverse_competition_id> <submission_id> --max-lines 20
python3 "$NUMOJ_USER_CLI" ranking download-submission <submission_id> ai-answer -o ./ai-answer.zip
python3 "$NUMOJ_USER_CLI" ranking my-submissions <competition_id> --limit 5
python3 "$NUMOJ_USER_CLI" ranking leaderboard <competition_id> --limit 10
python3 "$NUMOJ_USER_CLI" ranking appeal-status <competition_id> <submission_id>
```

For a reverse-judge submission, first read `answer_endpoints` from `ranking detail` and use one of its `id` values. This list contains only enabled answer-pool endpoints; quality-gate endpoints are selected automatically by the server and are never user-selectable.

Create a VibeHub work. Saving automatically submits it for review. The ZIP root
must contain `Dockerfile` and `vibehub.json`:

```bash
python3 "$NUMOJ_USER_CLI" vibehub guide -o ./vibehub-developer-guide.md
python3 "$NUMOJ_USER_CLI" vibehub create ./my-vibe.zip --title "My Vibe"
python3 "$NUMOJ_USER_CLI" vibehub mine
python3 "$NUMOJ_USER_CLI" vibehub delete <slug> --yes
```

Use Git submission when the competition enables it. The user does not provide a Git URL; NumOJ derives the URL from the competition's Git rule and the logged-in username. Always check first, then submit:

```bash
python3 "$NUMOJ_USER_CLI" ranking git <competition_id> check
python3 "$NUMOJ_USER_CLI" ranking git <competition_id> submit
```

Use the code repository:

```bash
python3 "$NUMOJ_USER_CLI" repository files
python3 "$NUMOJ_USER_CLI" repository save --filename helper.hpp --content-file helper.hpp
```

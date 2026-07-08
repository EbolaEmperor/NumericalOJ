---
name: numoj-admin
description: A skill to administer NumericalOJ/NumOJ. Use when the user asks you to do something on NumOJ as an administrator. For example, create a problem in NumOJ, assign homework, export student scores, manage users/classes, rejudge submissions, or configure ranking competitions.
---

# NumOJ Admin

Use the bundled script `scripts/numoj_admin.py` for NumOJ administrator workflows.

## First-Time Setup

Require the administrator to run initialization before any operation:

```bash
python3 /path/to/numoj-admin/scripts/numoj_admin.py init
```

The command prompts for:

- NumOJ URL, such as `https://oj.example.com` or `127.0.0.1:2025`
- administrator username
- administrator password

It logs in through NumOJ's existing `/login` route and writes a local JSON config to `~/.numoj-cli/config.json` by default. Treat that JSON as a secret because it contains the Flask session cookie. Use `--config <path>` or `NUMOJ_CLI_CONFIG=<path>` only when the administrator wants a different config file.

Verify access:

```bash
python3 /path/to/numoj-admin/scripts/numoj_admin.py auth status
```

Proceed only if the result reports `authenticated: true` and `admin: true`.

## Agent Workflow

1. Resolve the CLI path relative to this `SKILL.md`: `scripts/numoj_admin.py`.
2. If config is missing, `auth status` fails, or the account is not an administrator, stop and tell the user to run `init` with an administrator account; do not ask them to reveal the password in chat.
3. Before using a command area for the first time in the current task, run `python3 scripts/numoj_admin.py <command_area> --help` to fetch the real subcommand list and descriptions. Do not guess subcommands from memory or from the high-level Command Areas summary.
4. Run `python3 scripts/numoj_admin.py <command_area> <subcommand> --help` before using unfamiliar subcommands. Every command supports `--help`.
5. Execute the narrowest administrator command matching the user's request.
6. Summarize created IDs, changed settings, current statuses, exported files, or visible scores.

For a different NumOJ instance, set the address through `init --base-url <url>` or pass the CLI-level `--base-url <url>` option.

JSON inspection commands print JSON to stdout. To save them, use shell redirection. The `-o/--output` option is reserved for commands that download or export real files, such as score CSVs, code ZIPs, output images, ranking attachments, written-submission files, or repository file contents.

Do not use commands that launch external model/API work, large judging workloads, destructive data changes, or mass notifications unless the administrator explicitly asks for that action. This includes Promptly prompt submissions, AI tutor calls, agent solve/data-generation tasks, AIGC detection runs, Agent-as-Judge evaluation, bulk rejudging, batch ranking probes/evaluation, deleting problems, deleting submissions, and deleting competitions.

## Command Areas

- `auth`: login status, local token cleanup, registration/password-reset pages, verification-code requests, registration, and password change.
- `site`: inspect public site routes and login/problem-list redirects.
- `me`: view current account classes, join/leave/set primary class, view current account submissions, and summarize visible grades.
- `submission`: list visible submissions, list submissions for one problem, inspect details/status/streams, fetch last submitted code, download output images, and download written-submission files.
- `problem`: list/view/create/edit/delete problems, fetch create/edit/submit contexts, submit programming/Promptly/written homework as the administrator, upload test data, inspect scores, rejudge submissions, check rejudge status, and manage problem-solving or test-data-generation agent tasks.
- `homework`: list class homework, assign/update/delete homework, export scores/codes/progress, download export artifacts, upload exam scores, inspect plagiarism records, and toggle class-adjustment settings.
- `user`: list users, create class types, rename users, add/remove class memberships, set primary classes, list grades, and update or clear manual grade overrides.
- `grading`: inspect pending written-homework grading items and submit manual grading decisions.
- `forum`: list forum threads, view threads and replies, fetch new-thread field metadata, create threads, and reply.
- `repository`: inspect and manage the per-user code repository: list/get/save/delete/upload files, inspect repository context, build/rebuild index jobs, check job status, search indexed code, and list indexed classes.
- `ai`: call existing AI tutor routes for code marks, ordinary tutor feedback, and AC-oriented feedback. These may call configured model services.
- `ai-detection`: inspect dashboard/problem/student pages, query task/model APIs, and launch/stop/delete AIGC detection tasks.
- `ranking`: list/view/create/edit/delete ranking competitions, submit by upload or Git, inspect personal/all submissions, view leaderboards, inspect matches/match details/judge streams, upload/download attachments/reference answers/scoring scripts, manage Agent-as-Judge rules/config/endpoints, reset limits, submit/check/review/handle appeals, and run batch/admin actions.

For ordinary student-only workflows, prefer `numoj-user` with a student account unless the user explicitly wants to operate as an administrator.

## Examples

Check administrator login:

```bash
python3 scripts/numoj_admin.py auth status
```

List users and inspect the current administrator account:

```bash
python3 scripts/numoj_admin.py user list --username admin
python3 scripts/numoj_admin.py me classes
```

Create a programming problem:

```bash
python3 scripts/numoj_admin.py problem create \
  --title "矩阵范数计算" \
  --content @problem.md \
  --type 1 \
  --lang matlab \
  --time-limit-ms 2000 \
  --submission-limit 5
```

Edit a problem without clearing omitted fields:

```bash
python3 scripts/numoj_admin.py problem edit <problem_id> \
  --title "矩阵范数计算（修订）" \
  --time-limit-ms 3000
```

Read problem details and inspect recent submissions:

```bash
python3 scripts/numoj_admin.py problem detail <problem_id>
python3 scripts/numoj_admin.py submission problem <problem_id> --limit 5
```

Submit code and inspect submission results:

```bash
python3 scripts/numoj_admin.py problem submit <problem_id> --code-file solution.m
python3 scripts/numoj_admin.py submission list --limit 10
python3 scripts/numoj_admin.py submission problem <problem_id> --limit 10
python3 scripts/numoj_admin.py submission detail <submission_id>
python3 scripts/numoj_admin.py submission status <submission_id>
python3 scripts/numoj_admin.py submission stream <submission_id> --max-lines 10
```

Fetch your last submission for some problem and save the code to some file:

```bash
python3 scripts/numoj_admin.py submission last-code <problem_id>
python3 scripts/numoj_admin.py submission last-code <problem_id> --output <filename>
```

Upload test data and rejudge a problem:

```bash
python3 scripts/numoj_admin.py problem upload-testdata <problem_id> testdata.zip
python3 scripts/numoj_admin.py problem rejudge <problem_id>
python3 scripts/numoj_admin.py problem rejudge-status <problem_id>
```

Assign homework and export scores:

```bash
python3 scripts/numoj_admin.py homework add --class-en C2026A --problem-id <problem_id> --ddl 2026-12-31T23:59
python3 scripts/numoj_admin.py homework export-scores --class-en C2026A -o scores.csv
```

Manage a user's class and grades:

```bash
python3 scripts/numoj_admin.py user add-to-class <user_id> C2026A
python3 scripts/numoj_admin.py user set-primary-class <user_id> C2026A
python3 scripts/numoj_admin.py user grades <user_id>
```

Create and configure a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking create --title "第 1 周打榜赛" --max-score 100
python3 scripts/numoj_admin.py ranking save-rules <competition_id> @rules.json
python3 scripts/numoj_admin.py ranking save-config <competition_id> --agent-base-url https://api.example.com --model qwen3
```

Submit and inspect a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking submit <competition_id> --base-model qwen3 --answer-file answer.json --code-zip code.zip
python3 scripts/numoj_admin.py ranking my-submissions <competition_id> --limit 5
python3 scripts/numoj_admin.py ranking leaderboard <competition_id> --limit 10
python3 scripts/numoj_admin.py ranking appeals <competition_id> --status open
```

Use Git submission when the competition enables it. The user does not provide a Git URL; NumOJ derives the URL from the competition's Git rule and the logged-in username. Always check first, then submit:

```bash
python3 scripts/numoj_admin.py ranking git <competition_id> check
python3 scripts/numoj_admin.py ranking git <competition_id> submit
```

Use the code repository:

```bash
python3 scripts/numoj_admin.py repository files
python3 scripts/numoj_admin.py repository save --filename helper.hpp --content-file helper.hpp
```

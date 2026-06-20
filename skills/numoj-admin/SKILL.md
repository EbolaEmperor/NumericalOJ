---
name: numoj-admin
description: A skill to administer NumericalOJ/NumOJ. Use when the user asks you to do something on NumOJ as an administrator. For example, create a problem in NumOJ, export student scores from NumOJ, etc.
---

# NumOJ Admin

Use the bundled script `scripts/numoj_admin.py` for administrator operations against a running NumOJ instance. Treat this as an administrator skill, not a developer tool: operate through the existing HTTP routes only, never import a NumOJ source checkout, never edit server files, never add POST endpoints, and never touch MySQL/Redis directly.

## First-Time Setup

Require the administrator to run initialization before any operation:

```bash
python3 /path/to/numoj-admin/scripts/numoj_admin.py init
```

The command prompts for:

- NumOJ URL, such as `https://oj.example.com` or `127.0.0.1:2025`
- administrator username
- administrator password

It logs in through NumOJ's existing `/login` route and writes a local JSON config to `~/.numoj-cli/config.json` by default. The JSON contains the base URL, username, and Flask session cookie. Treat it as a secret. Do not print, paste, commit, or transmit the cookie. Use `--config <path>` or `NUMOJ_CLI_CONFIG=<path>` only when the admin wants a different config file.

After initialization, verify access:

```bash
python3 /path/to/numoj-admin/scripts/numoj_admin.py auth status
```

Proceed only if the result reports `authenticated: true` and `admin: true`.

## Agent Workflow

When this skill is invoked:

1. Resolve the CLI path relative to this `SKILL.md`: `scripts/numoj_admin.py`.
2. If config is missing or `auth status` fails, stop and tell the administrator to run `init`; do not ask them to reveal the password in chat.
3. Run `python3 scripts/numoj_admin.py <group> <command> --help` before using unfamiliar commands. Every command supports `--help`.
4. Execute the narrowest administrator command that matches the request.
5. Summarize the result in administrator terms: what changed, what exported file was written, or what failed.

For a different NumOJ instance, set the address through `init --base-url <url>` or pass the CLI-level `--base-url <url>` option.

## Command Areas

- `auth`: initialize/login status, local token cleanup, registration/password-reset pages, verification-code requests, and password change.
- `site`: inspect the home route and its login/problem-list redirect.
- `me`: current-account classes, class join/leave/set-primary, current admin grades, and current-account submission history.
- `submission`: list all visible submissions, list submissions for one problem, inspect status/detail/stream, fetch last submitted code, download output images, and download written-submission files.
- `problem`: list/view problems, open submit pages, submit ordinary programming/written problems, create/edit/delete problems, open create/edit forms, upload test data, rejudge, check rejudge status, inspect Agent task pages/streams, start agent solve/data-generation tasks, and view scores.
- `homework`: list assigned homework for a class, assign/update/delete homework, export scores/codes/progress, download export artifacts, upload exam scores, and toggle class adjustment.
- `user`: list users, create/rename class types, set primary class, add/remove users from classes, list grades, and update or clear grades.
- `grading`: submit written-homework grading decisions and inspect pending grading items.
- `forum`: list forum threads, view threads, open the new-thread page, create threads, and reply.
- `repository`: use the per-user code repository: list/get/save/delete/upload files, inspect repository page, build/rebuild index jobs, check job status, search indexed code, and list indexed classes.
- `ai`: call existing AI tutor routes for code marks, ordinary tutor feedback, and AC-oriented feedback. These may call configured model services.
- `ranking`: list/view ranking competitions, submit by upload or Git, inspect personal/all submissions, leaderboard, matches, match details, judge streams, create/edit/delete ranking competitions, upload/download attachments/reference answers/scoring scripts, manage Agent-as-Judge rules/config/endpoints, reset limits, submit/check/review/handle appeals, and run batch/admin actions.
- `ai-detection`: inspect dashboard/problem/student pages, query task/model APIs, or launch/stop/delete AIGC detection tasks.

Do not use commands that launch external model/API work, such as agent solving, generated test data, AIGC detection runs, or Agent-as-Judge evaluation, unless the administrator explicitly asks for that action and understands it may call configured model services.

## Examples

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
python3 scripts/numoj_admin.py problem edit 42 \
  --title "矩阵范数计算（修订）" \
  --time-limit-ms 3000
```

Submit a normal programming problem and inspect the latest submissions:

```bash
python3 scripts/numoj_admin.py problem submit 42 --code-file solution.m
python3 scripts/numoj_admin.py submission problem 42 --limit 5
python3 scripts/numoj_admin.py submission status 123
python3 scripts/numoj_admin.py submission stream 123 --max-lines 10
```

Assign homework and export scores:

```bash
python3 scripts/numoj_admin.py homework add --class-en C2026A --problem-id 42 --ddl 2026-12-31T23:59
python3 scripts/numoj_admin.py homework export-scores --class-en C2026A -o scores.csv
```

Create and configure a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking create --title "第 1 周打榜赛" --max-score 100
python3 scripts/numoj_admin.py ranking save-rules 1 '[{"rule_text":"结果格式正确","value":40},{"rule_text":"得分最优","value":60}]'
python3 scripts/numoj_admin.py ranking save-config 1 --agent-base-url https://api.example.com --model qwen3
```

Submit and inspect a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking submit 1 --base-model "qwen3" --answer-file answer.json --code-zip code.zip
python3 scripts/numoj_admin.py ranking my-submissions 1 --limit 5
python3 scripts/numoj_admin.py ranking leaderboard 1 --limit 10
python3 scripts/numoj_admin.py ranking appeals 1 --status open
```

For Git-based ranking submissions, do not provide a Git URL. NumOJ derives it from the competition's Git rule and the logged-in username. Check first, then submit:

```bash
python3 scripts/numoj_admin.py ranking git 1 check
python3 scripts/numoj_admin.py ranking git 1 submit
```

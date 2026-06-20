---
name: numoj-user
description: A skill to use NumericalOJ/NumOJ. Use when the user asks you to do something on NumOJ as a student. For example, submit a problem in NumOJ, view submission status, etc.
---

# NumOJ User

Use the bundled script `scripts/numoj_user.py` for normal NumOJ user workflows. This skill is intentionally not an administrator tool: do not use `/admin/...` routes, do not edit server code, do not add endpoints, and do not touch MySQL/Redis directly.

## First-Time Setup

Require the user to run initialization before any operation:

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

1. Resolve the CLI path relative to this `SKILL.md`: `scripts/numoj_user.py`.
2. If config is missing or `auth status` fails, stop and tell the user to run `init`; do not ask them to reveal the password in chat.
3. Run `python3 scripts/numoj_user.py <group> <command> --help` before using unfamiliar commands. Every command supports `--help`.
4. Execute the narrowest command matching the user's request.
5. Summarize submitted IDs, current statuses, exported files, or visible scores.

For a different NumOJ instance, set the address through `init --base-url <url>` or pass the CLI-level `--base-url <url>` option.

## Command Areas

- `auth`: login status and local token cleanup.
- `me`: view own classes, join/leave/set primary class, view own submissions, and summarize visible grades from submission history.
- `problem`: submit programming code or written-homework PDF/ZIP files.
- `submission`: list personal submissions, list submissions for one problem, inspect status/detail, and fetch last submitted code.
- `ranking`: submit ranking competitions by upload or Git, view personal ranking submissions, view leaderboards, and download own visible ranking submission files.

This skill deliberately excludes administrator actions such as creating/editing problems, assigning homework, exporting class scores, managing users/classes, rejudging, AIGC detection, Agent-as-Judge configuration, batch evaluation, and deleting submissions.

## Examples

Submit a programming problem:

```bash
python3 scripts/numoj_user.py problem submit 42 --code-file solution.m
python3 scripts/numoj_user.py submission problem 42 --limit 5
python3 scripts/numoj_user.py submission status 123
```

Submit a written problem:

```bash
python3 scripts/numoj_user.py problem submit 43 --file homework.pdf
```

Inspect personal history and visible grades:

```bash
python3 scripts/numoj_user.py me submissions --limit 10
python3 scripts/numoj_user.py me grades --pages 5
```

Submit and inspect a ranking competition:

```bash
python3 scripts/numoj_user.py ranking submit 1 --base-model "qwen3" --answer-file answer.json --code-zip code.zip
python3 scripts/numoj_user.py ranking my-submissions 1 --limit 5
python3 scripts/numoj_user.py ranking leaderboard 1 --limit 10
```

Use Git submission when the competition enables it:

```bash
python3 scripts/numoj_user.py ranking git 1 check
python3 scripts/numoj_user.py ranking git 1 submit
```

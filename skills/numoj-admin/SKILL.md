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
- `site-config`: inspect and manage global LLM endpoints, feature bindings,
  SMTP settings, and WebSearch MCP settings. LLM create/update commands always
  run the server's real connection test and consume its one-time test token
  before saving.
- `me`: view current account classes, join or leave classes, view current account submissions, and summarize visible grades.
- `submission`: list visible submissions, list submissions for one problem, inspect details/status/streams, fetch last submitted code, download output images, and download written-submission files.
- `problem`: list/view/create/edit/delete problems, fetch create/edit/submit contexts, submit programming/Promptly/written homework as the administrator, upload test data, inspect scores, rejudge submissions, check rejudge status, and manage problem-solving or test-data-generation agent tasks.
- `homework`: list class homework, assign/update/delete homework, export scores/codes/progress, download export artifacts, upload exam scores, inspect plagiarism records, and toggle class-adjustment settings.
- `user`: list users, create class types, rename users, add/remove class memberships, grant administrator privileges, list grades, and update or clear manual grade overrides.
- `grading`: inspect pending written-homework grading items and submit manual grading decisions.
- `forum`: list forum threads, view threads and replies, fetch new-thread field metadata, create threads, and reply.
- `repository`: inspect and manage the per-user code repository: list/get/save/delete/upload files, inspect repository context, build/rebuild index jobs, check job status, search indexed code, and list indexed classes.
- `ai`: call existing AI tutor routes for code marks, ordinary tutor feedback, and AC-oriented feedback. These may call configured model services.
- `ai-detection`: inspect dashboard/problem/student pages, query task/model APIs, and launch/stop/delete AIGC detection tasks.
- `ranking`: list/view/create/edit/delete ranking competitions, submit by upload or Git, inspect personal/all submissions, view leaderboards, inspect matches/match details/judge streams, upload/download attachments/reference answers/scoring scripts, manage Agent-as-Judge / reverse-judge config/endpoints and the independent reverse-judge quality gate, reset limits, submit/check/review/handle appeals, and run batch/admin actions.

For ordinary student-only workflows, prefer `numoj-user` with a student account unless the user explicitly wants to operate as an administrator.

## Examples

Check administrator login:

```bash
python3 scripts/numoj_admin.py auth status
```

Inspect dynamic-config metadata and current global settings:

```bash
python3 scripts/numoj_admin.py site-config meta
python3 scripts/numoj_admin.py site-config llm list
python3 scripts/numoj_admin.py site-config binding list
python3 scripts/numoj_admin.py site-config mail get
python3 scripts/numoj_admin.py site-config web-search get
```

Create an OpenAI-compatible text endpoint. `create` and `update` perform the
required connection test and save in one command; the API key and one-time test
token are never printed:

```bash
python3 scripts/numoj_admin.py site-config llm create \
  --protocol openai \
  --category text \
  --endpoint-base-url https://llm.example.com/v1 \
  --api-key-env NUMOJ_LLM_API_KEY \
  --env-file site-config-secrets.env \
  --model example-model \
  --thinking

python3 scripts/numoj_admin.py site-config llm update <endpoint_id> \
  --model example-model-v2 \
  --api-key @llm-api-key.txt \
  --input-price-per-million 1 \
  --cached-input-price-per-million 0.02 \
  --output-price-per-million 2
```

Bind a feature, then lock and unlock the repository Embedding binding. Read the
exact confirmation phrase from `site-config meta`; omit `--password` to use the
non-echoing interactive password prompt:

```bash
python3 scripts/numoj_admin.py site-config binding set ai_code_annotation \
  --endpoint-id <endpoint_id>
python3 scripts/numoj_admin.py site-config binding lock-embedding \
  --reason "Index configuration is verified"
python3 scripts/numoj_admin.py site-config binding unlock-embedding \
  --confirmation "我已阅读上述内容，我清楚后果，我坚持要解锁"
```

Save and test SMTP or WebSearch settings. Secret values accept direct text,
`@file`, or an environment-variable name with an optional dotenv file:

```bash
python3 scripts/numoj_admin.py site-config mail set \
  --smtp-server smtp.example.com \
  --smtp-port 465 \
  --smtp-username noreply@example.com \
  --smtp-password-env NUMOJ_SMTP_PASSWORD \
  --env-file site-config-secrets.env
python3 scripts/numoj_admin.py site-config mail test

python3 scripts/numoj_admin.py site-config web-search set \
  --search-base-url https://search.example.com/mcp \
  --authorization-env NUMOJ_WEB_SEARCH_AUTHORIZATION \
  --env-file site-config-secrets.env
python3 scripts/numoj_admin.py site-config web-search test
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

Manage a user's classes, privileges, and grades:

```bash
python3 scripts/numoj_admin.py user add-to-class <user_id> C2026A
python3 scripts/numoj_admin.py user grant-admin <user_id>
python3 scripts/numoj_admin.py user grades <user_id>
```

`user grant-admin` is a one-way privilege grant. It is idempotent for users who
are already administrators and does not change any class memberships.

Create and configure a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking create --title "第 1 周打榜赛" --max-score 100
python3 scripts/numoj_admin.py ranking save-rules <competition_id> @rules.json
python3 scripts/numoj_admin.py ranking save-endpoint <competition_id> \
  --harness codex \
  --protocol openai \
  --agent-base-url https://llm.example.com/v1 \
  --api-key-env LLM_API_KEY \
  --model example-model
```

Create or edit a reverse-judge ranking competition and configure the AI answering endpoint:

```bash
python3 scripts/numoj_admin.py ranking edit <competition_id> \
  --scoring-mode reverse_judge \
  --submission-method zip \
  --agent-timeout 600
python3 scripts/numoj_admin.py ranking save-endpoint <competition_id> \
  --harness pi \
  --protocol openai \
  --agent-base-url https://llm.example.com/v1 \
  --api-key-env LLM_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --context-window-tokens 1000000 \
  --max-output-tokens 384000 \
  --thinking-compatibility \
  --timeout-seconds 600
```

Endpoint model metadata defaults to a 1,000,000-token context window, 384,000
maximum output tokens, and thinking compatibility enabled. The single-endpoint
commands accept `--protocol`, `--context-window-tokens`, `--max-output-tokens`, and
`--thinking-compatibility` / `--no-thinking-compatibility`. For endpoint-pool
JSON passed to `save-endpoints` or `save-quality-gate-endpoints`, use the fields
`protocol`, `context_window_tokens`, `max_output_tokens`,
`thinking_compatibility`, and `thinking_format` on
each endpoint object. New endpoints receive the server defaults when these
fields are omitted; updates that carry an existing endpoint `id` retain that
endpoint's current values when the fields are omitted.
Context and maximum-output values must be positive integers no greater than
1,000,000, and maximum output cannot exceed the context window.

Configure the reverse-judge quality gate. Its endpoint pool is independent from the AI-answering pool and is scheduled automatically; participants never select a quality endpoint. The prompt and endpoint JSON support `@file`, and endpoint secrets may use `api_key_env` plus `--env-file` just like the Agent-as-Judge pool:

```bash
python3 scripts/numoj_admin.py ranking save-quality-gate <competition_id> \
  --disabled \
  --prompt @quality-gate-prompt.txt
python3 scripts/numoj_admin.py ranking save-quality-gate-endpoints <competition_id> \
  @quality-gate-endpoints.json \
  --env-file agent-secrets.env
python3 scripts/numoj_admin.py ranking save-quality-gate <competition_id> --enabled
```

Submit and inspect a ranking competition:

```bash
python3 scripts/numoj_admin.py ranking submit <competition_id> --base-model qwen3 --answer-file answer.json --code-zip code.zip
python3 scripts/numoj_admin.py ranking submit <competition_id> --code-zip reverse_problem.zip --agent-endpoint-id <answer_endpoint_id>
python3 scripts/numoj_admin.py ranking reverse-stream <competition_id> <submission_id> --max-lines 10
python3 scripts/numoj_admin.py ranking download-submission <submission_id> ai-answer -o ./ai-answer.zip
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

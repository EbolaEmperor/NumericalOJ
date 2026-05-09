# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The production deployment lives on the `why-server` host at `/home/ebola/oj/`; the local checkout is synced there via `scp` / `rsync` (see [Deployment to why-server](#deployment-to-why-server) for the full procedure).

NumericalOJ is a Chinese-language educational online judge for MATLAB/Octave, C, C++, and Python. Beyond standard programming-judge features it ships:

- Class management (per-class assignments, score export, submission-count limits, code plagiarism / AI-generated-code detection).
- Programming problems with AI-tutor feedback after evaluation, and AI agents that can solve problems / generate test data.
- Written-homework problems graded by AI after LaTeX OCR transcription of submitted images.
- A per-user header-file repository (`user_libraries/`, `library/`) that programming submissions can `#include`, with vector-indexed search.
- Forum, ranking-style competitions, and a small games surface.

The README (`README.md`) is in Chinese and is mostly deployment-focused.

## Running the system

There are **three** processes; all three must run together for the app to work end-to-end:

```bash
# 1. Web app (Flask, port 2025) — serves UI + API, registers Celery tasks
python3 oj.py
# or under supervisord:
supervisord -c web.conf

# 2. Celery workers — judging + AI agents, two queues
supervisord -c celery.conf
# Equivalent: celery -A oj.celery worker -Q celery   (judging)
#             celery -A oj.celery worker -Q agent -c 1  (AI agents)

# 3. Sandboxed code-execution service (Flask, port 5050)
cd judger && python3 app.py
# or: cd judger && supervisord -c judger.conf

# Plus: redis-server (broker + caches), mysqld (myojdb)
```

The web app expects both Redis (`REDIS_HOST/PORT/DB` in `config.py`) and the judger reachable at `http://localhost:5050` from the Celery `celery` queue worker. The IP whitelist in `judger/app.py` (`ALLOWED_IPS`) is `127.0.0.1` only — the judger must run on the same host as Celery.

DB bootstrap: `mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;" && mysql -u root -p myojdb < myojdb.sql`. Default admin is `admin` / `admin123`.

There is no test suite, lint config, or build step. Sanity-check changes with `python3 -m py_compile <file>` (the existing `.claude/settings.local.json` allowlists this pattern across the codebase).

## Deployment to why-server

When the user asks you to deploy, follow this procedure end-to-end. Don't push code to `why-server` unless deployment is explicitly requested.

1. **Sync the local code to `why-server:/home/ebola/oj/`.** The canonical command lives in `.claude/settings.local.json` — it's an `rsync -avz` that already excludes `config.py`, `static/`, `__pycache__`, `.git`, `tmp/`, and `uploads/`. Use that command (or an equivalent `scp` for individual files); never copy the whole tree without those exclusions.
2. **Find and kill the existing supervisord processes** on the remote host: run `ps aux | grep "supervisor"` over SSH, identify the PIDs of the three running supervisords (one per conf file), and kill them.
3. **Restart the three supervisord groups** in this order: `judger.conf`, `web.conf`, `celery.conf`. Each is launched as `supervisord -c <name>.conf` from `/home/ebola/oj/` (and `judger.conf` from `/home/ebola/oj/judger/`).

### Frontend-only fast path

If the change touches **only** templates (`templates/*.html`) or other client-side assets, `scp` the modified files over and stop there — do **not** kill or restart supervisord. The Flask app runs in debug mode and auto-reloads templates on each request, so the change is live as soon as the file lands. Reserve the full kill-and-restart procedure above for Python or config changes that the running interpreter wouldn't pick up.

### Remote files that must NOT be overwritten

These two paths on `why-server` are append-only — you may add to them, but never overwrite or delete what's already there:

- **`static/`** — production may host extra vendored assets that aren't in the local checkout. If you need a new asset, `scp` it in additively; never `rsync --delete` this directory.
- **`config.py`** — holds the production DashScope API keys, MySQL password, mail SMTP credentials, etc. The local `config.py` is a placeholder template and must not clobber the remote copy. If a new config knob is genuinely required, ask the user to add it manually on the server, or add code that reads from a separate file with a sensible fallback.

The default `rsync` command in `.claude/settings.local.json` already excludes `config.py`; it does **not** exclude `static/`, so be careful when adjusting flags.

## Configuration

`config.py` is **tracked in git as a template with placeholder values** — fill in MySQL credentials, mail SMTP, and DashScope (Aliyun Qwen) keys before the app will work. There is no separate `.env`. Keys to know:

- `MYSQL_*`, `REDIS_*` — infra.
- `DASHSCOPE_*`, `CODING_PLAN_*`, `QWEN_*_MODEL`, `AI_TUTOR_MODEL` — Aliyun DashScope endpoints used everywhere AI is involved (tutor feedback, written-homework grading, agent solver, embeddings).
- `MATLAB_AI_DETECT_*` — points at a self-hosted vLLM-served fine-tuned detector for MATLAB AI-generated code.
- `REPOSITORY_*` — vector-search config for the user-library repository (FAISS index under `tmp/repository_vector_index`).
- `AGENT_*` — limits for the problem-solving / test-data-generation agents (max rounds, submit limit, context size, memory).

## Architecture

### Two-process boundary (important)

The code-execution sandbox is a **separate Flask service** (`judger/app.py`, port 5050) that the main app calls over HTTP. Endpoints: `/run-hello` (Octave/MATLAB), `/run-c`, `/run-cpp`, `/run-py` for one-shot runs; `/batch-evaluate-{c,cpp}` and streaming NDJSON variants `/batch-evaluate-stream-{c,cpp}` compile once and run many test points. Sandboxing is `coreutils timeout` + `RLIMIT_CPU` + `RLIMIT_AS`, plus a regex-based forbidden-function filter (`check_forbidden`) on user code. The C/C++ compilers add `-I <OJ_ROOT>/library` for shared headers; per-submission user header files arrive in the `user_files` field and are written into the run directory.

### Web app composition (`oj.py`)

`oj.py` is a thin shell. It:

1. Creates the Flask app and Redis clients (`rds` decoded; `rds_binary` raw bytes for ZIP/binary cache values).
2. Registers ~15 Blueprints from `oj_modules/routes/*.py`. Each route module owns a feature surface (auth, problem-core, submissions, admin-problem, admin-user, homework, ranking, repository, AI-detection, AI tutor, class management, forum, grading, rejudge, games).
3. Constructs a single Celery app (`oj.celery`, two queues: `celery` for judging, `agent` for the slower AI-agent tasks) and calls each `register_*_task(celery, ...)` factory in `oj_modules/tasks/__init__.py` to obtain bound task references.
4. Calls `init_*_module(...)` on the route modules that need Celery task references or Redis, plus `init_submission_snapshot_cache(rds)` and `init_agent_progress_cache(rds)`.

The `register → init` pattern is load-bearing: route modules **do not import Celery tasks directly**; they receive bound task callables via `init_*_module`. When adding a new background task, follow this pattern — write `register_xxx_task(celery_app, ...)` returning the bound task, expose it from `oj_modules/tasks/__init__.py`, then have `oj.py` pass it into the relevant route module's `init_xxx_module`.

### Module layout

- `oj_modules/db_services.py` (~2k lines) — the catch-all DB layer. Owns a hand-rolled MySQL connection pool (`_PooledConnectionProxy`) configured via `MYSQL_POOL_*`; **always use `get_db_connection()` from here, never construct pymysql connections directly**, otherwise the pool semantics break. Also lazy-creates and migrates a few columns/tables on first access (the `_*_ready` flags).
- `oj_modules/ai_utils.py` — DashScope wrappers, prompts, image-aware grading helpers, response normalization. Anything that talks to Qwen models lives here.
- `oj_modules/tasks/` — Celery task definitions. `evaluate_tasks.py` is the judging pipeline (uses HTTP to the judger). `agent_solve_task.py`, `agent_generate_testdata_task.py`, `agent_solve_helpers.py`, `agent_generate_helpers.py`, `agent_shared.py` implement the multi-round AI agents. `written_homework_tasks.py` does LaTeX OCR + grading. `ai_detection_tasks.py` runs the AI-code detector. `repository_index_tasks.py` builds FAISS indexes for the user-library repository. `ranking_evaluate_tasks.py` is the ranking-competition judge.
- `oj_modules/ai_detection/` — orchestration for AI-generated-code detection (LLM-based + behavioral signals) with `detector.py` combining them. Final score = `min(1.0, llm_score + behavior_score * 0.3)`.
- `oj_modules/repository_index_services.py` — FAISS-backed vector search over user-library code chunks; embeddings via Qwen `text-embedding-v4`.
- `oj_modules/ranking_db.py` — ranking-competition data layer.
- `templates/` is flat (no subdirs); `layout.html` is the base, `layout_embedded.html` for iframe-style views.
- `static/` bundles vendored Bootstrap, CodeMirror, MathJax, FontAwesome.

### Database

MySQL schema lives in `myojdb.sql`. Core tables: `users`, `class_table`, `user_class_map`, `problems`, `submissions`, `submission_test_points`, `submission_limits`, `ac_record`, `max_score`, `agent_task_runs`, `forum_threads`, `forum_replies`, `final_exam_scores`, `verification_codes`, `user_code_repository`, `repository_index_jobs`, `repository_function_chunks`, `repository_class_metadata`, `repository_chunk_embeddings`, `ai_detection_results`, `ai_detection_tasks`. Per-user-per-problem submission count is capped (default 5) by `submission_limits`. Submissions have a Redis snapshot cache (`init_submission_snapshot_cache`) used by the live UI; DB is the source of truth.

### Cache and locks (Redis)

- DB `0` (configurable) holds: Celery broker/backend, submission status snapshots (`SUBMISSION_SNAPSHOT_TTL_SECONDS`), evaluation locks (`EVALUATE_SUBMISSION_LOCK_TTL_SECONDS`, prevents double-judging on retry), agent run progress + pubsub event streams.
- A second binary-decoded client `rds_binary` is used for cached ZIP / binary blobs (e.g., bulk homework downloads).

## Conventions worth knowing

- The repo's working language is Chinese: most user-visible strings, status names, and a lot of comments are in Chinese. Keep that style when editing UI / templates / messages.
- Forbidden-function checking happens in **two places**: server-side problem config sends a comma-separated list to the judger which regex-matches `<func>(`, and the judger has special-cased the literal `\` for Octave. If you add a language, mirror this contract.
- Time limits are passed in **nanoseconds**; memory limits arrive in bytes and the judger multiplies by 10 internally before applying `RLIMIT_AS` (legacy quirk — keep it consistent across `/run-*` endpoints).
- The competitions material under `competitions/` is gitignored; treat it as scratch / dataset work, not part of the deployed app.
- `.codex/skills/matlab-problem-setter/` is a Codex skill for scaffolding MATLAB problem packages — useful as a reference for the expected problem-package structure (`problem.md`, `data/*.in`/`*.out`, `interactor.m`, `template.m`, `solution.m`, `config.json`), even when working from Claude Code.
- `fix-tools/` holds one-off SQL scripts for data repair; not run automatically.
- Production deploy target is `why-server:/home/ebola/oj/` — see [Deployment to why-server](#deployment-to-why-server). Don't push there unless the user explicitly asks for a deploy.

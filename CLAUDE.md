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

There are **two** processes; both must run together for the app to work end-to-end:

```bash
# 1. Web app (Flask, port 2025) — serves UI + API, registers Celery tasks
python3 oj.py
# or under supervisord:
supervisord -c web.conf

# 2. Celery workers — judging + AI agents + Agent-as-Judge, three queues
supervisord -c celery.conf
# Equivalent: celery -A oj.celery worker -Q celery   (judging + in-process sandbox)
#             celery -A oj.celery worker -Q agent -c 1  (AI agents)
#             celery -A oj.celery worker -Q judge -c 2  (打榜赛 Agent-as-Judge, runs Docker containers)

# Plus: redis-server (broker + caches), mysqld (myojdb)
```

The sandboxed code execution runs **in-process inside the Celery `celery`-queue worker** (`oj_modules/judger_core.py`, called directly by `evaluate_tasks.py`) — there is no longer a separate judger HTTP service on port 5050. The web app only needs Redis (`REDIS_HOST/PORT/DB` in `config.py`) reachable. Because the sandbox shells out to `gcc`/`g++`/`python3`/`octave`, the Celery worker host must have those toolchains (and Intel MKL, if used); run dirs live under `JUDGER_RUN_ROOT` (default `<OJ_ROOT>/tmp/judger_runs`).

DB bootstrap: `mysql -u root -p -e "CREATE DATABASE myojdb CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;" && mysql -u root -p myojdb < myojdb.sql`. Default admin is `admin` / `admin123`.

There **is** a pytest suite under `tests/` (`tests/unit`, `tests/db`, `tests/e2e`, plus `tests/ci` infra) with `pytest.ini` and `tests/conftest.py` (DB-resetting fixtures). Always sanity-check changes with `python3 -m py_compile <file>`, and run the relevant tests before deploying:

- Infra-free pure-logic tests can run on local/dev machines, but **never on `why-server` / host `computing`**: `pytest tests/unit/test_judger_core.py tests/unit/test_security_regression.py tests/unit/test_grading_and_compare.py tests/unit/test_sandbox_limits.py`.
- `tests/db` needs MySQL + Redis and must run only on a local machine or another non-production server with clearly disposable services.
- `tests/e2e/` is the CLI-driven end-to-end path: each file starts a local Flask service against disposable MySQL/Redis and drives real HTTP routes through `skills/numoj-admin/scripts/numoj_admin.py` and `skills/numoj-user/scripts/numoj_user.py`, split by auth, problem/submission, homework/class, repository/forum, ranking, AI-detection, and help-matrix scenarios. It must run only on a local machine or another non-production server.
- CI/full-suite test runs, including anything under `tests/ci/`, are **forbidden on `why-server` / host `computing`**. If they must be run manually, run them locally or on a separate non-production server; never use the production host as a CI runner. A lightweight GitHub Actions gate (`.github/workflows/ci.yml`) runs `compileall` + the infra-free unit tests on every push/PR.

### Data safety boundary

There has been a real production incident where unit tests were run directly on `why-server` (the production host's own hostname is `computing`) and the production database was cleared. Avoid repeating this class of failure:

- **Never run any tests on `why-server` / host `computing`, including infra-free unit tests, DB tests, CLI e2e smoke tests, CI scripts, Docker-Compose test runners, or isolated test containers.** The production host is for serving the app and explicit deploy/ops work only, not for verification runs.
- **Never run `pytest` in the production checkout (`why-server:/home/ebola/oj/`) or in any shell that is using the production `config.py`, production MySQL database (`myojdb`), or production Redis.** The test fixtures can reset tables and must be treated as destructive when pointed at live services.
- **Never run DB-resetting tests, CLI e2e smoke tests, migrations, seed scripts, SQL imports, or repair scripts against production data unless the user explicitly asks for that exact production operation.** Before any such command, confirm the hostname, working directory, config file, database host, database name, and Redis target.
- **CI tests must not run on `why-server` / host `computing`, even if they claim to use isolated infrastructure.** There is intentionally no remote-run helper script; run tests only from a local/dev machine or a separate CI runner.
- **Read-only production inspection is allowed; production writes are not implicit.** Safe production operations are limited to read-only SQL (`SELECT`, `SHOW`, `EXPLAIN`), log inspection, process inspection, and the explicit deploy procedure. Any production data write, delete, truncate, import, migration, or script with side effects requires explicit user approval and a backup/rollback plan.
- **Before running a command that might touch data, prove it is not production.** If the target cannot be clearly identified as local, containerized, disposable, or backed up, stop and ask instead of guessing.

There is no separate lint config or build step.

Cross-cutting helpers added during the 2026 hardening pass — prefer these over re-implementing:
- `oj_modules/auth_helpers.py` — single source of `current_user`/`is_admin` + `login_required`/`admin_required` decorators (don't re-define per route module; `problem_core_routes` keeps a memoized variant on purpose).
- `oj_modules/security_utils.py` — `hash_password`/`verify_password` (werkzeug KDF, verify-then-rehash of legacy sha256) and `rate_limit_hit`/`cooldown_active` (Redis, fail-open).
- `oj_modules/markdown_utils.py` — `sanitize_html`/`render_markdown` (bleach allowlist, regex-scrub fallback). Every Markdown sink rendered with `| safe` MUST pass through `sanitize_html`.
- `oj_modules/db_services.py::safe_table_name(name)` — MUST wrap any class/dynamic table name interpolated into SQL (the per-class-table f-string pattern).

## Deployment to why-server

When the user asks you to deploy, follow this procedure end-to-end. Don't push code to `why-server` unless deployment is explicitly requested.

1. **Sync the local code to `why-server:/home/ebola/oj/`.** The canonical command lives in `.claude/settings.local.json` — it's an `rsync -avz` that already excludes `config.py`, `static/`, `__pycache__`, `.git`, `tmp/`, and `uploads/`. Use that command (or an equivalent `scp` for individual files); never copy the whole tree without those exclusions.
2. **Find and kill the existing supervisord processes** on the remote host: run `ps aux | grep "supervisor"` over SSH, identify the PIDs of the two app supervisords (`web.conf`, `celery.conf`), and kill them. Leave the system supervisord (`/etc/supervisor/supervisord.conf`, owned by `root`) alone. The old `judger.conf` group no longer exists; if a stale judger supervisord / `judger/app.py` is still running from a previous deploy, kill it too. **Kill by explicit PID, not `pkill -f <pattern>`** — a `pkill -f` pattern can match the very SSH shell running it and abort the command midway.
3. **Restart the two supervisord groups** in this order: `web.conf`, then `celery.conf`. Each is launched as `supervisord -c <name>.conf` from `/home/ebola/oj/`.

### Agent-as-Judge image (打榜赛 `agent_judge` mode)

The `agent_judge` ranking mode judges submissions inside a prebuilt Docker image (`numericaloj-agent-judge:latest`) that bundles the Agent Harness CLIs (`claude`, `codex`, `opencode`) + toolchain. `rsync` does **not** rebuild it — after changing `docker/agent_judge/*`, rebuild once on the host: `docker build -t numericaloj-agent-judge:latest docker/agent_judge`. The `celery_agent_judge` worker (`-Q judge`, local config keeps the production concurrency at `-c 16`) runs `docker run` per submission; the host must have Docker and the worker user must be in the `docker` group. Do **not** add `--cap-drop ALL` to that `docker run` — it removes `CAP_DAC_OVERRIDE`, breaking both result-file writes and in-container `apt`. Per-competition model creds (harness / base_url / api_key / model) live in MySQL, not `config.py`; the `AGENT_JUDGE_*` infra knobs are read via `getattr(config, ...)` defaults so the remote `config.py` needs no edits.

There is also a local lightweight image at `docker/agent_judge-lite/` (`numericaloj-agent-judge-lite:latest`). It excludes Intel MKL, Octave, heavy OCR/ML/browser stacks, `texlive-full`, Chinese TeX packages, Codex, and opencode; it keeps Claude Code, OpenBLAS/LAPACK/Eigen, basic English LaTeX, and common Python scientific packages. Build it with `docker build -f docker/agent_judge-lite/Dockerfile -t numericaloj-agent-judge-lite:latest docker`. The judge worker reads `AGENT_JUDGE_DOCKER_IMAGE` from the environment before `config.py`; `local_dev.conf` sets that variable to the lite image for this checkout, while production remains on `numericaloj-agent-judge:latest` by default.

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
- `DASHSCOPE_*`, `QWEN_*_MODEL`, `AI_TUTOR_MODEL` — Aliyun DashScope endpoints used everywhere AI is involved (tutor feedback, written-homework grading, agent solver, embeddings).
- `MATLAB_AI_DETECT_*` — points at a self-hosted vLLM-served fine-tuned detector for MATLAB AI-generated code.
- `REPOSITORY_*` — vector-search config for the user-library repository (FAISS index under `tmp/repository_vector_index`).
- `AGENT_*` — limits for the problem-solving / test-data-generation agents (max rounds, submit limit, context size, memory). `AGENT_MAX_ROUNDS` is now actually enforced in the agent ReAct loops.

**Optional hardening knobs (all read via `getattr(config, ...)` / env with safe defaults — the remote `config.py` needs no edits):**
- `SECRET_KEY` (config) — Flask session-signing key. If absent, a random key is generated and persisted to `tmp/secret_key` (gitignored, stable across restarts). The old hardcoded key is gone.
- `FLASK_DEBUG` (config, default `False`) — never enable in production (Werkzeug debugger = RCE). Templates still hot-reload via `TEMPLATES_AUTO_RELOAD` even with debug off, so the frontend fast-path still works.
- `SESSION_COOKIE_SECURE` (config, default `False`) — set `True` once served over HTTPS. `HttpOnly` + `SameSite=Lax` are always on.
- `CONTENT_SECURITY_POLICY` (config) — overrides the default permissive CSP set in `oj.py`'s `after_request`.
- `JUDGER_RLIMIT_NPROC_HEADROOM` (env, default 1024) / `JUDGER_RLIMIT_NPROC_ABS` (env, default 0=off) / `JUDGER_RLIMIT_FSIZE_BYTES` / `JUDGER_GUARD_TIMEOUT_BUFFER_SEC` (env) — sandbox fork-bomb / disk-fill / Python-timeout-backstop tuning. **`RLIMIT_NPROC` is per-real-UID system-wide**, and judging shares the `ebola` UID with web/celery/MKL threads, so the cap is set to *current UID task count + HEADROOM* (never a fixed small absolute — a fixed 256 caused the 2026-06-06 outage when the UID's live thread count exceeded it and every sandbox `fork()` got EAGAIN). `_ABS` forces a fixed absolute value as an escape hatch.
- `JUDGER_RLIMIT_CPU_STARTUP_BUFFER_SEC` (env, default 30) — **`RLIMIT_CPU` caps *aggregate* CPU-seconds across all threads, not wall-clock.** A multithreaded runtime (Octave/MATLAB BLAS/MKL needs ~4 CPU-s of multi-thread work just to start) blows past a wall-clock-sized CPU cap in milliseconds, so the cap is computed as `cpu_count × ⌈wall_TLE⌉ + STARTUP_BUFFER` — a loose backstop above the legitimate ceiling, with the coreutils `timeout` (wall-clock) as the real bound. A fixed `RLIMIT_CPU = wall_TLE` caused the 2026-06-06 Octave "all Nonzero Exit Status" outage (every octave submission SIGKILLed at startup).
- `JUDGER_OCTAVE_RLIMIT_AS` (env, default off) — Octave gets CPU (multithread-aware, see above) / NPROC / FSIZE limits, but `RLIMIT_AS` is opt-in (it historically broke Octave/MKL virtual-memory reservations). Verify Octave's virtual footprint before enabling.

Note: after editing `docker/agent_judge/report` or `docker/agent_judge/run_harness`, rebuild the agent-judge image (`docker build -t numericaloj-agent-judge:latest docker/agent_judge`).

## Architecture

### Two-process boundary (important)

The code-execution sandbox is an **in-process library** (`oj_modules/judger_core.py`) that the Celery `celery`-queue worker calls directly from `evaluate_tasks.py`. (It used to be a separate Flask service on port 5050 with an `ALLOWED_IPS` whitelist; that service was removed.) API: `run_single(language, data)` for one-shot Octave/C/C++/Python runs; `batch_evaluate_stream(language, data)` — a **generator** yielding `compile` / `test_result` / `done` events, the in-process replacement for the old NDJSON stream that preserves live per-test-point snapshot updates; and `batch_evaluate(language, data)` (non-stream). The `data` and result dicts keep the same field shape as the old HTTP payloads. Sandboxing is `coreutils timeout` + `RLIMIT_CPU` + `RLIMIT_AS` (set in a `preexec_fn`, which works in Celery prefork — forked — workers), plus a regex-based forbidden-function filter (`check_forbidden`) on user code. The C/C++ compilers add `-I <OJ_ROOT>/library` for shared headers; per-submission user header files arrive in the `user_files` field and are written into the run directory (`JUDGER_RUN_ROOT/<sid>`).

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
- `oj_modules/tasks/` — Celery task definitions. `evaluate_tasks.py` is the judging pipeline (runs the sandbox in-process via `oj_modules/judger_core.py`). `agent_solve_task.py`, `agent_generate_testdata_task.py`, `agent_solve_helpers.py`, `agent_generate_helpers.py`, `agent_shared.py` implement the multi-round AI agents. `written_homework_tasks.py` does LaTeX OCR + grading. `ai_detection_tasks.py` runs the AI-code detector. `repository_index_tasks.py` builds FAISS indexes for the user-library repository. `ranking_evaluate_tasks.py` is the ranking-competition judge.
- `oj_modules/ai_detection/` — orchestration for AI-generated-code detection (LLM-based + behavioral signals) with `detector.py` combining them. Final score = `min(1.0, llm_score + behavior_score * 0.3)`.
- `oj_modules/repository_index_services.py` — FAISS-backed vector search over user-library code chunks; embeddings via Qwen `text-embedding-v4`.
- `oj_modules/ranking_db.py` — ranking-competition data layer.
- `templates/` is flat (no subdirs); `layout.html` is the base, `layout_embedded.html` for iframe-style views.
- `static/` bundles vendored Bootstrap, CodeMirror, MathJax, FontAwesome.

### Database

MySQL schema lives in `myojdb.sql`. Core tables: `users`, `class_table`, `user_class_map`, `problems`, `submissions`, `submission_test_points`, `submission_limits`, `ac_record`, `max_score`, `agent_task_runs`, `forum_threads`, `forum_replies`, `final_exam_scores`, `verification_codes`, `user_code_repository`, `repository_index_jobs`, `repository_function_chunks`, `repository_class_metadata`, `repository_chunk_embeddings`, `ai_detection_results`, `ai_detection_tasks`. Per-user-per-problem submission count is capped (default 5) by `submission_limits`. Submissions have a Redis snapshot cache (`init_submission_snapshot_cache`) used by the live UI; DB is the source of truth.

### Cache and locks (Redis)

- DB `0` (configurable) holds: Celery broker/backend, submission status snapshots (`SUBMISSION_SNAPSHOT_TTL_SECONDS`), evaluation locks (`EVALUATE_SUBMISSION_LOCK_TTL_SECONDS`, prevents double-judging on retry), the self-scheduling Pending requeue watchdog owner/items, agent run progress + pubsub event streams.
- A second binary-decoded client `rds_binary` is used for cached ZIP / binary blobs (e.g., bulk homework downloads).

## Conventions worth knowing

- The repo's working language is Chinese: most user-visible strings, status names, and a lot of comments are in Chinese. Keep that style when editing UI / templates / messages.
- Forbidden-function checking: the problem's comma-separated forbidden list is passed to `judger_core.check_forbidden`, which regex-matches `<func>(` (and special-cases the literal `\` for Octave). If you add a language, mirror this contract.
- Time limits are passed in **nanoseconds**; memory limits arrive in bytes and `judger_core` multiplies by 10 internally before applying `RLIMIT_AS` (legacy quirk — keep it consistent across the `run_*` / `batch_*` functions).
- The competitions material under `competitions/` is gitignored; treat it as scratch / dataset work, not part of the deployed app.
- `.codex/skills/matlab-problem-setter/` is a Codex skill for scaffolding MATLAB problem packages — useful as a reference for the expected problem-package structure (`problem.md`, `data/*.in`/`*.out`, `interactor.m`, `template.m`, `solution.m`, `config.json`), even when working from Claude Code.
- `fix-tools/` holds one-off SQL scripts for data repair; not run automatically.
- Production deploy target is `why-server:/home/ebola/oj/` — see [Deployment to why-server](#deployment-to-why-server). Don't push there unless the user explicitly asks for a deploy.

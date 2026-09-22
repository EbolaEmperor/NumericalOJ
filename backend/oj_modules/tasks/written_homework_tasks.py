#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import pymysql

from backend.oj_modules.config import EVALUATE_SUBMISSION_LOCK_TTL_SECONDS
from backend.oj_modules.shared.archive import (
    ArchiveExtractionError,
    ZipExtractionPolicy,
    extract_zip,
)
from backend.oj_modules.ai.grading import (
    WrittenGradingRound,
    evaluate_written_homework_with_ai,
    evaluate_written_homework_with_ai_from_images,
    reconsider_written_homework_with_ai,
)
from backend.oj_modules.ai.transcription import (
    render_pdf_to_images,
    save_transcribed_latex,
)
from backend.oj_modules.ai.client import resolve_problem_llm_endpoint_snapshot
from backend.oj_modules.problems.llm_bindings import (
    DIRECT_IMAGE_GRADING_ENDPOINT_ID,
    TEXT_GRADING_ENDPOINT_ID,
    deserialize_problem_llm_bindings,
)
from backend.oj_modules.problems.written_vote import normalize_written_vote_config
from backend.oj_modules.site_config.services import get_llm_endpoint
from backend.oj_modules.db_services import (
    get_problem,
    get_submission_by_id,
    refresh_submission_status_snapshot,
    update_submission_status,
)
from backend.oj_modules.submissions.grading import (
    get_file_path_for_submission,
    update_submission_comment,
    update_submission_score_and_comment,
)
from backend.oj_modules.submissions.locks import acquire_submission_lock, release_submission_lock
from backend.oj_modules.submissions.written_voting import (
    create_attempt,
    finish_attempt,
    get_latest_attempt,
    update_vote,
)


WRITTEN_TASK_NAME = "oj.transcribe_written_homework_to_latex"
# 硬超时必须小于幂等锁 TTL（EVALUATE_SUBMISSION_LOCK_TTL_SECONDS），否则锁会先于任务过期，
# 导致重投的副本拿到锁并重复评分（重复计费 AI）。这里预留 120s，使「锁存活 > 任务时限」。
_WRITTEN_TASK_TIME_LIMIT = max(60, int(EVALUATE_SUBMISSION_LOCK_TTL_SECONDS) - 120)
_WRITTEN_TASK_SOFT_TIME_LIMIT = max(30, _WRITTEN_TASK_TIME_LIMIT - 60)
_MYSQL_RETRY_ERRORS = (
    pymysql.err.OperationalError,
    pymysql.err.InterfaceError,
    pymysql.err.InternalError,
)
_TEX_BEGIN_DOCUMENT_PATTERN = re.compile(r"\\begin\{document\}", flags=re.IGNORECASE)
_TEX_HAS_CJK_SETUP_PATTERN = re.compile(
    r"\\usepackage(?:\[[^\]]*\])?\{[^}]*?(?:xeCJK|ctex|CJKutf8)[^}]*\}|\\documentclass(?:\[[^\]]*\])?\{ctex[^}]*\}",
    flags=re.IGNORECASE,
)
_TEX_MISSING_CHAR_PATTERN = re.compile(r"Missing character: There is no .*?\(U\+([0-9A-Fa-f]{4,6})\)")
_WRITTEN_PDF_MAX_BYTES = 64 * 1024 * 1024
_VOTE_MAX_WORKERS = 3
_VOTE_CALL_ATTEMPTS = 3
_VOTE_CALL_TIMEOUT_SECONDS = 45
_TEX_COMPILE_SCRIPT = r'''
set -u
source_path="$1"
base_name="$2"
stage_timeout="$3"
export TEXINPUTS="/sandbox//:"
export BIBINPUTS="/sandbox//:"
export BSTINPUTS="/sandbox//:"

run_stage() {
    label="$1"
    shift
    log_path="/case/.numoj-${label}.log"
    "$@" >"$log_path" 2>&1
    rc=$?
    printf "\n[%s]\n" "$label"
    cat "$log_path"
    return "$rc"
}

run_stage "xelatex #1" \
    timeout -k 1s "${stage_timeout}s" \
    xelatex -interaction=nonstopmode -halt-on-error -file-line-error \
    -output-directory=/case "$source_path"
rc=$?
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi

run_stage "bibtex" \
    timeout -k 1s "${stage_timeout}s" bibtex "$base_name"
bib_rc=$?
if [ "$bib_rc" -ne 0 ]; then
    if ! grep -Eqi \
        'no \\citation commands|no \\bibdata command' \
        /case/.numoj-bibtex.log; then
        exit "$bib_rc"
    fi
fi

run_stage "xelatex #2" \
    timeout -k 1s "${stage_timeout}s" \
    xelatex -interaction=nonstopmode -halt-on-error -file-line-error \
    -output-directory=/case "$source_path"
rc=$?
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi

run_stage "xelatex #3" \
    timeout -k 1s "${stage_timeout}s" \
    xelatex -interaction=nonstopmode -halt-on-error -file-line-error \
    -output-directory=/case "$source_path"
exit $?
'''


def _fake_written_homework_grade_from_env():
    raw_score = os.getenv("NUMOJ_FAKE_WRITTEN_HOMEWORK_SCORE")
    if raw_score is None:
        return None
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        score = 5.0
    score = max(0.0, min(5.0, score))
    if score.is_integer():
        score = int(score)
    comment = os.getenv("NUMOJ_FAKE_WRITTEN_HOMEWORK_COMMENT") or "本地假书面批改结果。"
    return score, comment


def _is_deterministic_written_input_error(error):
    text = str(error or "")
    markers = (
        "Failed to load document",
        "Data format error",
        "No such file",
        "not a zip file",
        "File is not a zip file",
        "BadZipFile",
        "ZIP 中未找到 main.tex",
        "提交的 TeX 文本为空",
        "转写得到的 LaTeX 为空",
    )
    return any(marker in text for marker in markers)


def _written_vote_endpoint_key(written_mode):
    return (
        DIRECT_IMAGE_GRADING_ENDPOINT_ID
        if int(written_mode) == 2
        else TEXT_GRADING_ENDPOINT_ID
    )


def _resolve_written_vote_plan(problem, written_mode):
    """在批改开始时冻结所有评委端点；旧题的单端点绑定自动视为 1 票。"""

    config = normalize_written_vote_config((problem or {}).get("written_vote_config"))
    binding_key = _written_vote_endpoint_key(written_mode)
    if not config:
        endpoint_id = deserialize_problem_llm_bindings(
            (problem or {}).get("llm_endpoint_bindings")
        ).get(binding_key)
        if endpoint_id is None:
            # 复用既有诊断文本。
            resolve_problem_llm_endpoint_snapshot(problem, binding_key)
        config = [{"endpoint_id": int(endpoint_id), "count": 1}]

    plan = []
    vote_index = 1
    for item in config:
        raw_endpoint = get_llm_endpoint(item["endpoint_id"], include_secret=True)
        endpoint = resolve_problem_llm_endpoint_snapshot(
            problem,
            binding_key,
            endpoint=raw_endpoint,
        )
        revision = max(1, int(raw_endpoint.get("revision") or 1))
        for _ in range(int(item["count"])):
            plan.append({
                "vote_index": vote_index,
                "endpoint_id": int(item["endpoint_id"]),
                "endpoint_revision": revision,
                "model": endpoint.model,
                "endpoint": endpoint,
            })
            vote_index += 1
    return config, plan


def _run_written_vote(attempt_id, vote, evaluator):
    last_error = None
    for call_attempt in range(1, _VOTE_CALL_ATTEMPTS + 1):
        update_vote(vote["id"], status="running", call_attempts=call_attempt)
        try:
            evaluated = evaluator(vote["endpoint"])
            if isinstance(evaluated, WrittenGradingRound):
                score = int(evaluated.score)
                comment = str(evaluated.comment or "")
                round_result = evaluated
            else:
                score, comment = evaluated
                score = int(score)
                comment = str(comment or "")
                round_result = None
        except Exception as exc:  # 每一票独立重试，不重跑已经成功的票。
            last_error = exc
            continue
        update_vote(
            vote["id"],
            status="completed",
            score=score,
            comment=comment,
            call_attempts=call_attempt,
        )
        return {"score": score, "comment": comment, "round": round_result}
    update_vote(
        vote["id"],
        status="failed",
        error_message=str(last_error or "模型调用失败"),
        call_attempts=_VOTE_CALL_ATTEMPTS,
    )
    return {"error": str(last_error or "模型调用失败")}


def _run_written_vote_round(attempt, vote_plan, evaluator_for_vote):
    results = [None] * len(vote_plan)
    with ThreadPoolExecutor(max_workers=min(_VOTE_MAX_WORKERS, len(vote_plan))) as executor:
        future_map = {
            executor.submit(
                _run_written_vote,
                attempt["id"],
                vote,
                lambda endpoint, index=index: evaluator_for_vote(index, endpoint),
            ): index
            for index, vote in enumerate(vote_plan)
        }
        for future in as_completed(future_map):
            results[future_map[future]] = future.result()
    return results


def _evaluate_written_votes(attempt, vote_plan, evaluator, reconsider_evaluator=None):
    results = _run_written_vote_round(
        attempt,
        vote_plan,
        lambda _index, endpoint: evaluator(endpoint),
    )

    if any(result is None or result.get("error") for result in results):
        finish_attempt(attempt["id"], status="needs_manual_review")
        return None, "部分 AI 评委连续重试后仍未完成，已转人工复核。"

    scores = {int(result["score"]) for result in results}
    if len(scores) != 1:
        can_reconsider = (
            callable(reconsider_evaluator)
            and all(result.get("round") is not None for result in results)
        )
        if not can_reconsider:
            finish_attempt(attempt["id"], status="needs_manual_review")
            return None, "AI 评委给分不一致，已转人工复核。"

        first_round_results = results

        def evaluate_reconsideration(index, endpoint):
            peers = [
                {
                    "vote_index": int(vote_plan[peer_index]["vote_index"]),
                    "round": peer_result["round"],
                }
                for peer_index, peer_result in enumerate(first_round_results)
                if peer_index != index
            ]
            return reconsider_evaluator(
                endpoint,
                first_round_results[index]["round"],
                peers,
            )

        results = _run_written_vote_round(
            attempt,
            vote_plan,
            evaluate_reconsideration,
        )
        if any(result is None or result.get("error") for result in results):
            finish_attempt(attempt["id"], status="needs_manual_review")
            return None, "第二轮 AI 评委连续重试后仍未完成，已转人工复核。"
        scores = {int(result["score"]) for result in results}
        if len(scores) != 1:
            finish_attempt(attempt["id"], status="needs_manual_review")
            return None, "第二轮 AI 评委给分仍不一致，已转人工复核。"

    score = scores.pop()
    finish_attempt(attempt["id"], status="consensus", consensus_score=score)
    # 兼容既有列表、导出及详情中的单评语字段；完整评语仍以逐票记录为准。
    return score, results[0]["comment"]


def _read_text_file_safe(path, max_chars=300000):
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return (f.read() or "")[:max_chars]
    except Exception:
        return ""


def _write_text_file_safe(path, content):
    if not path:
        return
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(str(content or ""))
    except Exception:
        pass


def _publish_compiled_pdf(output_dir, filename, content):
    safe_name = os.path.basename(str(filename or ""))
    if (
        not safe_name
        or safe_name != filename
        or os.path.splitext(safe_name)[1].lower() != ".pdf"
    ):
        raise ValueError("PDF 产物名称无效")
    data = bytes(content)
    if len(data) > _WRITTEN_PDF_MAX_BYTES:
        raise ValueError("PDF 产物超过大小上限")
    directory_fd = os.open(
        output_dir,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    temporary_name = f".written-pdf-{uuid.uuid4().hex}.tmp"
    created = False
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(
            temporary_name,
            safe_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
        created = False
    finally:
        if created:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def _compile_tex_with_xelatex(tex_path, output_dir, timeout_seconds=120):
    tex_abs = os.path.abspath(str(tex_path or ""))
    if not tex_abs or not os.path.isfile(tex_abs):
        return False, None, "无效的 TeX 文件路径。"

    work_dir_abs = os.path.abspath(str(output_dir or ""))
    if not work_dir_abs or not os.path.isdir(work_dir_abs):
        return False, None, "编译目录不存在。"

    source_name = os.path.basename(tex_abs)
    base_name, _ = os.path.splitext(source_name)
    if not base_name:
        return False, None, "无效的 TeX 主文件名。"

    if os.path.dirname(tex_abs) != work_dir_abs:
        return False, None, "TeX 主文件必须位于编译目录根。"

    from backend.oj_modules.judging.sandbox import run_case_in_container

    stage_timeout = max(10, int(timeout_seconds))
    total_timeout = stage_timeout * 4 + 20
    pdf_name = f"{base_name}.pdf"
    command = [
        "/bin/sh",
        "-c",
        _TEX_COMPILE_SCRIPT,
        "numoj-written-tex",
        f"/sandbox/{source_name}",
        base_name,
        str(stage_timeout),
    ]
    try:
        result = run_case_in_container(
            command,
            run_dir=work_dir_abs,
            timeout_sec=total_timeout,
            document_name=pdf_name,
            document_max_bytes=_WRITTEN_PDF_MAX_BYTES,
        )
    except Exception as exc:
        return False, None, f"TeX 容器执行失败：{exc}"

    logs = "\n".join(
        part
        for part in (
            str(result.stdout or "").strip(),
            str(result.stderr or "").strip(),
        )
        if part
    ).strip()
    if result.returncode == 124:
        return False, None, logs or "TeX 编译超时。"
    if result.returncode != 0:
        return (
            False,
            None,
            logs or f"TeX 编译失败（returncode={result.returncode}）。",
        )
    pdf_content = getattr(result, "artifacts", {}).get(pdf_name)
    if pdf_content is None:
        return False, None, (logs + "\n未找到生成的 PDF 文件。").strip()
    try:
        _publish_compiled_pdf(work_dir_abs, pdf_name, pdf_content)
    except Exception as exc:
        return False, None, (logs + f"\nPDF 发布失败：{exc}").strip()
    pdf_path = os.path.join(work_dir_abs, pdf_name)
    return True, pdf_path, logs


def _build_tex_compile_fail_comment(log_text):
    header = "XeLaTeX 编译失败，按规则记 0 分。"
    log_excerpt = str(log_text or "").strip()[:4000]
    if not log_excerpt:
        return header
    return f"{header}\n\n编译日志节选：\n{log_excerpt}"


def _contains_cjk_characters(text):
    raw = str(text or "")
    for ch in raw:
        codepoint = ord(ch)
        if (
            0x3400 <= codepoint <= 0x4DBF
            or 0x4E00 <= codepoint <= 0x9FFF
            or 0xF900 <= codepoint <= 0xFAFF
            or 0x20000 <= codepoint <= 0x2A6DF
        ):
            return True
    return False


def _tex_has_cjk_setup(tex_text):
    return bool(_TEX_HAS_CJK_SETUP_PATTERN.search(str(tex_text or "")))


def _compile_log_has_missing_cjk_glyph(log_text):
    raw = str(log_text or "")
    if not raw:
        return False
    for matched in _TEX_MISSING_CHAR_PATTERN.findall(raw):
        try:
            codepoint = int(matched, 16)
        except Exception:
            continue
        if (
            0x3400 <= codepoint <= 0x4DBF
            or 0x4E00 <= codepoint <= 0x9FFF
            or 0xF900 <= codepoint <= 0xFAFF
            or 0x20000 <= codepoint <= 0x2A6DF
        ):
            return True
    return False


def _build_xecjk_fallback_tex(tex_text):
    raw = str(tex_text or "")
    if not raw.strip():
        return ""
    if not _contains_cjk_characters(raw):
        return ""
    if _tex_has_cjk_setup(raw):
        return ""

    begin_match = _TEX_BEGIN_DOCUMENT_PATTERN.search(raw)
    if not begin_match:
        return ""

    inject = (
        "\n% Auto-added by NumericalOJ: enable CJK fallback for XeLaTeX rendering\n"
        "\\usepackage{xeCJK}\n"
    )
    return raw[:begin_match.start()] + inject + raw[begin_match.start():]


def _safe_extract_zip(zip_path, target_dir, max_total_uncompressed=200 * 1024 * 1024):
    zip_abs = os.path.abspath(str(zip_path or ""))
    target_abs = os.path.abspath(str(target_dir or ""))
    if not os.path.isfile(zip_abs):
        raise RuntimeError("上传的 ZIP 文件不存在。")

    max_total = int(max_total_uncompressed)
    policy = ZipExtractionPolicy(
        max_members=4096,
        # 旧逻辑只限制总大小；让单文件上限与总上限一致，不额外收紧正常提交。
        max_file_bytes=max_total,
        max_total_bytes=max_total,
        max_compression_ratio=500.0,
        require_non_empty=True,
        cleanup_on_error=True,
    )
    try:
        extract_zip(zip_abs, target_abs, policy=policy)
    except ArchiveExtractionError as exc:
        member = exc.member_name or ""
        messages = {
            'empty_archive': "ZIP 压缩包为空。",
            'too_many_members': "ZIP 文件数量过多，已拒绝处理。",
            'total_too_large': "ZIP 解压后体积过大，已拒绝处理。",
            'file_too_large': "ZIP 中单个文件体积过大，已拒绝处理。",
            'compression_ratio': "ZIP 包含异常压缩比文件，已拒绝处理。",
            'symlink': f"ZIP 包含符号链接：{member}",
            'encrypted_member': f"ZIP 包含加密文件：{member}",
            'duplicate_target': f"ZIP 包含重复路径：{member}",
            'target_conflict': f"ZIP 包含冲突路径：{member}",
            'absolute_path': f"ZIP 包含非法路径：{member}",
            'path_traversal': f"ZIP 包含非法路径：{member}",
            'outside_destination': f"ZIP 包含越界路径：{member}",
            'size_mismatch': f"ZIP 文件大小校验失败：{member}",
        }
        raise RuntimeError(messages.get(exc.reason, "ZIP 解压失败。")) from exc


def _find_main_tex(extracted_dir):
    root = os.path.abspath(str(extracted_dir or ""))
    candidates = []
    for current_root, _, files in os.walk(root):
        for name in files:
            if str(name).lower() == "main.tex":
                abs_path = os.path.abspath(os.path.join(current_root, name))
                depth = abs_path.count(os.sep) - root.count(os.sep)
                candidates.append((depth, abs_path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], len(item[1]), item[1]))
    return candidates[0][1]


def register_written_homework_task(celery_app):
    existing = celery_app.tasks.get(WRITTEN_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        name=WRITTEN_TASK_NAME,
        bind=True,
        time_limit=_WRITTEN_TASK_TIME_LIMIT,
        soft_time_limit=_WRITTEN_TASK_SOFT_TIME_LIMIT,
        autoretry_for=_MYSQL_RETRY_ERRORS,
        retry_backoff=True,
        retry_jitter=True,
        retry_kwargs={'max_retries': 3},
    )
    def transcribe_written_homework_to_latex(self, submission_id):
        """
        书面作业 LaTeX 转写 + AI 评分任务（异步）。
        """
        submission = get_submission_by_id(submission_id)
        if not submission or submission.get('problem_type') != 2:
            return

        lock_client, lock_key, lock_token = acquire_submission_lock(submission_id)
        if lock_client is not None and lock_token is None:
            print(f"[Idempotency] Skip duplicate written grading for submission_id={submission_id}")
            return
        if lock_client is None:
            print(f"[Idempotency] Redis lock unavailable, run written grading without lock for submission_id={submission_id}")

        try:
            submission = get_submission_by_id(submission_id)
        except Exception:
            release_submission_lock(lock_client, lock_key, lock_token)
            raise
        if not submission or submission.get('problem_type') != 2:
            release_submission_lock(lock_client, lock_key, lock_token)
            return
        if submission.get('status') not in ('Pending', 'Waiting', 'Running'):
            print(
                f"[Idempotency] Skip written grading for submission_id={submission_id}, "
                f"status={submission.get('status')}"
            )
            release_submission_lock(lock_client, lock_key, lock_token)
            return
        previous_vote_attempt = get_latest_attempt(submission_id, include_votes=False)
        if (
            submission.get('status') == 'Pending'
            and previous_vote_attempt
            and str(previous_vote_attempt.get('status') or '') == 'needs_manual_review'
        ):
            print(
                f"[Idempotency] Skip written grading awaiting manual review "
                f"for submission_id={submission_id}"
            )
            release_submission_lock(lock_client, lock_key, lock_token)
            return

        upload_folder = ""
        uploaded_filename = f"submission_{submission_id}"
        tex_extract_dir = None
        vote_attempt = None
        try:
            update_submission_status(submission_id, 'Running')

            file_path = get_file_path_for_submission(submission_id)
            if not file_path or not os.path.exists(file_path):
                print(f"[LaTeX OCR] submission={submission_id} 文件不存在: {file_path}")
                update_submission_score_and_comment(submission_id, 0, "提交文件不存在，无法自动评分，按规则记 0 分。")
                update_submission_status(submission_id, 'Unaccepted')
                return

            upload_folder = os.path.dirname(file_path)
            uploaded_filename = os.path.basename(file_path)

            problem = get_problem(submission['problem_id'])
            if not problem:
                raise RuntimeError("题目不存在，无法自动评分。")
            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1
            if written_mode not in (1, 2, 3, 4):
                written_mode = 1

            fake_grade = _fake_written_homework_grade_from_env()
            if fake_grade is not None:
                score, ai_comment = fake_grade
                update_submission_score_and_comment(submission_id, score, ai_comment)
                update_submission_status(submission_id, 'Accepted' if score == 5 else 'Unaccepted')
                refresh_submission_status_snapshot(submission_id)
                print(
                    f"[Written Grade] submission={submission_id} 使用本地假批改结果: "
                    f"score={score}"
                )
                return

            # 任务开始时把本次实际会使用的题目软链接解析成快照；OCR、编译或
            # 图片渲染耗时期间发生的全局配置修改不会影响本次任务。
            ocr_endpoint = None
            if written_mode == 1:
                ocr_endpoint = resolve_problem_llm_endpoint_snapshot(
                    problem,
                    "ocr_endpoint_id",
                )
            elif written_mode == 4:
                # 纯人工批改不应进入本任务；若模式在排队期间被切换，恢复为待
                # 人工处理状态并停止，不能误用 OCR/评分端点。
                update_submission_status(submission_id, 'Pending')
                refresh_submission_status_snapshot(submission_id)
                return

            vote_config, vote_plan = _resolve_written_vote_plan(problem, written_mode)

            def grade_with_votes(evaluator):
                nonlocal vote_attempt
                public_votes = [
                    {key: value for key, value in vote.items() if key != "endpoint"}
                    for vote in vote_plan
                ]
                vote_attempt = create_attempt(
                    submission_id,
                    written_mode,
                    {
                        "judges": vote_config,
                        "grading_prompt": str(problem.get("written_grading_prompt") or ""),
                    },
                    public_votes,
                )
                # create_attempt 将行 ID 写回 public_votes；同步到带端点快照的执行计划。
                for vote, persisted in zip(vote_plan, public_votes):
                    vote["id"] = persisted["id"]
                return _evaluate_written_votes(
                    vote_attempt,
                    vote_plan,
                    evaluator,
                    lambda endpoint, first_round, peers: reconsider_written_homework_with_ai(
                        first_round,
                        peers,
                        endpoint=endpoint,
                        timeout_seconds=_VOTE_CALL_TIMEOUT_SECONDS,
                        repair_invalid_json=False,
                    ),
                )

            if written_mode == 2:
                image_paths = render_pdf_to_images(file_path, upload_folder)
                score, ai_comment = grade_with_votes(
                    lambda endpoint: evaluate_written_homework_with_ai_from_images(
                        problem,
                        image_paths,
                        endpoint=endpoint,
                        timeout_seconds=_VOTE_CALL_TIMEOUT_SECONDS,
                        repair_invalid_json=False,
                        return_round=True,
                    )
                )
            elif written_mode == 3:
                if not str(file_path).lower().endswith('.zip'):
                    score = 0
                    ai_comment = "当前批改模式要求提交 .zip 文件（需包含 main.tex），检测到文件类型不匹配，按规则记 0 分。"
                    update_submission_score_and_comment(submission_id, score, ai_comment)
                    update_submission_status(submission_id, 'Unaccepted')
                    refresh_submission_status_snapshot(submission_id)
                    print(
                        f"[TeX Grade] submission={submission_id} 文件类型错误: "
                        f"path={file_path}, score=0, status=Unaccepted"
                    )
                    return

                try:
                    base_name, _ = os.path.splitext(uploaded_filename)
                    extracted_dir = os.path.join(upload_folder, f"{base_name}_project")
                    tex_extract_dir = extracted_dir
                    if os.path.isdir(extracted_dir):
                        shutil.rmtree(extracted_dir, ignore_errors=True)
                    os.makedirs(extracted_dir, exist_ok=True)

                    _safe_extract_zip(file_path, extracted_dir)
                    main_tex_path = _find_main_tex(extracted_dir)
                    if not main_tex_path:
                        score = 0
                        ai_comment = "ZIP 中未找到 main.tex，按规则记 0 分。"
                        update_submission_score_and_comment(submission_id, score, ai_comment)
                        update_submission_status(submission_id, 'Unaccepted')
                        refresh_submission_status_snapshot(submission_id)
                        print(
                            f"[TeX Grade] submission={submission_id} 缺少 main.tex: "
                            f"score=0, status=Unaccepted"
                        )
                        return

                    tex_text = _read_text_file_safe(main_tex_path)
                    main_tex_dir = os.path.dirname(main_tex_path)
                    compile_ok, compiled_pdf_path, compile_log = _compile_tex_with_xelatex(
                        tex_path=main_tex_path,
                        output_dir=main_tex_dir,
                        timeout_seconds=120,
                    )
                    if compile_ok and _compile_log_has_missing_cjk_glyph(compile_log):
                        fallback_tex_text = _build_xecjk_fallback_tex(tex_text)
                        if fallback_tex_text:
                            fallback_tex_filename = "main__cjk_fallback__.tex"
                            fallback_tex_path = os.path.join(main_tex_dir, fallback_tex_filename)
                            _write_text_file_safe(fallback_tex_path, fallback_tex_text)
                            fallback_ok, fallback_pdf_path, fallback_log = _compile_tex_with_xelatex(
                                tex_path=fallback_tex_path,
                                output_dir=main_tex_dir,
                                timeout_seconds=120,
                            )
                            compile_log = (
                                f"{compile_log}\n\n"
                                "---- xeCJK fallback compile log ----\n"
                                f"{fallback_log}"
                            ).strip()
                            if fallback_ok and fallback_pdf_path and os.path.isfile(fallback_pdf_path):
                                compiled_pdf_path = fallback_pdf_path

                    # 将产物 PDF 复制到提交根目录，供详情页稳定读取。
                    if compile_ok and compiled_pdf_path and os.path.isfile(compiled_pdf_path):
                        canonical_pdf_path = os.path.join(upload_folder, f"{base_name}.pdf")
                        try:
                            shutil.copyfile(compiled_pdf_path, canonical_pdf_path)
                            compiled_pdf_path = canonical_pdf_path
                        except Exception:
                            pass
                    compile_log_path = os.path.join(upload_folder, f"{base_name}_xelatex.log")
                    _write_text_file_safe(compile_log_path, compile_log)

                    if not compile_ok:
                        compile_error_path = os.path.join(upload_folder, f"{base_name}_xelatex_error.txt")
                        _write_text_file_safe(compile_error_path, compile_log)
                        score = 0
                        ai_comment = _build_tex_compile_fail_comment(compile_log)
                        update_submission_score_and_comment(submission_id, score, ai_comment)
                        update_submission_status(submission_id, 'Unaccepted')
                        refresh_submission_status_snapshot(submission_id)
                        print(
                            f"[TeX Grade] submission={submission_id} xelatex 编译失败: "
                            f"score=0, status=Unaccepted, log={compile_error_path}"
                        )
                        return

                    if not tex_text.strip():
                        score = 0
                        ai_comment = "提交的 TeX 文本为空，按规则记 0 分。"
                        update_submission_score_and_comment(submission_id, score, ai_comment)
                        update_submission_status(submission_id, 'Unaccepted')
                        refresh_submission_status_snapshot(submission_id)
                        print(
                            f"[TeX Grade] submission={submission_id} TeX 文本为空: "
                            f"score=0, status=Unaccepted"
                        )
                        return

                    # TeX 成功编译后先推送一次快照，前端可立刻渲染 PDF。
                    refresh_submission_status_snapshot(submission_id)
                    score, ai_comment = grade_with_votes(
                        lambda endpoint: evaluate_written_homework_with_ai(
                            problem,
                            tex_text,
                            endpoint=endpoint,
                            timeout_seconds=_VOTE_CALL_TIMEOUT_SECONDS,
                            repair_invalid_json=False,
                            return_round=True,
                        )
                    )
                except Exception as tex_error:
                    score = 0
                    ai_comment = _build_tex_compile_fail_comment(str(tex_error))
                    update_submission_score_and_comment(submission_id, score, ai_comment)
                    update_submission_status(submission_id, 'Unaccepted')
                    refresh_submission_status_snapshot(submission_id)
                    print(
                        f"[TeX Grade] submission={submission_id} 处理失败并按 0 分处理: "
                        f"{tex_error}"
                    )
                    return
            else:
                def _on_partial_latex(_partial_text, _markdown_path):
                    # 每次 OCR 增量写盘后发布一次快照，驱动前端 SSE 即时刷新。
                    refresh_submission_status_snapshot(submission_id)

                markdown_path = save_transcribed_latex(
                    pdf_path=file_path,
                    upload_folder=upload_folder,
                    uploaded_filename=uploaded_filename,
                    on_partial_latex=_on_partial_latex,
                    endpoint=ocr_endpoint,
                )
                with open(markdown_path, 'r', encoding='utf-8') as f:
                    latex_text = f.read()
                if not latex_text.strip():
                    raise RuntimeError("转写得到的 LaTeX 为空。")
                # OCR 已完成，立即发布一次实时状态，供前端渲染 LaTeX 转写结果。
                refresh_submission_status_snapshot(submission_id)
                score, ai_comment = grade_with_votes(
                    lambda endpoint: evaluate_written_homework_with_ai(
                        problem,
                        latex_text,
                        endpoint=endpoint,
                        timeout_seconds=_VOTE_CALL_TIMEOUT_SECONDS,
                        repair_invalid_json=False,
                        return_round=True,
                    )
                )

            if score is None:
                update_submission_comment(submission_id, ai_comment)
                update_submission_status(submission_id, 'Pending')
                refresh_submission_status_snapshot(submission_id)
                return
            update_submission_score_and_comment(submission_id, score, ai_comment)
            new_status = 'Accepted' if score == 5 else 'Unaccepted'
            update_submission_status(submission_id, new_status)
            if written_mode == 2:
                print(
                    f"[Image Grade] submission={submission_id} 图片直评完成: "
                    f"score={score}, status={new_status}"
                )
            elif written_mode == 3:
                print(
                    f"[TeX Grade] submission={submission_id} TeX 编译+评分完成: "
                    f"score={score}, status={new_status}, pdf={compiled_pdf_path}"
                )
            else:
                print(
                    f"[LaTeX OCR] submission={submission_id} 转写+评分完成: "
                    f"score={score}, status={new_status}, markdown={markdown_path}"
                )
        except Exception as e:
            if isinstance(e, _MYSQL_RETRY_ERRORS):
                raise
            deterministic_input_error = _is_deterministic_written_input_error(e)
            error_filename = f"{os.path.splitext(uploaded_filename)[0]}_latex_error.txt"
            error_path = os.path.join(upload_folder, error_filename)
            try:
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"LaTeX 转写/自动评分失败（submission_id={submission_id}）\n")
                    f.write(str(e))
            except Exception:
                pass
            try:
                if deterministic_input_error:
                    update_submission_score_and_comment(
                        submission_id,
                        0,
                        f"提交文件无法解析或格式不符合要求：{str(e)}",
                    )
                    update_submission_status(submission_id, 'Unaccepted')
                else:
                    if vote_attempt is not None:
                        finish_attempt(vote_attempt["id"], status="needs_manual_review")
                    update_submission_comment(submission_id, f"AI 自动评分失败：{str(e)}")
                    update_submission_status(submission_id, 'Pending')
            except Exception:
                pass
            print(f"[LaTeX OCR] submission={submission_id} 转写或评分失败: {e}")
        finally:
            # TeX 工程只服务于本次编译。PDF、编译日志和错误日志已经复制到提交根目录；
            # 无论成功、输入错误、异常还是上方任意提前 return，都不能永久保留最多
            # 200 MiB 的解压目录。
            if tex_extract_dir:
                shutil.rmtree(tex_extract_dir, ignore_errors=True)
            release_submission_lock(lock_client, lock_key, lock_token)

    return transcribe_written_homework_to_latex

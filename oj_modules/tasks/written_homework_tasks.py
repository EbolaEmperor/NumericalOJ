#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shutil
import subprocess
import zipfile

import pymysql

from config import AI_TUTOR_MODEL, EVALUATE_SUBMISSION_LOCK_TTL_SECONDS, QWEN_TEXT_MODEL
from oj_modules.ai_utils import (
    evaluate_written_homework_with_ai,
    evaluate_written_homework_with_ai_from_images,
    render_pdf_to_images,
    save_transcribed_latex,
)
from oj_modules.db_services import (
    get_problem,
    get_submission_by_id,
    refresh_submission_status_snapshot,
    update_submission_status,
)
from oj_modules.grading_services import (
    get_file_path_for_submission,
    update_submission_comment,
    update_submission_score_and_comment,
)


WRITTEN_TASK_NAME = "oj.transcribe_written_homework_to_latex"
_DEFAULT_WRITTEN_GRADING_MODEL_SPEC = (
    f"{str(QWEN_TEXT_MODEL or '').strip().lower()}-thinking"
    if str(QWEN_TEXT_MODEL or "").strip()
    else f"{str(AI_TUTOR_MODEL or '').strip().lower()}-thinking"
)
_WRITTEN_TASK_TIME_LIMIT = max(60, int(EVALUATE_SUBMISSION_LOCK_TTL_SECONDS))
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


def _run_cmd(cmd, cwd, timeout_seconds):
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=max(10, int(timeout_seconds)),
            check=False,
        )
    except FileNotFoundError:
        return False, f"命令不存在：{cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"命令超时：{' '.join(cmd)}"
    except Exception as e:
        return False, f"命令执行失败（{' '.join(cmd)}）：{e}"

    stdout = str(proc.stdout or "").strip()
    stderr = str(proc.stderr or "").strip()
    log = "\n".join(part for part in [stdout, stderr] if part).strip()
    if proc.returncode != 0:
        if not log:
            log = f"命令失败（returncode={proc.returncode}）：{' '.join(cmd)}"
        return False, log
    return True, log


def _is_nonfatal_bibtex_failure(log_text):
    raw = str(log_text or "")
    if not raw:
        return False
    lowered = raw.lower()
    return (
        ("no \\citation commands" in lowered and "no \\bibdata command" in lowered)
        or "i found no \\citation commands" in lowered
        or "i found no \\bibdata command" in lowered
    )


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

    logs = []
    xelatex_cmd = [
        "xelatex",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-file-line-error",
        source_name,
    ]

    ok1, log1 = _run_cmd(xelatex_cmd, cwd=work_dir_abs, timeout_seconds=timeout_seconds)
    logs.append(f"[xelatex #1]\n{log1}")
    if not ok1:
        return False, None, "\n\n".join(logs)

    bibtex_cmd = ["bibtex", base_name]
    bib_ok, bib_log = _run_cmd(bibtex_cmd, cwd=work_dir_abs, timeout_seconds=timeout_seconds)
    logs.append(f"[bibtex]\n{bib_log}")
    if not bib_ok and not _is_nonfatal_bibtex_failure(bib_log):
        return False, None, "\n\n".join(logs)

    ok2, log2 = _run_cmd(xelatex_cmd, cwd=work_dir_abs, timeout_seconds=timeout_seconds)
    logs.append(f"[xelatex #2]\n{log2}")
    if not ok2:
        return False, None, "\n\n".join(logs)

    ok3, log3 = _run_cmd(xelatex_cmd, cwd=work_dir_abs, timeout_seconds=timeout_seconds)
    logs.append(f"[xelatex #3]\n{log3}")
    if not ok3:
        return False, None, "\n\n".join(logs)

    pdf_path = os.path.join(work_dir_abs, f"{base_name}.pdf")
    if not os.path.isfile(pdf_path):
        logs.append("未找到生成的 PDF 文件。")
        return False, None, "\n\n".join(logs)
    return True, pdf_path, "\n\n".join(logs).strip()


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

    os.makedirs(target_abs, exist_ok=True)
    total_size = 0
    with zipfile.ZipFile(zip_abs, 'r') as zf:
        infos = zf.infolist()
        if not infos:
            raise RuntimeError("ZIP 压缩包为空。")
        for info in infos:
            raw_name = str(info.filename or "")
            if not raw_name:
                continue
            normalized = raw_name.replace("\\", "/").lstrip("/")
            if normalized.startswith("../") or "/../" in normalized or normalized == "..":
                raise RuntimeError(f"ZIP 包含非法路径：{raw_name}")
            dest_path = os.path.abspath(os.path.join(target_abs, normalized))
            if not (dest_path == target_abs or dest_path.startswith(target_abs + os.sep)):
                raise RuntimeError(f"ZIP 包含越界路径：{raw_name}")

            if info.is_dir() or normalized.endswith("/"):
                os.makedirs(dest_path, exist_ok=True)
                continue

            total_size += max(0, int(info.file_size or 0))
            if total_size > int(max_total_uncompressed):
                raise RuntimeError("ZIP 解压后体积过大，已拒绝处理。")

            parent = os.path.dirname(dest_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with zf.open(info, 'r') as src, open(dest_path, 'wb') as dst:
                shutil.copyfileobj(src, dst)


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

        update_submission_status(submission_id, 'Running')

        file_path = get_file_path_for_submission(submission_id)
        if not file_path or not os.path.exists(file_path):
            print(f"[LaTeX OCR] submission={submission_id} 文件不存在: {file_path}")
            update_submission_score_and_comment(submission_id, 0, "提交文件不存在，无法自动评分，按规则记 0 分。")
            update_submission_status(submission_id, 'Unaccepted')
            return

        upload_folder = os.path.dirname(file_path)
        uploaded_filename = os.path.basename(file_path)

        try:
            problem = get_problem(submission['problem_id'])
            if not problem:
                raise RuntimeError("题目不存在，无法自动评分。")
            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1
            written_model = str(problem.get('written_grading_model') or _DEFAULT_WRITTEN_GRADING_MODEL_SPEC).strip().lower()

            if written_mode == 2:
                image_paths = render_pdf_to_images(file_path, upload_folder)
                score, ai_comment = evaluate_written_homework_with_ai_from_images(
                    problem,
                    image_paths,
                    grading_model_spec=written_model,
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
                    score, ai_comment = evaluate_written_homework_with_ai(
                        problem,
                        tex_text,
                        grading_model_spec=written_model,
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
                )
                with open(markdown_path, 'r', encoding='utf-8') as f:
                    latex_text = f.read()
                if not latex_text.strip():
                    raise RuntimeError("转写得到的 LaTeX 为空。")
                # OCR 已完成，立即发布一次实时状态，供前端渲染 LaTeX 转写结果。
                refresh_submission_status_snapshot(submission_id)
                score, ai_comment = evaluate_written_homework_with_ai(
                    problem,
                    latex_text,
                    grading_model_spec=written_model,
                )

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
                    update_submission_comment(submission_id, f"AI 自动评分失败：{str(e)}")
                    update_submission_status(submission_id, 'Pending')
            except Exception:
                pass
            print(f"[LaTeX OCR] submission={submission_id} 转写或评分失败: {e}")

    return transcribe_written_homework_to_latex

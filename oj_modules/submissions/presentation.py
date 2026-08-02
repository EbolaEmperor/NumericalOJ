"""普通提交页面与 JSON API 共用的无请求状态展示 helper。"""

import html
import os
import re

import markdown


_EXACT_DOUBLE_BACKSLASH_PATTERN = re.compile(r"(?<!\\)\\\\(?!\\)")


def summarize_panel_test_points(raw_points):
    """将测试点收敛为详情面板所需的有界摘要。"""
    points = []
    for fallback_index, raw_point in enumerate(raw_points or (), start=1):
        if not isinstance(raw_point, dict):
            continue
        try:
            test_index = int(
                raw_point.get("test_index")
                or raw_point.get("index")
                or fallback_index
            )
        except (TypeError, ValueError):
            test_index = fallback_index
        points.append({
            "test_index": test_index,
            "status": str(raw_point.get("status") or "Unknown"),
            "time": raw_point.get("time"),
            "stderr": str(raw_point.get("stderr") or "")[:600],
            "stdout": str(raw_point.get("stdout") or "")[:600],
            "has_output_image": bool(raw_point.get("has_output_image")),
        })
    return points


def _read_text_file_safe(path, max_chars=200000):
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as file_obj:
            return (file_obj.read() or "")[:max_chars]
    except Exception:
        return ""


def _normalize_transcribed_backslashes_for_mathjax(text):
    """只把恰好两个连续反斜杠替换为四个。"""
    raw = str(text or "")
    if not raw:
        return ""
    return _EXACT_DOUBLE_BACKSLASH_PATTERN.sub(r"\\\\\\\\", raw)


def render_written_markdown_to_html(markdown_text):
    raw_text = str(markdown_text or "")
    if not raw_text.strip():
        return ""

    escaped_text = html.escape(raw_text, quote=False)
    try:
        rendered = markdown.markdown(
            escaped_text,
            extensions=["extra", "fenced_code", "tables", "sane_lists"],
        )
    except Exception:
        return escaped_text.replace("\n", "<br>")

    return re.sub(
        r"(?i)\s(href|src)\s*=\s*(['\"])\s*(javascript:|vbscript:|data:)",
        r" \1=\2#",
        rendered,
    )


def load_written_submission_latex_and_error(submission):
    if not submission or int(submission.get("problem_type") or 0) != 2:
        return "", ""

    submission_id = submission.get("id")
    if not submission_id:
        return "", ""

    upload_dir = os.path.join("uploads", str(submission_id))
    if not os.path.isdir(upload_dir):
        return "", ""

    test_points = submission.get("test_points")
    source_filename = ""
    if isinstance(test_points, list) and test_points:
        source_filename = os.path.basename(str(test_points[0] or "").strip())

    latex_candidates = []
    error_candidates = []
    if source_filename:
        base_name, _ = os.path.splitext(source_filename)
        if base_name:
            latex_candidates.append(os.path.join(upload_dir, f"{base_name}.md"))
            latex_candidates.append(os.path.join(upload_dir, f"{base_name}.tex"))
            error_candidates.append(
                os.path.join(upload_dir, f"{base_name}_latex_error.txt")
            )

    try:
        for name in sorted(os.listdir(upload_dir)):
            lower = name.lower()
            absolute_path = os.path.join(upload_dir, name)
            if lower.endswith(".md") or lower.endswith(".tex"):
                latex_candidates.append(absolute_path)
            elif lower.endswith("_latex_error.txt"):
                error_candidates.append(absolute_path)
    except Exception:
        pass

    latex_text = ""
    seen_latex = set()
    for path in latex_candidates:
        if path in seen_latex:
            continue
        seen_latex.add(path)
        latex_text = _read_text_file_safe(path)
        if latex_text.strip():
            break
    latex_text = _normalize_transcribed_backslashes_for_mathjax(latex_text)

    error_text = ""
    seen_errors = set()
    for path in error_candidates:
        if path in seen_errors:
            continue
        seen_errors.add(path)
        error_text = _read_text_file_safe(path, max_chars=12000)
        if error_text.strip():
            break

    return latex_text, error_text


__all__ = [
    "load_written_submission_latex_and_error",
    "render_written_markdown_to_html",
    "summarize_panel_test_points",
]

"""PDF 渲染、图片编码与书面作业转写。"""

import base64
import mimetypes
import os
import tempfile
import time

from backend.oj_modules.config import (
    LATEX_OCR_MAX_IMAGES_PER_REQUEST,
    LATEX_OCR_STREAM_EMIT_INTERVAL,
    LATEX_OCR_STREAM_EMIT_MIN_DELTA,
)
from backend.oj_modules.ai.client import (
    _call_llm_vision,
    resolve_llm_endpoint_snapshot,
)
from backend.oj_modules.ai.parsing import _strip_markdown_code_fence_markers
from backend.oj_modules.judging import core as judger_core


def render_pdf_to_images(pdf_path, output_dir):
    try:
        import pypdfium2 as pdfium
    except ImportError as e:
        raise RuntimeError("缺少 pypdfium2 依赖，无法将 PDF 渲染为图片。") from e

    pdf = pdfium.PdfDocument(pdf_path)
    image_paths = []
    try:
        if len(pdf) == 0:
            raise RuntimeError("PDF 文件为空，无法转写。")
        prefix = os.path.splitext(os.path.basename(pdf_path))[0]
        for page_idx in range(len(pdf)):
            page = pdf[page_idx]
            try:
                bitmap = page.render(scale=2.0)
                image = bitmap.to_pil()
                image_filename = f"{prefix}_page_{page_idx + 1:03d}.png"
                image_path = os.path.join(output_dir, image_filename)
                image.save(image_path, format='PNG')
                image_paths.append(image_path)
            finally:
                page.close()
    finally:
        pdf.close()
    return image_paths


# 通用视觉端点可稳定接受的图片 MIME；其余格式（bmp/gif/tiff 等）
# 在发送前就地无损转成 PNG，避免模型拒收导致图片题 AI 批改失败。
_VISION_SAFE_IMAGE_MIME = {'image/png', 'image/jpeg', 'image/webp'}


def _build_image_data_url(image_path):
    mime_type, _ = mimetypes.guess_type(image_path)
    if not mime_type:
        mime_type = 'image/png'
    image_bytes = judger_core.read_safe_regular_artifact(image_path)

    # 非视觉模型友好的格式（典型如 BMP）转成 PNG 再发；任何失败都回退到原始字节，
    # 绝不让转码本身打断批改流程。
    if mime_type not in _VISION_SAFE_IMAGE_MIME:
        try:
            import io
            from PIL import Image
            with Image.open(io.BytesIO(image_bytes)) as im:
                converted = im.convert('RGBA') if im.mode in ('P', 'LA') else im.convert('RGB')
                buf = io.BytesIO()
                converted.save(buf, format='PNG')
            encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{encoded}"
        except Exception as e:
            print(f"[Image Analysis] {mime_type} 转 PNG 失败，回退原始字节: {e}")

    encoded = base64.b64encode(image_bytes).decode('utf-8')
    return f"data:{mime_type};base64,{encoded}"


def _split_image_batches(image_data_urls, max_images_per_request=None):
    if max_images_per_request is None:
        try:
            max_images_per_request = int(LATEX_OCR_MAX_IMAGES_PER_REQUEST)
        except Exception:
            max_images_per_request = 1
    if max_images_per_request < 1:
        max_images_per_request = 1
    return [
        image_data_urls[i:i + max_images_per_request]
        for i in range(0, len(image_data_urls), max_images_per_request)
    ]


def _transcribe_image_batch(image_urls, prompt_text, endpoint, on_delta=None):
    latex_text = _strip_markdown_code_fence_markers(
        _call_llm_vision(
            prompt_text,
            image_urls,
            endpoint,
            timeout=300,
            on_delta=on_delta,
        )
    )
    if not latex_text:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    return latex_text


def transcribe_images_to_latex(
    image_paths,
    on_partial_text=None,
    *,
    endpoint=None,
    endpoint_id=None,
):
    if not image_paths:
        raise RuntimeError("未生成可用于识别的图片。")
    use_endpoint = resolve_llm_endpoint_snapshot(
        endpoint,
        endpoint_id=endpoint_id,
        allowed_categories={"omni", "vision"},
        purpose="书面作业 OCR",
    )
    prompt = (
        "请将这份书面作业完整转写为 Markdown 内嵌 LaTeX 的格式。"
        "要求："
        "1. 保留原题号、段落和公式结构；"
        "2. 无法识别的内容用 {[无法辨认]} 标注；"
        "3. 行内公式用 $...$ 包裹，行间公式用 $$(换行)...(换行)$$ 包裹；"
        "4. 不要输出任何解释，直接输出 Markdown 源码。"
    )
    image_data_urls = [_build_image_data_url(path) for path in image_paths]
    try:
        max_images_per_request = int(LATEX_OCR_MAX_IMAGES_PER_REQUEST)
    except Exception:
        max_images_per_request = 1
    image_batches = _split_image_batches(image_data_urls, max_images_per_request=max_images_per_request)

    transcribed_parts = []
    current_raw_part = []

    def _emit_partial_preview():
        if not callable(on_partial_text):
            return
        preview_parts = list(transcribed_parts)
        if current_raw_part:
            preview_current = _strip_markdown_code_fence_markers(''.join(current_raw_part))
            if preview_current:
                preview_parts.append(preview_current.strip())
        preview_text = "\n\n".join([p for p in preview_parts if str(p or "").strip()]).strip()
        try:
            on_partial_text(preview_text)
        except Exception:
            pass

    total = len(image_batches)
    for idx, batch in enumerate(image_batches, start=1):
        current_raw_part = []
        chunk_prompt = prompt
        if total > 1:
            chunk_prompt += (
                f" 这是第 {idx}/{total} 组页面。"
                "请只输出这一组页面对应的 LaTeX 片段，不要重复其他组内容。"
            )

        def _on_delta(delta_text):
            if not delta_text:
                return
            current_raw_part.append(delta_text)
            _emit_partial_preview()

        part = _transcribe_image_batch(
            batch,
            chunk_prompt,
            use_endpoint,
            on_delta=_on_delta,
        )
        if part:
            transcribed_parts.append(part.strip())
            current_raw_part = []
            _emit_partial_preview()

    if not transcribed_parts:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    return "\n\n".join(transcribed_parts).strip()

def _atomic_write_text(path, content):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_latex_", suffix=".md", dir=parent, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(str(content or ""))
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def save_transcribed_latex(
    pdf_path,
    upload_folder,
    uploaded_filename,
    on_partial_latex=None,
    *,
    endpoint=None,
    endpoint_id=None,
):
    image_paths = render_pdf_to_images(pdf_path, upload_folder)
    markdown_filename = f"{os.path.splitext(uploaded_filename)[0]}.md"
    markdown_path = os.path.join(upload_folder, markdown_filename)
    _atomic_write_text(markdown_path, "")

    try:
        stream_emit_interval = max(0.1, float(LATEX_OCR_STREAM_EMIT_INTERVAL))
    except Exception:
        stream_emit_interval = 0.1
    try:
        stream_emit_min_delta = max(1, int(LATEX_OCR_STREAM_EMIT_MIN_DELTA))
    except Exception:
        stream_emit_min_delta = 1

    last_emit_ts = 0.0
    last_emitted_text = ""

    def _on_partial_text(text):
        nonlocal last_emit_ts, last_emitted_text
        partial = str(text or "")
        if partial == last_emitted_text:
            return
        now = time.monotonic()
        if (
            last_emitted_text
            and (now - last_emit_ts) < stream_emit_interval
            and abs(len(partial) - len(last_emitted_text)) < stream_emit_min_delta
        ):
            return
        _atomic_write_text(markdown_path, partial)
        last_emit_ts = now
        last_emitted_text = partial
        if callable(on_partial_latex):
            try:
                on_partial_latex(partial, markdown_path)
            except Exception:
                pass

    latex_text = transcribe_images_to_latex(
        image_paths,
        on_partial_text=_on_partial_text,
        endpoint=endpoint,
        endpoint_id=endpoint_id,
    )
    _atomic_write_text(markdown_path, latex_text)
    if callable(on_partial_latex):
        try:
            on_partial_latex(latex_text, markdown_path)
        except Exception:
            pass
    return markdown_path

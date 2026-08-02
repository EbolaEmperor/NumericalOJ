"""题目管理页与 JSON API 共用的评分模型选项。"""

from config import AI_TUTOR_MODEL, QWEN_CODER_MODEL, QWEN_OMNI_MODEL, QWEN_TEXT_MODEL
from oj_modules.ai.grading import DEFAULT_WRITTEN_GRADING_RULES_TEXT


DEFAULT_WRITTEN_GRADING_MODEL = (
    f"{str(QWEN_TEXT_MODEL or '').strip().lower()}-thinking"
    if str(QWEN_TEXT_MODEL or "").strip()
    else f"{str(AI_TUTOR_MODEL or '').strip().lower()}-thinking"
)
WRITTEN_GRADING_MODEL_OPTIONS = [
    item
    for item in dict.fromkeys([
        (
            f"{str(QWEN_TEXT_MODEL or '').strip().lower()}-thinking"
            if str(QWEN_TEXT_MODEL or "").strip()
            else ""
        ),
        str(QWEN_TEXT_MODEL or "").strip().lower(),
        (
            f"{str(AI_TUTOR_MODEL or '').strip().lower()}-thinking"
            if str(AI_TUTOR_MODEL or "").strip()
            else ""
        ),
        str(AI_TUTOR_MODEL or "").strip().lower(),
        "mimo",
    ])
    if item
]
if (
    DEFAULT_WRITTEN_GRADING_MODEL
    and DEFAULT_WRITTEN_GRADING_MODEL not in WRITTEN_GRADING_MODEL_OPTIONS
):
    WRITTEN_GRADING_MODEL_OPTIONS.insert(0, DEFAULT_WRITTEN_GRADING_MODEL)

DEFAULT_WRITTEN_GRADING_PROMPT = DEFAULT_WRITTEN_GRADING_RULES_TEXT
DEFAULT_PROGRAMMING_GRADING_MODEL = (
    str(QWEN_OMNI_MODEL or "").strip().lower()
    or str(QWEN_TEXT_MODEL or "").strip().lower()
)
PROGRAMMING_GRADING_MODEL_OPTIONS = [
    item
    for item in dict.fromkeys([
        str(QWEN_CODER_MODEL or "").strip().lower(),
        str(QWEN_OMNI_MODEL or "").strip().lower(),
        str(QWEN_TEXT_MODEL or "").strip().lower(),
    ])
    if item
]
if (
    DEFAULT_PROGRAMMING_GRADING_MODEL
    and DEFAULT_PROGRAMMING_GRADING_MODEL not in PROGRAMMING_GRADING_MODEL_OPTIONS
):
    PROGRAMMING_GRADING_MODEL_OPTIONS.insert(0, DEFAULT_PROGRAMMING_GRADING_MODEL)


__all__ = [
    "DEFAULT_PROGRAMMING_GRADING_MODEL",
    "DEFAULT_WRITTEN_GRADING_MODEL",
    "DEFAULT_WRITTEN_GRADING_PROMPT",
    "PROGRAMMING_GRADING_MODEL_OPTIONS",
    "WRITTEN_GRADING_MODEL_OPTIONS",
]

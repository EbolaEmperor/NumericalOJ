"""模型文本、JSON 与 LaTeX 转义的纯解析 helper。"""

import json
import re


def _strip_markdown_code_fence_markers(text):
    raw = str(text or "")
    if not raw.strip():
        return ""
    cleaned_lines = []
    for line in raw.splitlines():
        if re.match(r"^\s*```[^\n`]*\s*$", line):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()

_CONTROL_ESCAPE_TO_LATEX_PREFIX = {
    "\n": "n",
    "\t": "t",
    "\r": "r",
    "\x08": "b",
    "\x0c": "f",
}
_LATEX_ESCAPE_ARTIFACT_PATTERN = re.compile(r"([\n\r\t\x08\x0c])\s*([A-Za-z]{2,})")
_COMMON_LATEX_COMMANDS = {
    "neq", "ne", "leq", "geq", "approx", "sim", "equiv",
    "in", "notin", "subset", "subseteq", "supset", "supseteq",
    "cup", "cap", "to", "rightarrow", "leftarrow", "leftrightarrow",
    "mapsto", "times", "cdot", "pm", "mp", "div",
    "frac", "sqrt", "sum", "prod", "int", "lim",
    "alpha", "beta", "gamma", "delta", "epsilon", "varepsilon",
    "theta", "lambda", "mu", "pi", "sigma", "omega",
    "infty", "forall", "exists", "nabla",
    "begin", "end", "left", "right",
    "mathbb", "mathcal", "mathbf", "mathrm", "text", "operatorname",
}
_COMMON_LATEX_PREFIXES = (
    "math", "text", "begin", "end", "left", "right", "operatorname",
    "mathbf", "mathrm", "mathbb", "mathcal", "underline", "overline",
)


def _looks_like_latex_command(command):
    cmd = str(command or "").strip().lower()
    if len(cmd) < 2:
        return False
    if cmd in _COMMON_LATEX_COMMANDS:
        return True
    return any(cmd.startswith(prefix) and len(cmd) > len(prefix) for prefix in _COMMON_LATEX_PREFIXES)


def _repair_latex_escape_artifacts(text):
    raw = str(text or "")
    if not raw:
        return ""

    def _replace_match(match):
        ctrl = match.group(1)
        tail = match.group(2) or ""
        prefix = _CONTROL_ESCAPE_TO_LATEX_PREFIX.get(ctrl)
        if not prefix:
            return match.group(0)
        command = f"{prefix}{tail}"
        if not _looks_like_latex_command(command):
            return match.group(0)
        return f"\\{command}"

    return _LATEX_ESCAPE_ARTIFACT_PATTERN.sub(_replace_match, raw)

def _extract_first_json_object(text):
    if not text:
        return None

    candidates = [text.strip()]
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

        for idx, ch in enumerate(candidate):
            if ch != '{':
                continue
            try:
                obj, _ = decoder.raw_decode(candidate[idx:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return None


def _extract_first_json_object_relaxed(text):
    strict_obj = _extract_first_json_object(text)
    if strict_obj is not None:
        return strict_obj

    if not text:
        return None

    candidates = [text.strip()]
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    for candidate in candidates:
        start = candidate.find('{')
        end = candidate.rfind('}')
        if start < 0 or end <= start:
            continue
        body = candidate[start:end + 1]
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', body)
        try:
            obj = json.loads(repaired)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue

    return None

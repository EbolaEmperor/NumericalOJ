"""FaithSieve 工件的路径、结构和文件边界。"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class FaithSieveProtocolError(ValueError):
    """角色回传不能安全地作为下一阶段输入。"""


class FaithSieveJSONSyntaxError(FaithSieveProtocolError):
    """完整模型回传的 JSON 语法错误；不包括字段或数学语义问题。"""


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaithSieveProtocolError("FaithSieve 角色回传 JSON 有重复字段")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise FaithSieveProtocolError("FaithSieve 角色回传含非标准 JSON 常量")


def parse_json_response(value, *, strict_constants=False):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise FaithSieveProtocolError("FaithSieve 角色回传格式无效或过大")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise FaithSieveProtocolError("FaithSieve 角色回传不是有效 Unicode") from None
    if size > MAX_RESPONSE_BYTES:
        raise FaithSieveProtocolError("FaithSieve 角色回传格式无效或过大")
    text = value.strip()
    if text.startswith("```json\n") and text.endswith("\n```"):
        text = text[8:-4]
    elif text.startswith("```\n") and text.endswith("\n```"):
        text = text[4:-4]
    try:
        payload = json.loads(text, object_pairs_hook=_unique_json_object,
                             parse_constant=_reject_json_constant if strict_constants else None)
    except json.JSONDecodeError as exc:
        raise FaithSieveJSONSyntaxError(
            f"FaithSieve 角色未返回可解析 JSON（第 {exc.lineno} 行、第 {exc.colno} 列：{exc.msg}）"
        ) from None
    except FaithSieveProtocolError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise FaithSieveProtocolError("FaithSieve 角色未返回可解析 JSON") from None
    if not isinstance(payload, dict):
        raise FaithSieveProtocolError("FaithSieve 角色回传必须是 JSON 对象")
    return payload


def artifact_path(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise FaithSieveProtocolError("FaithSieve 工件路径无效")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", ".."} for part in value.split("/")):
        raise FaithSieveProtocolError("FaithSieve 工件路径越界")
    if value not in {"problem.md", "faithsieve_result.json"} and not value.startswith(
        "faithsieve-work/"
    ):
        raise FaithSieveProtocolError("FaithSieve 工件路径越界")
    if path.suffix not in {".md", ".txt", ".lean", ".json"}:
        raise FaithSieveProtocolError("FaithSieve 工件类型无效")
    return value


class ArtifactStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.visible_paths = None

    def begin_replay(self, paths):
        """重入只暴露按当前调用顺序恢复的工件，隔离磁盘上的后续旧输出。"""
        self.visible_paths = set(paths)

    def path(self, relative):
        path = self.root / artifact_path(relative)
        if not path.resolve().is_relative_to(self.root):
            raise FaithSieveProtocolError("FaithSieve 工件路径越界")
        return path

    def write(self, relative, content):
        if not isinstance(content, str):
            raise FaithSieveProtocolError("FaithSieve 文本工件必须是字符串")
        if len(content.encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise FaithSieveProtocolError("FaithSieve 单个工件过大")
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if self.visible_paths is not None:
            self.visible_paths.add(relative)

    def write_json(self, relative, payload):
        self.write(relative, json.dumps(payload, ensure_ascii=False, indent=2))

    def read(self, relative):
        path = self.path(relative)
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise FaithSieveProtocolError("FaithSieve 输入工件过大")
        return path.read_text(encoding="utf-8")

    def read_json(self, relative):
        return parse_json_response(self.read(relative))

    def remove(self, relative):
        self.path(relative).unlink(missing_ok=True)
        if self.visible_paths is not None:
            self.visible_paths.discard(relative)

    def bundle(self, paths=(), prefixes=()):
        selected = set(paths)
        for prefix in prefixes:
            root = self.path(prefix + "/placeholder.md").parent
            if root.exists():
                for path in root.rglob("*"):
                    if path.is_file() and path.suffix in {".md", ".txt", ".lean", ".json"}:
                        selected.add(path.relative_to(self.root).as_posix())
        return {
            path: self.read(path) for path in sorted(selected)
            if self.path(path).is_file() and (self.visible_paths is None or path in self.visible_paths)
        }


def _structured_artifact_text(value):
    """边编码边限流，避免短引用展开后一次性分配巨大的 JSON 文本。"""
    chunks, size = [], 0
    try:
        for chunk in json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False).iterencode(value):
            size += len(chunk.encode("utf-8"))
            if size > MAX_ARTIFACT_BYTES:
                raise FaithSieveProtocolError("FaithSieve 单个工件过大")
            chunks.append(chunk)
    except FaithSieveProtocolError:
        raise
    except UnicodeError:
        raise FaithSieveProtocolError("FaithSieve 工件文本不是有效 Unicode") from None
    except (ValueError, TypeError, RecursionError):
        raise FaithSieveProtocolError("FaithSieve 结构化工件不是有效 JSON") from None
    return "".join(chunks)


def validate_role_response(payload, *, fields, statuses, expected_artifact, allowed_outputs, structured_outputs=(), structured_normalizers=None):
    """先完整校验，再允许一次性落盘，避免污染已有输入。"""
    payload = parse_json_response(payload)
    if "result" not in payload or "artifacts" not in payload:
        raise FaithSieveProtocolError(
            "FaithSieve 角色必须回传包含 result 和 artifacts 的完整外层对象；"
            "原角色的 status/artifact/report 等字段只能放在 result 内，"
            "artifacts 必须包含指定路径的完整工件正文，不能只返回内层结果"
        )
    if set(payload) - {"result", "artifacts", "control", "execution"}:
        raise FaithSieveProtocolError("FaithSieve 角色回传有额外字段")
    result = payload.get("result")
    if not isinstance(result, dict) or set(result) != set(fields):
        raise FaithSieveProtocolError("FaithSieve 角色状态字段不符合原提示词协议")
    if result.get("status") not in statuses:
        raise FaithSieveProtocolError("FaithSieve 角色状态无效")
    if result.get("artifact") != expected_artifact:
        raise FaithSieveProtocolError("FaithSieve 角色工件与指定路径不符")
    if not isinstance(result.get("report"), str) or not result["report"].strip():
        raise FaithSieveProtocolError("FaithSieve 角色报告不能为空")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict) or expected_artifact not in artifacts:
        raise FaithSieveProtocolError("FaithSieve 角色未回传指定工件")
    normalized = {}
    for path, text in artifacts.items():
        artifact_path(path)
        if path in structured_outputs and isinstance(text, dict):
            normalizer = (structured_normalizers or {}).get(path)
            if normalizer is not None:
                text = normalizer(text)
            text = _structured_artifact_text(text)
        if not allowed_outputs(path) or not isinstance(text, str):
            raise FaithSieveProtocolError(
                "FaithSieve 角色试图修改非输出工件；result JSON 只能在外层 result 返回，"
                "由宿主生成结果文件，不得再次放进 artifacts"
            )
        try:
            size = len(text.encode("utf-8"))
        except UnicodeError:
            raise FaithSieveProtocolError("FaithSieve 工件文本不是有效 Unicode") from None
        if size > MAX_ARTIFACT_BYTES:
            raise FaithSieveProtocolError("FaithSieve 单个工件过大")
        normalized[path] = text
    control = payload.get("control", {})
    if not isinstance(control, dict):
        raise FaithSieveProtocolError("FaithSieve 流程数据必须是 JSON 对象")
    return result, normalized, control

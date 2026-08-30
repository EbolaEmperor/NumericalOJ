"""Tree-sitter structural highlighting for MATLAB-compatible Octave code."""

from __future__ import annotations

import hashlib
import threading
from typing import Any

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_matlab

from backend.oj_modules.editor.language_server import (
    LANGUAGE_SERVICE_POOL_SIZE,
    LANGUAGE_SOURCE_MAX_BYTES,
    LanguageServiceProtocolError,
    SemanticLanguageServicePool,
)


_TOKEN_TYPES = [
    "class",
    "parameter",
    "variable",
    "property",
    "enumMember",
    "function",
    "method",
]
_TOKEN_MODIFIERS = ["declaration"]
_TYPE_INDEX = {name: index for index, name in enumerate(_TOKEN_TYPES)}
_DECLARATION = 1
_QUERY_SOURCE = r"""
(class_definition name: (identifier) @class.declaration)
(function_definition name: (identifier) @function.declaration)
(function_signature name: (identifier) @function.declaration)
(function_arguments (identifier) @parameter.declaration)
(lambda (arguments (identifier) @parameter.declaration))
(field_expression field: (function_call name: (identifier) @method))
(function_call name: (identifier) @function)
(handle_operator (identifier) @function)
(validation_functions (identifier) @function)
(command (command_name) @function)
(property name: (identifier) @property.declaration)
(field_expression field: (identifier) @property)
(superclass "." (identifier) @property)
(property_name "." (identifier) @property)
(enum . (identifier) @enumMember.declaration)
(assignment left: (identifier) @variable.declaration)
(iterator . (identifier) @variable.declaration)
(global_operator (identifier) @variable.declaration)
(persistent_operator (identifier) @variable.declaration)
(catch_clause (identifier) @variable.declaration)
"""
_CAPTURE_STYLES = {
    "class.declaration": ("class", _DECLARATION, 30),
    "function.declaration": ("function", _DECLARATION, 30),
    "parameter.declaration": ("parameter", _DECLARATION, 30),
    "method": ("method", 0, 40),
    "function": ("function", 0, 20),
    "property.declaration": ("property", _DECLARATION, 30),
    "property": ("property", 0, 20),
    "enumMember.declaration": ("enumMember", _DECLARATION, 30),
    "variable.declaration": ("variable", _DECLARATION, 30),
}


def _utf16_columns_by_byte(value: str) -> dict[int, int]:
    """Map UTF-8 character boundaries to Monaco's UTF-16 columns in O(n)."""
    columns = {0: 0}
    byte_offset = 0
    utf16_column = 0
    for character in value:
        byte_offset += len(character.encode("utf-8"))
        utf16_column += len(character.encode("utf-16-le")) // 2
        columns[byte_offset] = utf16_column
    return columns


class OctaveTreeSitterService:
    """Return LSP-shaped structural tokens without executing Octave code."""

    service_name = "Tree-sitter Octave"

    def __init__(self) -> None:
        self._language = Language(tree_sitter_matlab.language())
        self._parser = Parser(self._language)
        self._query = Query(self._language, _QUERY_SOURCE)
        self._lock = threading.Lock()

    def legend(self) -> dict[str, list[str]]:
        return {
            "tokenTypes": list(_TOKEN_TYPES),
            "tokenModifiers": list(_TOKEN_MODIFIERS),
        }

    def semantic_tokens(self, document_key: str, source: str) -> dict[str, Any]:
        del document_key
        encoded = source.encode("utf-8")
        if len(encoded) > LANGUAGE_SOURCE_MAX_BYTES:
            raise ValueError("代码超过实时解析大小限制")
        try:
            with self._lock:
                tree = self._parser.parse(encoded)
                captures = QueryCursor(self._query).captures(tree.root_node)
        except (RuntimeError, ValueError) as exc:
            raise LanguageServiceProtocolError(
                self.service_name,
                "Octave 结构化解析失败",
            ) from exc

        lines = source.splitlines()
        line_columns = [_utf16_columns_by_byte(line) for line in lines]
        selected: dict[tuple[int, int], tuple[int, str, int, Any]] = {}
        for capture, nodes in captures.items():
            token_type, modifiers, priority = _CAPTURE_STYLES[capture]
            for node in nodes:
                if node.start_point.row != node.end_point.row:
                    continue
                key = (node.start_byte, node.end_byte)
                current = selected.get(key)
                if current is None or priority > current[0]:
                    selected[key] = (priority, token_type, modifiers, node)

        absolute_tokens: list[tuple[int, int, int, int, int]] = []
        for _, token_type, modifiers, node in selected.values():
            row = node.start_point.row
            if row >= len(lines):
                continue
            columns = line_columns[row]
            start_column = columns.get(node.start_point.column)
            end_column = columns.get(node.end_point.column)
            if start_column is None or end_column is None:
                continue
            absolute_tokens.append(
                (
                    row,
                    start_column,
                    end_column - start_column,
                    _TYPE_INDEX[token_type],
                    modifiers,
                )
            )
        absolute_tokens.sort()

        data: list[int] = []
        previous_line = 0
        previous_character = 0
        for line, character, length, token_type, modifiers in absolute_tokens:
            delta_line = line - previous_line
            delta_character = (
                character if delta_line else character - previous_character
            )
            data.extend(
                [delta_line, delta_character, length, token_type, modifiers]
            )
            previous_line = line
            previous_character = character
        digest = hashlib.sha256(encoded).hexdigest()
        return {"data": data, "result_id": f"1:{digest[:12]}"}


_service = SemanticLanguageServicePool(
    service_name="Tree-sitter Octave",
    size=LANGUAGE_SERVICE_POOL_SIZE,
    factory=lambda _slot: OctaveTreeSitterService(),
)


def verify_octave_language_runtime() -> None:
    """Exercise the same query and token conversion used by HTTP requests."""
    result = _service.semantic_tokens(
        "runtime-self-check",
        "function y = f(x)\n  y = zeros(size(x));\nend\n",
    )
    if not result.get("data"):
        raise RuntimeError("Tree-sitter MATLAB 语义令牌自检失败")


def get_octave_language_service(language: str) -> SemanticLanguageServicePool:
    if language not in {"matlab", "octave"}:
        raise ValueError("仅 MATLAB/Octave 支持 Tree-sitter 结构化解析")
    return _service

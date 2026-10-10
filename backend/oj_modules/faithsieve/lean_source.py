"""Lean 工件的词法边界；不替代 Lean 编译或自然语言语义审计。"""

from __future__ import annotations

from dataclasses import dataclass
import unicodedata


class LeanSourceError(ValueError):
    """无法完整识别工件中的注释或字面量。"""


@dataclass(frozen=True)
class LeanToken:
    kind: str
    text: str


_PLACEHOLDERS = {"sorry", "admit", "axiom"}
_UNSAFE_IDENTIFIERS = {"sorryax", "mksorry", "axiomdecl"}
_INTERPOLATED_PREFIXES = {"s!", "m!", "dbg_trace", "throwError"}
_COMPLEX_INTERPOLATION = {
    "throwErrorAt", "throwNamedError", "throwNamedErrorAt", "logNamedError",
    "logNamedErrorAt", "logNamedWarning", "logNamedWarningAt",
}
_COMMANDS = {
    "def", "abbrev", "opaque", "axiom", "theorem", "lemma", "example", "instance",
    "inductive", "structure", "class", "namespace", "section", "end", "variable",
    "variables", "import", "export", "attribute", "syntax", "macro", "macro_rules",
    "elab", "notation", "run_cmd", "initialize", "builtin_initialize",
}


def _identifier_start(char):
    return char == "_" or unicodedata.category(char).startswith("L")


def _identifier_rest(char):
    category = unicodedata.category(char)
    return _identifier_start(char) or category.startswith(("M", "N")) or char in "'!?"


class _Lexer:
    def __init__(self, source):
        self.source = source
        self.tokens = []

    def _token(self, kind, start, end):
        self.tokens.append(LeanToken(kind, self.source[start:end]))

    def _block_comment(self, start):
        index, depth = start + 2, 1
        while index < len(self.source):
            if self.source.startswith("/-", index):
                depth += 1
                index += 2
            elif self.source.startswith("-/", index):
                depth -= 1
                index += 2
                if not depth:
                    return index
            else:
                index += 1
        raise LeanSourceError("Lean 块注释未闭合")

    def _string(self, start, quote, *, interpolated=False, depth=0):
        index = quote + 1
        literal_index = len(self.tokens)
        self._token("literal", start, index)
        while index < len(self.source):
            char = self.source[index]
            if char == '"':
                self.tokens[literal_index] = LeanToken("literal", self.source[start:index + 1])
                return index + 1
            if char == "\\":
                index += 2
            elif interpolated and char == "{":
                index = self.scan(index + 1, closing_brace=True, depth=depth + 1)
            else:
                index += 1
        raise LeanSourceError("Lean 字符串未闭合")

    def _raw_string(self, start, quote):
        hashes = quote - start - 1
        closing = '"' + "#" * hashes
        end = self.source.find(closing, quote + 1)
        if end < 0:
            raise LeanSourceError("Lean 原始字符串未闭合")
        end += len(closing)
        self._token("literal", start, end)
        return end

    def _char(self, start):
        index = start + 1
        if index >= len(self.source):
            raise LeanSourceError("Lean 字符字面量未闭合")
        if self.source[index] == "\\":
            index += 1
            if index >= len(self.source):
                raise LeanSourceError("Lean 字符字面量未闭合")
            escape = self.source[index]
            index += 1 + (2 if escape == "x" else 4 if escape == "u" else 0)
        else:
            index += 1
        if index >= len(self.source) or self.source[index] != "'":
            raise LeanSourceError("Lean 字符字面量未闭合")
        self._token("literal", start, index + 1)
        return index + 1

    def scan(self, index=0, *, closing_brace=False, depth=0):
        if depth > 64:
            raise LeanSourceError("Lean 插值表达式嵌套过深")
        source = self.source
        while index < len(source):
            char = source[index]
            if char.isspace():
                index += 1
            elif source.startswith("--", index):
                newline = source.find("\n", index + 2)
                index = len(source) if newline < 0 else newline + 1
            elif source.startswith("/-", index):
                index = self._block_comment(index)
            elif char == "«":
                end = source.find("»", index + 1)
                if end < 0:
                    raise LeanSourceError("Lean 转义标识符未闭合")
                self._token("quoted_identifier", index, end + 1)
                index = end + 1
            elif source.startswith(('s!"', 'm!"'), index):
                index = self._string(index, index + 2, interpolated=True, depth=depth)
            elif char == '"':
                previous = self.tokens[-1] if self.tokens else None
                interpolated = (previous is not None and previous.kind == "identifier"
                                and previous.text in _INTERPOLATED_PREFIXES
                                and (len(self.tokens) < 2 or self.tokens[-2].text != "."))
                index = self._string(index, index, interpolated=interpolated, depth=depth)
            elif char == "'":
                index = self._char(index)
            elif char == "r" and (index + 1 < len(source)):
                quote = index + 1
                while quote < len(source) and source[quote] == "#":
                    quote += 1
                if quote < len(source) and source[quote] == '"':
                    index = self._raw_string(index, quote)
                else:
                    end = index + 1
                    while end < len(source) and _identifier_rest(source[end]):
                        end += 1
                    self._token("identifier", index, end)
                    index = end
            elif _identifier_start(char):
                end = index + 1
                while end < len(source) and _identifier_rest(source[end]):
                    end += 1
                self._token("identifier", index, end)
                index = end
            elif char in "0123456789":
                end = index + 1
                while end < len(source) and source[end] in "0123456789":
                    end += 1
                self._token("number", index, end)
                index = end
            elif closing_brace and char == "{":
                index = self.scan(index + 1, closing_brace=True, depth=depth + 1)
            elif closing_brace and char == "}":
                return index + 1
            else:
                end = index + (2 if source.startswith(":=", index) else 1)
                self._token("symbol", index, end)
                index = end
        if closing_brace:
            raise LeanSourceError("Lean 插值表达式未闭合")
        return index


def lean_tokens(source):
    """跳过嵌套注释；字面量文本不作为代码，插值中的表达式仍扫描。"""
    lexer = _Lexer(source)
    lexer.scan()
    for index, token in enumerate(lexer.tokens):
        if token.kind != "identifier" or (index and lexer.tokens[index - 1].text == "."):
            continue
        # 这些原生宏在 name/ref 参数之后才读取插值字符串；本门禁不推断
        # 任意 Lean term 的边界，不能把其中的代码误当普通字面量吞掉。
        if token.text in _COMPLEX_INTERPOLATION or (
            token.text == "trace" and index + 1 < len(lexer.tokens)
            and lexer.tokens[index + 1].text == "["
        ):
            raise LeanSourceError("Lean 工件包含无法可靠扫描的复杂插值形式")
    return lexer.tokens


def contains_forbidden_lean(tokens):
    for token in tokens:
        if token.kind == "identifier":
            name = token.text.casefold()
            if name in _PLACEHOLDERS | _UNSAFE_IDENTIFIERS:
                return True
        elif token.kind == "quoted_identifier":
            # 转义标识符仍可引用实际的 sorry 构造器，不能借 guillemets 绕过。
            if token.text[1:-1].casefold() in _UNSAFE_IDENTIFIERS:
                return True
    return False


def statement_prop_name(tokens):
    names = []
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.text != "def":
            continue
        following = tokens[index + 1:index + 5]
        if (len(following) == 4 and following[0].kind in {"identifier", "quoted_identifier"}
                and [item.text for item in following[1:]] == [":", "Prop", ":="]):
            names.append(following[0].text)
    return names[0] if len(names) == 1 else None


def _scoped_option(tokens, index):
    """只识别明确的 set_option name value in；全局设置不属于 proof body。"""
    index += 1
    if index >= len(tokens) or tokens[index].kind not in {"identifier", "quoted_identifier"}:
        return False
    index += 1
    while index + 1 < len(tokens) and tokens[index].text == ".":
        if tokens[index + 1].kind not in {"identifier", "quoted_identifier"}:
            return False
        index += 2
    if index >= len(tokens):
        return False
    value = tokens[index]
    if not (value.kind == "number" or value.text in {"true", "false"}
            or (value.kind == "literal" and value.text.startswith(('"', 'r"', 'r#')))):
        return False
    return index + 1 < len(tokens) and tokens[index + 1].text == "in"


def _scoped_open(tokens, index):
    index += 1
    seen_name = False
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "identifier" and token.text == "in":
            return seen_name
        if token.kind not in {"identifier", "quoted_identifier"} and token.text != ".":
            return False
        seen_name = True
        index += 1
    return False


def is_fixed_proof_appendix(tokens, proposition):
    if (not proposition or len(tokens) < 6
            or [token.text for token in tokens[:5]] != ["theorem", "FaithSieveProof", ":", proposition, ":="]
            or tokens[0].kind != "identifier" or tokens[1].kind != "identifier"):
        return False
    return not any(
        (token.kind == "identifier" and token.text in _COMMANDS)
        or (token.kind == "identifier" and token.text == "set_option" and not _scoped_option(tokens, index))
        or (token.kind == "identifier" and token.text == "open" and not _scoped_open(tokens, index))
        or (token.kind == "symbol" and token.text == "#"
            and (index + 1 == len(tokens) or tokens[index + 1].text != "["))
        for index, token in enumerate(tokens[5:], 5)
    )

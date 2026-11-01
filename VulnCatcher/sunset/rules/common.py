"""轻量源码辅助工具（不依赖 tree-sitter / 外部解析器）。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache


def strip_comments(text: str, language: str = "java") -> str:
    """把注释替换为空格，保留字符串与换行，保证行号不变。"""
    if not text:
        return ""
    line_comment = "//"
    block_start, block_end = "/*", "*/"
    hash_comment = language in {"python", "ruby", "shell", "yaml", "php"}
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        char = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if hash_comment and char == "#":
                state = "line"
                out.append(" ")
            elif char == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 1
            elif char == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 1
            elif char == '"':
                state = "string"
                out.append(char)
            elif char == "'" and language not in {"python"}:
                state = "char"
                out.append(char)
            else:
                out.append(char)
        elif state == "line":
            if char == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
        elif state == "block":
            if char == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 1
            elif char == "\n":
                out.append("\n")
            else:
                out.append(" ")
        elif state == "string":
            out.append(char)
            if char == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif char == '"':
                state = "code"
        elif state == "char":
            out.append(char)
            if char == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif char == "'":
                state = "code"
        i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def var_reference_pattern(name: str) -> re.Pattern[str]:
    r"""Match a tainted variable reference, honouring the PHP `$` sigil.

    Taint keys are stored without the sigil (``_assignment_target`` and
    ``_tainted_map`` capture ``(?:\$|@)?([A-Za-z_]\w*)``), while PHP source always
    writes ``$var``.  The optional ``\$`` prefix bridges the two; the ``[\w$]``
    guards keep ``$var`` from matching inside ``$varx``, ``xvar`` or ``$foo_var``.
    Languages without the sigil (Java, JS, ...) skip the optional prefix, so
    their matching behaviour is unchanged.
    """
    return re.compile(rf"(?<![\w$])\$?{re.escape(name)}(?![\w$])")


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def split_args(args: str) -> list[str]:
    """按顶层逗号切分参数，忽略括号/字符串内的逗号。"""
    result: list[str] = []
    depth = 0
    current: list[str] = []
    quote = ""
    iterator = iter(range(len(args)))
    for index in iterator:
        char = args[index]
        if quote:
            current.append(char)
            if char == "\\" and index + 1 < len(args):
                current.append(args[index + 1])
                next(iterator, None)
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            current.append(char)
        elif char in "([{<":
            depth += 1
            current.append(char)
        elif char in ")]}>":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            result.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        result.append("".join(current).strip())
    return result


def enclosing_call_args(line: str, open_paren_index: int) -> str | None:
    """返回从 open_paren_index 的左括号开始匹配到的括号内文本。"""
    if open_paren_index >= len(line) or line[open_paren_index] != "(":
        return None
    depth = 0
    quote = ""
    for index in range(open_paren_index, len(line)):
        char = line[index]
        if quote:
            if char == "\\":
                continue
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[open_paren_index + 1:index]
    return line[open_paren_index + 1:]


def find_block_end(text: str, start: int) -> int:
    """从 start（{ 的位置）开始找匹配的 }，忽略字符串与字符字面量。"""
    depth = 0
    quote = ""
    index = start
    n = len(text)
    while index < n:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return n - 1


@dataclass
class JavaMethod:
    name: str
    start_line: int  # 1-based
    end_line: int
    params: list[str] = field(default_factory=list)
    signature: str = ""
    annotations: list[str] = field(default_factory=list)

    def param_names(self) -> list[str]:
        names: list[str] = []
        for param in self.params:
            cleaned = re.sub(r"@\w+(?:\([^)]*\))?", " ", param)
            cleaned = re.sub(r"\bfinal\b", " ", cleaned)
            match = re.search(r"([A-Za-z_]\w*)\s*$", cleaned.strip())
            if match:
                names.append(match.group(1))
        return names


_CONTROL = {
    "if", "for", "while", "switch", "catch", "synchronized", "try", "else",
    "do", "return", "new", "throw", "assert", "case", "default", "super", "this",
    "record", "class", "interface", "enum", "lambda",
}


def _matching_paren(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    index = open_index
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _last_signature_paren(header: str) -> tuple[int, int, str] | None:
    """在 `{` 前的 header 中找最后一个方法参数括号，并返回 (open, close, name)。"""
    pairs: list[tuple[int, int]] = []
    index = 0
    while index < len(header):
        if header[index] == "(":
            close = _matching_paren(header, index)
            if close < 0:
                break
            pairs.append((index, close))
            index = close + 1
            continue
        index += 1
    for open_index, close_index in reversed(pairs):
        remainder = header[close_index + 1:].strip()
        if remainder and not remainder.startswith("throws"):
            continue
        before = header[:open_index].rstrip()
        match = re.search(r"([A-Za-z_]\w*)$", before)
        if not match:
            continue
        name = match.group(1)
        if name in _CONTROL:
            continue
        # 排除 obj.method(...) 与 @Annotation(...) 以及 new Foo(...) { 匿名类
        preceding = before[:match.start()].rstrip()
        if preceding.endswith((".", "@")):
            continue
        if re.search(r"\bnew\s*$", preceding):
            continue
        # 排除赋值/return 里出现的调用
        if re.search(r"(?:=|return)\s*$", preceding):
            continue
        return open_index, close_index, name
    return None


def extract_java_methods(code: str) -> list[JavaMethod]:
    """基于 `{` 的轻量方法识别。

    比单纯的「标识符(...){」更稳：先找最后一段参数括号，要求其后面只有空白或
    throws，从而跳过 `@PostMapping("/x")`、`if (...)`、`new Foo(...)`。
    """
    methods: list[JavaMethod] = []
    lines = code.splitlines()
    for brace in (index for index, char in enumerate(code) if char == "{"):
        header_start = max(
            code.rfind(";", 0, brace),
            code.rfind("{", 0, brace),
            code.rfind("}", 0, brace),
            code.rfind(":", 0, brace),
        ) + 1
        header = code[header_start:brace]
        if ")" not in header:
            continue
        found = _last_signature_paren(header)
        if not found:
            continue
        open_index, close_index, name = found
        name_pos = header_start + header.rfind(name, 0, open_index)
        line_start = line_of(code, name_pos)
        end = find_block_end(code, brace)
        end_line = line_of(code, end)
        signature = lines[line_start - 1].strip() if 0 <= line_start - 1 < len(lines) else ""
        annotations: list[str] = []
        back = line_start - 2
        while back >= 0 and lines[back].strip().startswith("@"):
            annotations.append(lines[back].strip())
            back -= 1
        methods.append(
            JavaMethod(
                name=name,
                start_line=line_start,
                end_line=end_line,
                params=split_args(header[open_index + 1:close_index]),
                signature=signature,
                annotations=list(reversed(annotations)),
            )
        )
    # 同名/同起始行去重
    seen: set[tuple[str, int]] = set()
    unique: list[JavaMethod] = []
    for method in methods:
        key = (method.name, method.start_line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(method)
    return unique

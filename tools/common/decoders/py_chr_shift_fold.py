"""
Family:     setup.py with control-flow flattening and strings built as
            `''.join(map(getattr(__builtins__, <'c'+'h'+'r' from builtin reprs>), [<shift/add int exprs>]))`,
            state variable assigned pure integer arithmetic (`834*(395 & 643)+... | 104 << 313 ...`)
Reverses:   folds each integer expression with a small arithmetic parser (no eval) and replaces each
            chr-join call with the plain string literal; replaces pure-arithmetic right-hand sides of
            assignments with the folded integer, so the flattened state machine can be followed
Per sample: none

Self-check: every folded char code must be a printable character or tab/CR/LF, otherwise the decode is refused (ValueError).
Nothing from the package is imported, compiled or run. Pure stdlib: re.
"""
from __future__ import annotations

import re

_CHR_CALL = re.compile(
    r"''\.join\(map\(getattr\(__builtins__,\s*oct\.__str__\(\)\[-3 << 0\] \+ hex\.__str__\(\)\[-1 << 2\]"
    r" \+ copyright\.__str__\(\)\[4 << 0\]\),\s*\[([^\[\]]*)\]\)\)")
_ARITH_ASSIGN = re.compile(r"(?m)^([ \t]*[^\W\d]\w* ?= ?)([0-9()+\-*/&|^~<> \t]+)$")
_TOK = re.compile(r"\s*(\d+|<<|>>|//|[()+\-*&|^~])")


class _Parser:
    def __init__(self, text: str):
        self.toks = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOK.match(text, pos)
            if not m:
                raise ValueError("unexpected token at %r" % text[pos:pos + 10])
            self.toks.append(m.group(1))
            pos = m.end()
            while pos < len(text) and text[pos] in " \t\r\n\\":
                pos += 1
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self) -> int:
        v = self.or_()
        if self.peek() is not None:
            raise ValueError("trailing tokens")
        return v

    def or_(self):
        v = self.xor()
        while self.peek() == "|":
            self.take()
            v |= self.xor()
        return v

    def xor(self):
        v = self.and_()
        while self.peek() == "^":
            self.take()
            v ^= self.and_()
        return v

    def and_(self):
        v = self.shift()
        while self.peek() == "&":
            self.take()
            v &= self.shift()
        return v

    def shift(self):
        v = self.add()
        while self.peek() in ("<<", ">>"):
            op = self.take()
            r = self.add()
            if op == "<<":
                if r > 4096:
                    raise ValueError("shift too large")
                v <<= r
            else:
                v >>= r
        return v

    def add(self):
        v = self.mul()
        while self.peek() in ("+", "-"):
            op = self.take()
            r = self.mul()
            v = v + r if op == "+" else v - r
        return v

    def mul(self):
        v = self.unary()
        while self.peek() in ("*", "//"):
            op = self.take()
            r = self.unary()
            v = v * r if op == "*" else v // r
        return v

    def unary(self):
        t = self.peek()
        if t == "~":
            self.take()
            return ~self.unary()
        if t == "-":
            self.take()
            return -self.unary()
        if t == "+":
            self.take()
            return self.unary()
        return self.atom()

    def atom(self):
        t = self.take()
        if t == "(":
            v = self.or_()
            if self.take() != ")":
                raise ValueError("unbalanced parenthesis")
            return v
        if t.isdigit():
            return int(t)
        raise ValueError("unexpected token %r" % t)


def fold(text: str) -> int:
    return _Parser(text).parse()


def _split_top(text: str):
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def _chr_sub(m: re.Match) -> str:
    out = []
    for part in _split_top(m.group(1)):
        c = fold(part)
        if not 9 <= c <= 0x10FFFF or not (chr(c).isprintable() or chr(c) in "\t\r\n"):
            raise ValueError("char code out of range: %d" % c)
        out.append(chr(c))
    return repr("".join(out))


def _assign_sub(m: re.Match) -> str:
    rhs = m.group(2)
    if not re.search(r"[+\-*/&|^~<>]", rhs):
        return m.group(0)
    return m.group(1) + str(fold(rhs))


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    text = input_bytes.decode("utf-8")
    text, n = _CHR_CALL.subn(_chr_sub, text)
    if not n:
        raise ValueError("no chr-join calls found")
    text = _ARITH_ASSIGN.sub(_assign_sub, text)
    return text.encode("utf-8")

"""Fold char-code strings and opaque integer arithmetic in a Python file.

Family:      setup.py files flattened into numeric state machines, with strings built by ''.join(map(<chr resolver>, [shift arithmetic ints]))
Reverses:    each join over a list of constant integer expressions becomes a string literal; each assignment whose right side is pure integer arithmetic becomes its value
Per sample:  resolver (the exact source text of the expression that resolves to chr, spaces after commas may be any whitespace in the file)

The file is treated as text. Integer expressions go through the small parser
below; nothing from the package is evaluated.
"""

import re

_TOKEN = re.compile(r"\s*(\d+|//|<<|>>|[()&|^~+\-*%])")


class _Parser:
    """Recursive descent over Python's integer operator precedence."""

    def __init__(self, text):
        self.tokens = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            match = _TOKEN.match(text, pos)
            if match is None:
                raise ValueError("bad token")
            self.tokens.append(match.group(1))
            pos = match.end()
        self.index = 0

    def peek(self):
        if self.index < len(self.tokens):
            return self.tokens[self.index]
        return None

    def take(self):
        token = self.peek()
        self.index += 1
        return token

    def parse(self):
        value = self.bit_or()
        if self.peek() is not None:
            raise ValueError("trailing tokens")
        return value

    def bit_or(self):
        value = self.bit_xor()
        while self.peek() == "|":
            self.take()
            value = value | self.bit_xor()
        return value

    def bit_xor(self):
        value = self.bit_and()
        while self.peek() == "^":
            self.take()
            value = value ^ self.bit_and()
        return value

    def bit_and(self):
        value = self.shift()
        while self.peek() == "&":
            self.take()
            value = value & self.shift()
        return value

    def shift(self):
        value = self.additive()
        while self.peek() in ("<<", ">>"):
            operator = self.take()
            right = self.additive()
            if right < 0 or right > 100000:
                raise ValueError("shift out of range")
            value = value << right if operator == "<<" else value >> right
        return value

    def additive(self):
        value = self.term()
        while self.peek() in ("+", "-"):
            operator = self.take()
            right = self.term()
            value = value + right if operator == "+" else value - right
        return value

    def term(self):
        value = self.unary()
        while self.peek() in ("*", "//", "%"):
            operator = self.take()
            right = self.unary()
            if operator == "*":
                value = value * right
            elif operator == "//":
                value = value // right
            else:
                value = value % right
        return value

    def unary(self):
        token = self.peek()
        if token == "-":
            self.take()
            return -self.unary()
        if token == "+":
            self.take()
            return self.unary()
        if token == "~":
            self.take()
            return ~self.unary()
        return self.atom()

    def atom(self):
        token = self.take()
        if token == "(":
            value = self.bit_or()
            if self.take() != ")":
                raise ValueError("unbalanced")
            return value
        if token is None or not token.isdigit():
            raise ValueError("expected a number")
        return int(token)


def _fold(text):
    return _Parser(text).parse()


def _split_items(text):
    items = []
    depth = 0
    current = []
    for char in text:
        if char == "," and depth == 0:
            items.append("".join(current))
            current = []
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        current.append(char)
    if "".join(current).strip():
        items.append("".join(current))
    return items


def decode(input_bytes, params, read):
    text = input_bytes.decode("utf-8")
    parts = params["resolver"].split(", ")
    resolver = r",\s*".join(re.escape(part) for part in parts)
    join_call = re.compile(r"''\.join\(map\(" + resolver + r",\s*\[([^\]]*)\]\)\)")

    def join_literal(match):
        try:
            codes = [_fold(item) for item in _split_items(match.group(1))]
            return repr("".join(chr(code) for code in codes))
        except (ValueError, ZeroDivisionError, OverflowError):
            return match.group(0)

    text = join_call.sub(join_literal, text)

    assignment = re.compile(r"(?<![=!<>])=[ \t]*([0-9()&|^~+\-*/%<> \t]+?)[ \t]*$", re.M)

    def folded_assignment(match):
        try:
            return "= " + str(_fold(match.group(1)))
        except (ValueError, ZeroDivisionError, OverflowError):
            return match.group(0)

    return assignment.sub(folded_assignment, text).encode("utf-8")

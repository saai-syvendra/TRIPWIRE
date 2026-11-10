"""
Text hygiene for anything taken from package code: secret redaction, share-link id redaction, URL and IPv4
defanging, and string-literal unescaping. Pure functions on strings; nothing is resolved or fetched.
"""
from __future__ import annotations

import re

URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"`<>()\[\]{}\\]+", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![\w.])")
SECRETS = [re.compile(p) for p in (
    r"(?<=/api/webhooks/)\d+/[\w-]+",
    r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])",
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
    r"\bnpm_[A-Za-z0-9]{36}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
)]


# File-share, paste and request-capture hosts whose URL path carries a secret access id.
SHARE_HOST = re.compile(r"(transfer\.sh|dropboxusercontent\.com|dropbox\.com|pastebin\.com|paste\.ee"
                        r"|hastebin\.com|termbin\.com|file\.io|anonfiles\.com|gofile\.io|0x0\.st|webhook\.site"
                        r"|pipedream\.net|requestbin\.\w+|ngrok\.io|ngrok-free\.app|trycloudflare\.com)", re.I)
# A URL whether or not it is already defanged (hxxp, [.]), so re-defanging analyst text still redacts ids.
# Brackets are allowed in the path because a defanged host carries `[.]`.
URLISH = re.compile(r"\b(?:h[tx]{2}ps?|wss?|f[tx]p)://[^\s'\"`<>(){}\\]+", re.I)


def redact(s: str) -> str:
    for rx in SECRETS:
        s = rx.sub(lambda m: m.group(0)[:4] + "…", s)
    return s


def _redact_share(m) -> str:
    """Redacts the high-entropy access id in a file-share URL path to its first 4 chars; keeps the filename."""
    url = m.group(0)
    host = url.split("://", 1)[1].split("/", 1)[0].replace("[.]", ".")
    if not SHARE_HOST.search(host):
        return url
    scheme, rest = url.split("://", 1)
    host_raw, sep, path = rest.partition("/")
    if not sep:
        return url
    segs = [seg[:4] + "…" if re.fullmatch(r"[A-Za-z0-9_-]{6,}", seg) else seg for seg in path.split("/")]
    return f"{scheme}://{host_raw}{sep}" + "/".join(segs)


def defang(s: str) -> str:
    """Redacts secrets and share-link ids, defangs URLs and IPv4 addresses; bare domains are left to the analyst."""
    def url(m):
        scheme, rest = m.group(0).split("://", 1)
        host, sep, path = rest.partition("/")
        scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
        return f"{scheme}://{host.replace('.', '[.]')}{sep}{path}"
    s = URLISH.sub(_redact_share, URL.sub(url, redact(s)))
    return IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), s)


def unescape(raw: str) -> tuple[str, bool]:
    """Decodes \\x, \\u and simple escapes in a string literal body; returns (value, changed)."""
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`"}

    def sub(m):
        e = m.group(1)
        if e[0] in "xu":
            return chr(int(e[1:].strip("{}"), 16))
        return simple.get(e, e)
    value = re.sub(r"\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|.)", sub, raw)
    return value, bool(re.search(r"\\[xu]", raw))

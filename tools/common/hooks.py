"""
Install hook commands (npm scripts) as data: which package files a command runs, which code it passes inline
(`node -e`, `python -c`), the interpreter, the launch styles and whether it hides errors. The command string is
tokenised with shlex; nothing is executed.

Used by prepare.py to find entry points and by the verifier to rebuild inline-script derivations.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from tools.common.sanitize import defang


def inline_code(manifest: dict, root: Path, hook: str, flag: str) -> str | None:
    """The inline code a hook passes with -e/-c, as prepare saw it. `flag` is `-e`, or `-e #2` for the second
    script of the same kind in one hook (see number_inline)."""
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    scripts = {k: v for k, v in scripts.items() if isinstance(v, str)}
    if hook not in scripts:
        return None
    name = f"<{hook} {flag}>"
    found = [code for n, code, _ in parse_command(scripts[hook], hook, root, scripts)["inline"] if n == name]
    return found[0] if found else None


def segments(cmd: str) -> tuple[list[list[str]], list[str]]:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        tokens = cmd.split()
    segs, ops, cur = [], [], []
    for tok in tokens:
        if tok in ("&&", "||", ";", "|", "&", ";;"):
            segs.append(cur)
            ops.append(tok)
            cur = []
        else:
            cur.append(tok)
    segs.append(cur)
    clean = []
    for seg in segs:
        out, skip = [], False
        for tok in seg:
            if skip:
                skip = False
                continue
            if re.fullmatch(r"[<>]+&?|&[<>]+", tok):
                skip = True
                if out and out[-1].isdigit():
                    out.pop()
                continue
            out.append(tok)
        clean.append(out)
    return clean, ops


SILENCERS = re.compile(r"\|\|\s*(true|:|exit\s+0|echo\b)|2>\s*/dev/null|&>\s*/dev/null|>\s*/dev/null\s+2>&1"
                       r"|2>\s*nul\b|>\s*nul\b", re.I)
DOWNLOADERS = {"curl", "wget", "invoke-webrequest", "iwr", "certutil", "bitsadmin"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
NODES = {"node", "nodejs"}
PYTHONS = {"python", "python3", "python2", "py"}
NATIVE = {"node-gyp", "prebuild-install", "node-pre-gyp", "cmake-js", "prebuildify"}
CODE_KINDS = ("js", "py", "sh", "binary")


def file_kind(path: Path) -> str | None:
    """Language of a script started by a hook: js, py, sh, binary or None."""
    suffix = path.suffix.lower()
    if suffix in (".js", ".cjs", ".mjs"):
        return "js"
    if suffix == ".py":
        return "py"
    if suffix in (".sh", ".bash"):
        return "sh"
    try:
        head = path.read_bytes()[:256]
    except OSError:
        return None
    if head.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
        return "binary"
    first = head.split(b"\n", 1)[0]
    if first.startswith(b"#!"):
        if b"node" in first:
            return "js"
        if b"python" in first:
            return "py"
        return "sh"
    return None


def parse_command(cmd: str, hook: str, root: Path, scripts: dict, depth: int = 0) -> dict:
    """Entry-point facts for one hook command: files it runs, inline code, interpreter, launch styles."""
    out = {"files": [], "inline": [], "interpreter": None, "launch_style": [], "silent": bool(SILENCERS.search(cmd)),
           "notes": []}
    segs, ops = segments(cmd)

    def style(s):
        if s not in out["launch_style"]:
            out["launch_style"].append(s)

    def interp(i):
        out["interpreter"] = out["interpreter"] or i

    def add_file(token, lang_hint):
        token = token.strip()
        path = (root / token).resolve()
        if not path.is_file() and lang_hint == "js":
            # node resolves a script path like require does.
            path = next((c for c in (path.with_name(path.name + e) for e in (".js", ".cjs", ".mjs"))
                         if c.is_file()), path / "index.js")
        if not path.is_file() or not path.is_relative_to(root.resolve()):
            out["notes"].append(f"{hook}: '{defang(token)}' is not a file in the package")
            return
        rel = path.relative_to(root.resolve()).as_posix()
        kind = file_kind(path) or lang_hint
        if kind == "binary":
            style("dropped_binary")
        out["files"].append((rel, kind))

    if "&" in ops or any(t in ("nohup", "setsid", "disown") for s in segs for t in s[:1]):
        style("detached_child")
    for i, seg in enumerate(segs):
        while seg and (re.match(r"^\w+=", seg[0]) or seg[0] in ("cross-env", "env", "nohup", "setsid", "sudo",
                                                                  "exec", "time", "command")):
            seg = seg[1:]
        if not seg:
            continue
        exe = Path(seg[0]).name.lower().removesuffix(".exe")
        args = seg[1:]
        piped_into = i > 0 and ops[i - 1] == "|"
        if exe in DOWNLOADERS:
            nxt = segs[i + 1][0].lower() if i + 1 < len(segs) and segs[i + 1] else ""
            if i < len(ops) and ops[i] == "|" and Path(nxt).name in SHELLS | NODES | PYTHONS | {"iex"}:
                style("shell_pipe")
            style("download_then_exec")
            interp("sh")
        elif exe in NODES:
            interp("node")
            j = 0
            while j < len(args):
                a = args[j]
                if a in ("-e", "--eval", "-p", "--print") and j + 1 < len(args):
                    out["inline"].append((f"<{hook} -e>", args[j + 1], "js"))
                    style("inline_eval")
                    j += 2
                    continue
                if a in ("-r", "--require", "--import") and j + 1 < len(args):
                    if args[j + 1].startswith("."):
                        add_file(args[j + 1], "js")
                    j += 2
                    continue
                if a.startswith("-"):
                    j += 1
                    continue
                add_file(a, "js")
                style("direct_script")
                break
            if piped_into:
                style("shell_pipe")
        elif exe in SHELLS:
            interp("sh")
            if "-c" in args and args.index("-c") + 1 < len(args):
                inner = parse_command(args[args.index("-c") + 1], hook, root, scripts, depth + 1)
                merge(out, inner)
                style("inline_shell")
            elif args:
                add_file(args[0], "sh")
                style("direct_script")
            if piped_into:
                style("shell_pipe")
        elif exe in PYTHONS:
            interp("python")
            if "-c" in args and args.index("-c") + 1 < len(args):
                out["inline"].append((f"<{hook} -c>", args[args.index("-c") + 1], "py"))
                style("inline_eval")
            else:
                script = next((a for a in args if not a.startswith("-")), None)
                if script:
                    add_file(script, "py")
                    style("direct_script")
        elif exe in ("powershell", "pwsh"):
            interp("powershell")
            style("inline_shell")
            if any(a.lower() in ("-enc", "-encodedcommand", "-e") for a in args):
                style("decoded_eval")
        elif exe == "cmd" and args and args[0].lower() in ("/c", "/k"):
            interp("cmd")
            style("inline_shell")
            merge(out, parse_command(" ".join(args[1:]), hook, root, scripts, depth + 1))
        elif exe == "start" and args and args[0].lower() in ("/b", "/min"):
            style("detached_child")
            merge(out, parse_command(" ".join(args[1:]), hook, root, scripts, depth + 1))
        elif exe in ("npm", "yarn", "pnpm", "bun") and depth < 5:
            target = run_target(exe, args)
            if target and target in scripts:
                merge(out, parse_command(scripts[target], hook, root, scripts, depth + 1))
            elif target and (root / target).is_file():
                add_file(target, None)
                style("direct_script")
            elif args and args[0] in ("i", "install", "add", "ci"):
                out["notes"].append(f"{hook}: installs further packages ({defang(' '.join(seg))[:120]})")
            elif target:
                out["notes"].append(f"{hook}: runs script '{target}', which the manifest does not define")
        elif exe in NATIVE:
            style("native_build")
            interp("other")
            out["notes"].append(f"{hook}: delegates to {exe}; code inside that dependency is out of scope")
        elif exe in ("[", "[[", "test", "if"):
            out["notes"].append(f"{hook}: shell condition in the hook command, not covered by the extractor: "
                                f"{defang(' '.join(seg))[:150]}")
        elif exe in ("echo", "exit", "true", "false", ":", "chmod", "cd", "rm", "mkdir", "cp", "mv", "printf"):
            continue
        elif seg[0].startswith((".", "/")) or (root / seg[0]).is_file():
            add_file(seg[0], None)
            style("direct_script")
        else:
            interp("other")
            out["notes"].append(f"{hook}: runs '{defang(exe)}' from a dependency or the system; its code is out "
                                f"of scope")
    if depth == 0:
        out["inline"] = number_inline(out["inline"])
    return out


def number_inline(inline: list[tuple]) -> list[tuple]:
    """Several -e/-c scripts in one hook (`node -e A && node -e B`) would share the pseudo-file `<hook -e>` and
    overwrite each other; the second and later get `<hook -e #2>`, ... in command order."""
    seen, out = {}, []
    for name, code, lang in inline:
        seen[name] = seen.get(name, 0) + 1
        out.append((name if seen[name] == 1 else f"{name[:-1]} #{seen[name]}>", code, lang))
    return out


def run_target(exe: str, args: list[str]) -> str | None:
    if not args:
        return None
    if args[0] in ("run", "run-script") and len(args) > 1:
        return args[1]
    if exe in ("yarn", "pnpm", "bun") and args[0] not in ("install", "add", "i", "dlx", "exec", "x"):
        return args[0]
    return None


def merge(out: dict, inner: dict) -> None:
    for k in ("files", "inline", "notes"):
        out[k] += [x for x in inner[k] if x not in out[k]]
    for s in inner["launch_style"]:
        if s not in out["launch_style"]:
            out["launch_style"].append(s)
    out["interpreter"] = out["interpreter"] or inner["interpreter"]
    out["silent"] = out["silent"] or inner["silent"]

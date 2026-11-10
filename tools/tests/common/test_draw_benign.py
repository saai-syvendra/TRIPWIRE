"""The benign draw on canned registry responses: ranking, the install-code tests, pinning and fetching."""
import base64
import hashlib
import io
import json
import tarfile

from tools.common import draw_benign as db


def tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def responses() -> dict[str, bytes]:
    pkg, version, member = db.NPM_LIST
    listing = tgz({member: b"export const topDownload = [\n  'quiet',\n  'loud',\n  '@s/native',\n  'gone',\n]\n"})
    r = {f"https://registry.npmjs.org/{pkg}/{version}": json.dumps(
        {"dist": {"tarball": "https://t/list.tgz", "integrity": sri(listing)}}).encode(), "https://t/list.tgz": listing}
    r["https://api.npmjs.org/downloads/point/last-month/loud"] = json.dumps(
        {"loud": {"downloads": 50, "start": "2026-09-23", "end": "2026-10-22"}}).encode()
    r["https://api.npmjs.org/downloads/point/last-month/@s%2Fnative"] = json.dumps(
        {"downloads": 300, "start": "2026-09-23", "end": "2026-10-22"}).encode()
    for name, extra in (("quiet", {}), ("loud", {"scripts": {"postinstall": "node x.js"}}),
                        ("@s/native", {"gypfile": True})):
        ball = tgz({"package/package.json": json.dumps({"name": name}).encode()})
        url = f"https://t/{name.replace('/', '-')}.tgz"
        r[url] = ball
        r[f"https://registry.npmjs.org/{db.q(name)}/latest"] = json.dumps(
            {"version": "1.0.0", "dist": {"tarball": url, "integrity": sri(ball)}, **extra}).encode()
    r[db.PYPI_LIST] = json.dumps({"last_update": "2026-10-01 12:40:51", "rows": [
        {"project": "wheelonly", "download_count": 30}, {"project": "toml-only", "download_count": 20},
        {"project": "classic", "download_count": 10}]}).encode()
    for name, files in (("toml-only", {"toml-only-1.0/pyproject.toml": b""}),
                        ("classic", {"classic-2.0/setup.py": b"", "classic-2.0/sub/setup.py": b""})):
        data = tgz(files)
        url = f"https://f/{name}.tar.gz"
        r[url] = data
        r[f"https://pypi.org/pypi/{name}/json"] = json.dumps({"info": {"name": name, "version": "2.0"}, "urls": [
            {"packagetype": "sdist", "url": url, "digests": {"sha256": hashlib.sha256(data).hexdigest()}}]}).encode()
    r["https://pypi.org/pypi/wheelonly/json"] = json.dumps(
        {"info": {"name": "wheelonly", "version": "1"}, "urls": [{"packagetype": "bdist_wheel"}]}).encode()
    return r


def test_draw_ranks_by_downloads_and_keeps_only_install_code():
    canned = responses()
    manifest, kept = db.draw(canned.__getitem__, 5, 5, 100, "benign-test")
    got = [(e["ecosystem"], e["name"], e["rank"], e["install_code"]) for e in manifest["items"]]
    # quiet has no install code and gone is no longer served; @s/native (300) outranks loud (50)
    assert got == [("npm", "@s/native", 1, ["binding.gyp"]), ("npm", "loud", 2, ["postinstall"]),
                   ("pypi", "classic", 3, ["setup.py"])]
    assert manifest["pools"]["npm"]["downloads"] == "api.npmjs.org last-month 2026-09-23..2026-10-22"
    assert manifest["pools"]["pypi"]["last_update"] == "2026-10-01 12:40:51"
    assert all(e["sha256"] and e["weight"] is None and e["stratum"].startswith("benign-top-")
               for e in manifest["items"])
    assert set(kept) == {e["url"] for e in manifest["items"]}


def test_fetch_checks_the_pinned_sha256(repo):
    canned = responses()
    manifest, _ = db.draw(canned.__getitem__, 5, 5, 100, "benign-test")
    ok, failed = db.fetch_archives(manifest, canned.__getitem__)
    assert (ok, failed) == (3, [])
    assert db.dest(manifest["items"][0]).parent.as_posix().endswith("samples/benign_sample/npm/benign")
    manifest["items"][1]["sha256"] = "0" * 64
    db.dest(manifest["items"][1]).unlink()
    assert db.fetch_archives(manifest, canned.__getitem__)[1] == ["loud: bytes do not match the pinned sha256"]


def test_a_tampered_npm_tarball_is_not_drawn():
    canned = responses()
    canned["https://t/loud.tgz"] = b"other bytes"
    manifest, _ = db.draw(canned.__getitem__, 5, 5, 100, "benign-test")
    assert "loud" not in {e["name"] for e in manifest["items"]}


def test_setup_py_must_sit_at_the_sdist_root():
    assert db.sdist_has_setup_py(tgz({"p-1/setup.py": b""}))
    assert not db.sdist_has_setup_py(tgz({"p-1/docs/setup.py": b""}))
    assert not db.sdist_has_setup_py(b"not an archive")


def test_malformed_scripts_field_is_no_install_code():
    assert db.npm_install_code({"scripts": []}) == []
    assert db.npm_install_code({"scripts": {"install": "node-gyp rebuild"}, "gypfile": True}) == ["install",
                                                                                                "binding.gyp"]

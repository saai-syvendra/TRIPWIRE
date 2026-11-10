"""prepare.py in batches: the PyPI cluster key, tool-written records, refusing to clobber edited work, the merged
queue, duplicates within a batch, per-sample errors and when the registry is asked."""
import json

import pytest

from tools.analysis import prepare, work_queue
from tools.common import unpack
from tools.tests.helpers import NPM, prepared, sample, tgz


def typosquat(name, version, description="A fork of a popular library", payload="os.system('calc')"):
    return {"PKG-INFO": f"Name: {name}\nVersion: {version}\n",
            "README.md": "readme\n",
            "setup.py": "import os\n"
                        "from setuptools import setup\n"
                        "if os.name == 'nt':\n"
                        f"    {payload}\n"
                        f"setup(name={name!r}, version={version!r}, description={description!r},\n"
                        "      long_description=open('README.md').read(), author='someone',\n"
                        "      classifiers=['Programming Language :: Python', 'License :: OSI Approved'],\n"
                        "      project_urls={'Source': 'https://example.invalid/x'}, packages=['pkg'])\n"}


def sdist(repo, name, version, **kw):
    return sample(repo, f"pypi/{name}-{version}.tar.gz", tgz(typosquat(name, version, **kw), f"{name}-{version}/"))


def run_batch(repo, monkeypatch, *extra):
    monkeypatch.setattr("sys.argv", ["prepare.py", str(repo / "samples"), "--batch", *extra])
    return prepare.main()


def queue(repo):
    return [json.loads(line) for line in (repo / "scratch" / "queue.jsonl").read_text().splitlines()]


# --- cluster key -------------------------------------------------------------------------------------------------

def test_typosquats_differing_only_in_setup_metadata_are_one_campaign(repo):
    seen = {}
    one = prepare.prepare(sdist(repo, "reqeusts", "2.0.1"), None, None, seen)
    two = prepare.prepare(sdist(repo, "requestss", "9.9", description="Other words"), None, None, seen)
    assert one["status"] == "analyse"
    assert two["status"] == "member" and two["representative"] == "pypi:reqeusts@2.0.1"
    member = json.loads((repo / two["record"]).read_text())
    assert member["package"]["cluster_key"] == prepared(repo, one)["package"]["cluster_key"]
    assert member["package"]["analysis_type"] == "tool" and member["schema_version"] == "3.2"


def test_one_changed_code_byte_is_another_campaign(repo):
    seen = {}
    prepare.prepare(sdist(repo, "reqeusts", "2.0.1"), None, None, seen)
    other = prepare.prepare(sdist(repo, "requestss", "9.9", payload="os.system('calx')"), None, None, seen)
    assert other["status"] == "analyse"


def test_computed_metadata_is_code_and_stays_in_the_key():
    src = (b"from setuptools import setup\n"
           b"setup(name='a', version=__version__, description=f'{x}', long_description=open('R').read(),\n"
           b"      url=about['url'], keywords=('a', 'b'), classifiers=['x'] + extra, cmdclass={'install': P},\n"
           b"      install_requires=['evil'])\n")
    masked = unpack.mask_setup_metadata(src)
    m = unpack.METADATA_MASK
    assert masked == (b"from setuptools import setup\n"
                      b"setup(name=" + m + b", version=" + m + b", description=f'{x}', "
                      b"long_description=open('R').read(),\n"
                      b"      url=about['url'], keywords=" + m + b", classifiers=['x'] + extra, "
                      b"cmdclass={'install': P},\n"
                      b"      install_requires=['evil'])\n")


def test_only_setup_calls_are_masked():
    src = b"import x\nx.configure(name='a', version='1')\nsetuptools.setup(name='b')\n"
    assert unpack.mask_setup_metadata(src) == b"import x\nx.configure(name='a', version='1')\nsetuptools.setup(name=" \
        + unpack.METADATA_MASK + b")\n"
    assert unpack.mask_setup_metadata(b"print('no call')\n") == b"print('no call')\n"


def test_npm_files_are_hashed_as_they_are(repo, tmp_path):
    (tmp_path / "setup.py").write_text("setup(name='a')\n")
    raw = unpack.reached_file_digests(tmp_path, [["setup.py"]])
    assert raw != unpack.reached_file_digests(tmp_path, [["setup.py"]], mask_setup=True)
    res = prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None)
    assert prepared(repo, res)["package"]["cluster_key"]  # the exact npm digest is pinned in test_prepare.py


# --- clobbering and the queue ------------------------------------------------------------------------------------

def test_edited_scratch_is_never_deleted(repo):
    s = sample(repo, "npm/demo.tgz", tgz(NPM))
    first = prepare.prepare(s, None, None)
    work = repo / "scratch" / first["key"]
    rec = json.loads((work / "record.json").read_text())
    rec["attack_type"] = "typosquat"
    (work / "record.json").write_text(json.dumps(rec))
    again = prepare.prepare(s, None, None)
    assert again["status"] == "in_progress" and "record.json edited" in again["note"]
    assert json.loads((work / "record.json").read_text())["attack_type"] == "typosquat"
    assert not list((repo / "scratch").glob("_unpack_*"))


def test_unedited_scratch_is_prepared_again(repo):
    s = sample(repo, "npm/demo.tgz", tgz(NPM))
    prepare.prepare(s, None, None)
    assert prepare.prepare(s, None, None)["status"] == "analyse"


def test_batch_merges_into_the_queue(repo, monkeypatch):
    work_queue.write([{"key": "npm__other@1", "status": "done", "prepared": "scratch/npm__other@1/prepared.json",
                       "sample": "elsewhere.tgz"}])
    sample(repo, "npm/a.tgz", tgz(NPM))
    assert run_batch(repo, monkeypatch) == 0
    rows = queue(repo)
    assert [(r["key"], r["status"]) for r in rows] == [("npm__other@1", "done"), ("npm__demo-pkg@1.0.0", "analyse")]
    assert run_batch(repo, monkeypatch) == 0  # a re-run replaces its own row, never duplicates it
    assert [(r["key"], r["status"]) for r in queue(repo)] == [("npm__other@1", "done"),
                                                             ("npm__demo-pkg@1.0.0", "analyse")]


def test_queue_row_of_work_in_progress_is_kept(repo, monkeypatch):
    sample(repo, "npm/a.tgz", tgz(NPM))
    run_batch(repo, monkeypatch)
    work_queue.set_fields("npm__demo-pkg@1.0.0", {"status": "blocked", "note": "safeguard"})
    (repo / "scratch" / "npm__demo-pkg@1.0.0" / "summary.md").write_text("## Summary\n\nhalf done\n")
    run_batch(repo, monkeypatch)
    (row,) = queue(repo)
    assert row["status"] == "blocked" and row["note"] == "safeguard"


# --- duplicates within a batch -----------------------------------------------------------------------------------

def test_identical_second_archive_is_noted_on_the_first_row(repo, monkeypatch):
    data = tgz(typosquat("Foo_Bar", "1.0"), "Foo_Bar-1.0/")
    sample(repo, "pypi/a/Foo_Bar-1.0.tar.gz", data)
    sample(repo, "pypi/b/foo.bar-1.0.tar.gz", data)
    run_batch(repo, monkeypatch, "--no-registry")
    (row,) = queue(repo)
    assert row["key"] == "pypi__Foo_Bar@1.0" and row["status"] == "analyse"
    assert [(d["identical"], d["sample"].endswith("b/foo.bar-1.0.tar.gz")) for d in row["duplicates"]] == [(True, True)]


def test_different_archive_with_the_same_name_needs_a_person(repo, monkeypatch):
    sample(repo, "pypi/a/foo-1.0.tar.gz", tgz(typosquat("Foo_Bar", "1.0"), "Foo_Bar-1.0/"))
    sample(repo, "pypi/b/foo-1.0.tar.gz", tgz(typosquat("foo-bar", "1.0", payload="os.system('x')"), "foo-bar-1.0/"))
    run_batch(repo, monkeypatch, "--no-registry")
    (row,) = queue(repo)
    assert row["status"] == "duplicate_key" and row["duplicates"][0]["identical"] is False
    assert "decide which one" in row["note"]
    assert not (repo / "scratch" / "pypi__foo-bar@1.0").exists()


def test_existing_report_matches_any_pep503_spelling(repo):
    (repo / "reports" / "pypi").mkdir(parents=True)
    (repo / "reports" / "pypi" / "Foo_Bar@1.0.md").write_text("existing")
    res = prepare.prepare(sdist(repo, "foo.bar", "1.0"), None, None)
    assert res["status"] == "duplicate" and res["record"].endswith("Foo_Bar@1.0.md")


# --- errors and the registry -------------------------------------------------------------------------------------

def test_a_failing_sample_becomes_an_error_row_and_the_batch_continues(repo, monkeypatch):
    sample(repo, "npm/a.tgz", tgz(NPM))
    sample(repo, "npm/b.zip", b"PK")
    real = prepare.unpack

    def flaky(archive, dest):
        if archive.name == "b.zip":
            raise unpack.MissingTool("b.zip needs 7-Zip for AES decryption")
        return real(archive, dest)
    monkeypatch.setattr(prepare, "unpack", flaky)
    assert run_batch(repo, monkeypatch) == 1
    rows = {r["sample"].rsplit("/", 1)[-1]: r for r in queue(repo)}
    assert rows["a.tgz"]["status"] == "analyse"
    assert rows["b.zip"]["status"] == "error" and "MissingTool" in rows["b.zip"]["error"]
    assert not (repo / "reports" / "_skipped").exists()  # a missing tool is never a skip record
    assert not list((repo / "scratch").glob("_unpack_*"))


def test_missing_7zip_is_an_exception_not_an_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(unpack.shutil, "which", lambda name: None)
    with pytest.raises(unpack.MissingTool):
        unpack.unpack_7z(tmp_path / "x.zip", tmp_path / "out")


def test_registry_is_asked_only_after_member_detection(repo, monkeypatch):
    asked = []

    def fake(eco, name, version, sample_name=None, registry=False):
        if registry:
            asked.append(name)
        return None, None
    monkeypatch.setattr(prepare, "release_date", fake)
    seen, batch = {}, {}
    data = tgz(typosquat("reqeusts", "2.0.1"), "reqeusts-2.0.1/")
    for rel in ("pypi/a/reqeusts-2.0.1.tar.gz", "pypi/b/reqeusts-2.0.1.tar.gz"):
        prepare.prepare(sample(repo, rel, data), None, None, seen, registry=True, batch=batch)
    member = prepare.prepare(sdist(repo, "requestss", "9.9"), None, None, seen, registry=True, batch=batch)
    assert member["status"] == "member"
    assert asked == ["reqeusts", "requestss"]  # the identical second archive cost no lookup

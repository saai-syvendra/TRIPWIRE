"""Structure checks for every skills/<name>/: a lean SKILL.md with one-level references."""
import re

import pytest

from tools.common import paths

SKILLS = sorted(p.parent for p in (paths.CODE_ROOT / "skills").glob("*/SKILL.md"))
# Language idioms belong in the ecosystem references, not in a core procedure.
CORE_DENY = ["require(", "process.", "sys.", "setup.py", "cmdclass", "package.json", "node-gyp", "child_process",
             "subprocess", "os.system", "__dirname", "npm install", "pip install", ".exit("]
# Skills that other agents (not only Claude) run must not assume which model reads them.
EXTRA_DENY = {"verify-gates": ["Claude"]}
# References that must name specific agent CLIs (how to run each one) are exempt from EXTRA_DENY.
NAMES_AGENTS = {"verify-gates": {"agent-runners.md"}}

skill_dirs = pytest.mark.parametrize("skill_dir", SKILLS, ids=lambda p: p.name)


def skill_text(skill_dir):
    return (skill_dir / "SKILL.md").read_text(encoding="utf-8")


def frontmatter(skill_dir):
    m = re.match(r"^---\n(.*?)\n---\n", skill_text(skill_dir), re.S)
    assert m, "SKILL.md must start with a --- frontmatter block"
    return dict(re.findall(r"^(\w[\w-]*):\s*(.*)$", m.group(1), re.M))


def test_gate_analysis_is_present():
    assert "gate-analysis" in [s.name for s in SKILLS]


@skill_dirs
def test_frontmatter_name_and_description(skill_dir):
    fm = frontmatter(skill_dir)
    assert fm.get("name") == skill_dir.name
    assert re.fullmatch(r"[a-z0-9-]{1,64}", fm["name"]) and not re.search(r"anthropic|claude", fm["name"])
    desc = fm.get("description", "")
    assert 0 < len(desc) <= 1024 and "<" not in desc and ">" not in desc


@skill_dirs
def test_skill_md_is_under_500_lines(skill_dir):
    assert len(skill_text(skill_dir).splitlines()) < 500


@skill_dirs
def test_every_reference_is_linked_from_skill_md(skill_dir):
    text = skill_text(skill_dir)
    for ref in sorted((skill_dir / "references").glob("*.md")):
        assert f"references/{ref.name}" in text, f"{ref.name} is not linked from SKILL.md"


@skill_dirs
def test_long_references_have_contents_and_do_not_link_each_other(skill_dir):
    for ref in sorted((skill_dir / "references").glob("*.md")):
        text = ref.read_text(encoding="utf-8")
        if len(text.splitlines()) > 100:
            assert "## Contents" in text, f"{ref.name} needs a ## Contents section"
        assert "references/" not in text and not re.search(r"\]\([^)]*\.md\)", text), \
            f"{ref.name} links another file; keep references one level deep"


@skill_dirs
def test_core_has_no_language_idioms(skill_dir):
    text = skill_text(skill_dir)
    hits = [term for term in CORE_DENY + EXTRA_DENY.get(skill_dir.name, []) if term in text]
    assert not hits, f"move these out of {skill_dir.name}/SKILL.md: {hits}"


@skill_dirs
def test_references_do_not_assume_the_reading_model(skill_dir):
    deny = EXTRA_DENY.get(skill_dir.name, [])
    for ref in sorted((skill_dir / "references").glob("*.md")):
        if ref.name in NAMES_AGENTS.get(skill_dir.name, set()):
            continue
        hits = [term for term in deny if term in ref.read_text(encoding="utf-8")]
        assert not hits, f"{skill_dir.name}/references/{ref.name} names {hits}"


@skill_dirs
def test_skill_is_linked_for_claude_code_and_named_for_other_agents(skill_dir):
    links = paths.CODE_ROOT / ".claude" / "skills"
    if not links.is_dir():
        pytest.skip("Claude Code skill links are local setup (README); none here")
    link = links / skill_dir.name
    assert link.is_symlink() and link.resolve() == skill_dir.resolve(), f"missing .claude/skills/{skill_dir.name}"
    agents = paths.CODE_ROOT / "AGENTS.md"
    if agents.exists():
        assert f"skills/{skill_dir.name}/SKILL.md" in agents.read_text(encoding="utf-8")

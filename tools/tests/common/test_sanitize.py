"""Defanging must be idempotent along every path a string can take (generator, write_report, packets), so an
indicator never comes out double-bracketed like files[[.]]pythonhosted[[.]]org."""
import pytest

from tools.analysis.write_report import defang_all, defang_hosts
from tools.common.sanitize import defang

CASES = [
    "https://files.pythonhosted.org/packages/x.tar.gz",
    "hxxps://files[.]pythonhosted[.]org/packages/x.tar.gz",
    "files[.]pythonhosted[.]org",
    "download from https://evil.example:8443/a?b=c then run it",
    "10.0.0.1:80",
    "10[.]0[.]0[.]1",
    "1.2.3[.]4",
    "wss://c2.example/ws and ftp://drop.example/f",
    "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
    "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX",
    "plain text with no indicator",
]


@pytest.mark.parametrize("s", CASES)
def test_defang_is_idempotent(s):
    once = defang(s)
    assert defang(once) == once
    assert "[[" not in once and "]]" not in once


@pytest.mark.parametrize("s", CASES)
def test_record_paths_are_idempotent(s):
    once = defang_all({"a": [s], "b": s})
    assert defang_all(once) == once
    hosts = defang_hosts(once["b"])
    assert defang_hosts(hosts) == hosts and "[[" not in hosts


def test_pythonhosted_host_is_defanged_once():
    assert defang_hosts("files.pythonhosted.org:443") == "files[.]pythonhosted[.]org:443"
    assert defang_hosts(defang_hosts("files.pythonhosted.org:443")) == "files[.]pythonhosted[.]org:443"
    assert defang("https://files.pythonhosted.org/p") == defang(defang("https://files.pythonhosted.org/p"))

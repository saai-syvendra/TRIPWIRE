import io
import json
import socket
import urllib.error
import urllib.request

import pytest

from tools.analysis import release_date as rd


def url_of(req):
    return req.full_url if isinstance(req, urllib.request.Request) else req


def serve(monkeypatch, doc, seen=None):
    def fake(req, timeout=None):
        if seen is not None:
            seen.append(url_of(req))
        return io.BytesIO(json.dumps(doc).encode())
    monkeypatch.setattr(urllib.request, "urlopen", fake)


def scripted(monkeypatch, outcomes):
    """urlopen that raises or answers from `outcomes` in order; returns the calls and the waits."""
    calls, waits = [], []

    def fake(req, timeout=None):
        calls.append(req)
        out = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(out, Exception):
            raise out
        return io.BytesIO(json.dumps(out).encode())
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setattr(rd, "_sleep", waits.append)
    return calls, waits


def http_error(code):
    return urllib.error.HTTPError("https://registry.npmjs.org/a", code, "x", {}, None)


NPM_DOC = {"time": {"1": "2025-01-02T00:00:00Z"}}


def test_dated_archive_name_is_the_dataset_fallback():
    assert rd.from_filename("2025-11-24-02-echo-v0.0.7.zip") == "2025-11-24"
    assert rd.from_filename("2025-11-24-@actbase_native-v0.1.32.zip") == "2025-11-24"
    assert rd.from_filename("10Cent10-999.0.4.tar.gz") is None
    assert rd.from_filename("2025-13-40-x-v1.zip") is None
    assert rd.from_filename("20251124-x.zip") is None
    assert rd.release_date("npm", "02-echo", "0.0.7", "2025-11-24-02-echo-v0.0.7.zip") == ("2025-11-24", "dataset")
    assert rd.release_date("pypi", "x", "1", "x-1.tar.gz") == (None, None)


def test_registry_off_never_touches_the_network(monkeypatch):
    def boom(*a, **k):
        pytest.fail("urlopen called with registry=False")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert rd.release_date("npm", "a", "1", "2024-01-02-a-v1.zip") == ("2024-01-02", "dataset")


def test_npm_publish_time_and_quoted_scoped_name(monkeypatch):
    seen = []
    serve(monkeypatch, {"time": {"created": "2016-08-25T03:47:42Z", "0.1.32": "2025-11-24T04:11:05.345Z"}}, seen)
    assert rd.release_date("npm", "@actbase/native", "0.1.32", registry=True) == ("2025-11-24", "registry")
    assert seen == ["https://registry.npmjs.org/%40actbase%2Fnative"]


def test_requests_name_the_research_tool(monkeypatch):
    calls, _ = scripted(monkeypatch, [NPM_DOC])
    rd.release_date("npm", "a", "1", registry=True)
    assert calls[0].get_header("User-agent") == rd.USER_AGENT and "research" in rd.USER_AGENT


def test_hostile_name_cannot_leave_the_registry_host(monkeypatch):
    seen = []
    serve(monkeypatch, {}, seen)
    rd.release_date("pypi", "x@evil.example/../..", "1?a=b", registry=True)
    assert seen == ["https://pypi.org/pypi/x%40evil.example%2F..%2F../1%3Fa%3Db/json"]


def test_pypi_upload_time(monkeypatch):
    serve(monkeypatch, {"urls": [{"upload_time_iso_8601": "2023-03-01T10:00:00.000000Z"}]})
    assert rd.release_date("pypi", "1inch", "8.6", registry=True) == ("2023-03-01", "registry")


def test_removed_version_falls_back_to_the_archive_name_without_retrying(monkeypatch):
    calls, waits = scripted(monkeypatch, [http_error(404)])
    assert rd.release_date("npm", "a", "1", "2024-01-02-a-v1.zip", registry=True) == ("2024-01-02", "dataset")
    assert rd.release_date("pypi", "a", "1", "a-1.tar.gz", registry=True) == (None, None)
    assert len(calls) == 2 and waits == []


def test_missing_version_in_registry_doc(monkeypatch):
    serve(monkeypatch, {"time": {"unpublished": {"time": "2025-11-25T00:00:00Z"}}})
    assert rd.release_date("npm", "a", "1", registry=True) == (None, None)


@pytest.mark.parametrize("failure", [http_error(429), http_error(503), urllib.error.URLError(TimeoutError("t")),
                                     TimeoutError("read timed out"), ConnectionResetError("reset")],
                         ids=["429", "503", "timeout", "read-timeout", "reset"])
def test_transient_failures_are_retried_with_fixed_backoff(monkeypatch, failure):
    calls, waits = scripted(monkeypatch, [failure, failure, NPM_DOC])
    assert rd.release_date("npm", "a", "1", registry=True) == ("2025-01-02", "registry")
    assert len(calls) == 3 and waits == [1, 2]


def test_retries_stop_after_the_last_backoff(monkeypatch):
    calls, waits = scripted(monkeypatch, [http_error(500)])
    assert rd.release_date("npm", "a", "1", "2024-01-02-a-v1.zip", registry=True) == ("2024-01-02", "dataset")
    assert len(calls) == len(rd.BACKOFF) + 1 and waits == list(rd.BACKOFF)


def test_a_failed_lookup_never_disables_later_ones(monkeypatch):
    calls, _ = scripted(monkeypatch, [urllib.error.URLError(TimeoutError("t"))] * 4 + [NPM_DOC])
    assert rd.release_date("npm", "a", "1", registry=True) == (None, None)
    assert rd.release_date("npm", "b", "1", registry=True) == ("2025-01-02", "registry")
    assert len(calls) == 5


def test_unresolvable_host_fails_at_once(monkeypatch):
    calls, waits = scripted(monkeypatch, [urllib.error.URLError(socket.gaierror(-2, "Name or service not known"))])
    assert rd.release_date("npm", "a", "1", registry=True) == (None, None)
    assert len(calls) == 1 and waits == []

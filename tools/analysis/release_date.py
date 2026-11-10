#!/usr/bin/env python3
"""
Release date of a package version, for package.released_at and package.released_at_source.

Asks the public registry when the version was published (npm `time[version]`, PyPI `upload_time_iso_8601`).
Malicious versions are often removed from the registry, so it falls back to a YYYY-MM-DD prefix on the
dataset's archive name (datadog names samples `2025-11-24-<name>-v<version>.zip`), else None. Only the two
fixed registry hosts are contacted; the package's own name and version are quoted as single path segments,
so a hostile name cannot change the host. Never raises.

Every lookup stands alone: a failed lookup never disables later ones. A rate limit (429), a server error
(5xx), a timeout or a dropped or refused connection is retried after the fixed waits in BACKOFF (so at most
len(BACKOFF) + 1 requests per lookup); a 404 or other client error, a host that does not resolve, or a
response that is not JSON gives None at once. Requests carry a User-Agent naming this research tool.
"""
from __future__ import annotations

import datetime
import http.client
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 6
# Seconds to wait before each retry of a transient failure. Fixed counts, never a deadline.
BACKOFF = (1, 2, 4)
USER_AGENT = "tripwire-release-date/1 (academic supply-chain research; publish-date lookup only)"
DATE_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_sleep = time.sleep  # tests replace it


def registry_url(ecosystem: str, name: str, version: str) -> str | None:
    def q(s: str) -> str:
        return urllib.parse.quote(s, safe="")
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{q(name)}"
    if ecosystem == "pypi":
        return f"https://pypi.org/pypi/{q(name)}/{q(version)}/json"
    return None


def date_part(stamp) -> str | None:
    m = DATE_PREFIX.match(stamp) if isinstance(stamp, str) else None
    if not m:
        return None
    try:
        datetime.date.fromisoformat(m.group(1))
    except ValueError:
        return None
    return m.group(1)


def published(doc: dict, ecosystem: str, version: str) -> str | None:
    if ecosystem == "npm":
        return date_part((doc.get("time") or {}).get(version))
    files = doc.get("urls") or []
    return date_part(files[0].get("upload_time_iso_8601")) if files and isinstance(files[0], dict) else None


def transient(err: Exception) -> bool:
    """Worth retrying: a rate limit, a server error, a timeout, or a dropped or refused connection."""
    if isinstance(err, urllib.error.HTTPError):
        return err.code == 429 or 500 <= err.code < 600
    if isinstance(err, http.client.HTTPException):
        return True  # a response cut off mid-way
    reason = err.reason if isinstance(err, urllib.error.URLError) else err
    if isinstance(reason, socket.gaierror):
        return False  # the host does not resolve; retrying will not help
    return isinstance(reason, (TimeoutError, socket.timeout, ConnectionError))


def fetch(url: str):
    """The registry's JSON document at `url`, or None."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    for attempt in range(len(BACKOFF) + 1):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as r:
                return json.load(r)
        except ValueError:
            return None  # not JSON
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:  # HTTPError is a URLError
            if attempt == len(BACKOFF) or not transient(e):
                return None  # a 404 and friends: the version is gone from the registry
            _sleep(BACKOFF[attempt])
    return None


def from_registry(ecosystem: str, name: str | None, version: str | None) -> str | None:
    url = registry_url(ecosystem, name, version) if name and version else None
    if url is None:
        return None
    doc = fetch(url)
    return published(doc, ecosystem, version) if isinstance(doc, dict) else None


def from_filename(sample_name: str | None) -> str | None:
    """A dated archive name: the date must be followed by a dash, as in `2025-11-24-02-echo-v0.0.7.zip`."""
    if not sample_name or not re.match(r"^\d{4}-\d{2}-\d{2}-", sample_name):
        return None
    return date_part(sample_name)


def release_date(ecosystem: str, name: str | None, version: str | None, sample_name: str | None = None,
                 registry: bool = False) -> tuple[str | None, str | None]:
    """(YYYY-MM-DD, "registry" | "dataset") or (None, None)."""
    if registry:
        found = from_registry(ecosystem, name, version)
        if found:
            return found, "registry"
    found = from_filename(sample_name)
    return (found, "dataset") if found else (None, None)

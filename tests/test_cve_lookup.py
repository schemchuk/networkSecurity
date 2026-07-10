"""Tests for tools.cve_lookup.

All tests mock ``subprocess.run``; no real network or local searchsploit call
is performed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from tools.cve_lookup import CVELookupError, search_cves
from tools.schemas import CVE


SAMPLE_JSON = {
    "RESULTS_EXPLOIT": [
        {
            "Title": "Samba 3.0.20 - RCE",
            "EDB-ID": "16320",
            "Codes": "CVE-2007-2447;OSVDB-34700",
        },
        {
            "Title": "Samba - symlink",
            "EDB-ID": "33053",
            "Codes": "CVE-2008-1105",
        },
    ]
}


def _make_run_mock(stdout: str):
    """Return a monkeypatch-compatible mock for subprocess.run."""

    def _run(*args: Any, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(stdout=stdout, stderr="", returncode=0)

    return _run


def test_extracts_cves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "subprocess.run",
        _make_run_mock(json.dumps(SAMPLE_JSON)),
    )

    cves = search_cves("Samba", "3.0.20")

    assert cves == [
        CVE(id="CVE-2007-2447", cvss=None, source="exploitdb"),
        CVE(id="CVE-2008-1105", cvss=None, source="exploitdb"),
    ]


def test_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {
        "RESULTS_EXPLOIT": [
            {"Title": "A", "EDB-ID": "1", "Codes": "CVE-2007-2447"},
            {"Title": "B", "EDB-ID": "2", "Codes": "CVE-2007-2447"},
        ]
    }
    monkeypatch.setattr("subprocess.run", _make_run_mock(json.dumps(data)))

    cves = search_cves("Samba")

    assert [c.id for c in cves] == ["CVE-2007-2447"]


def test_empty_product_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def _run(*args: Any, **kwargs: Any):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr("subprocess.run", _run)

    assert search_cves("") == []
    assert search_cves(None) == []
    assert not called


def test_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "subprocess.run",
        _make_run_mock(json.dumps({"RESULTS_EXPLOIT": []})),
    )

    assert search_cves("Samba") == []


def test_missing_binary_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(*args: Any, **kwargs: Any):
        raise FileNotFoundError("searchsploit")

    monkeypatch.setattr("subprocess.run", _run)

    with pytest.raises(CVELookupError):
        search_cves("Samba")

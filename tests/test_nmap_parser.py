"""Tests for the deterministic nmap XML parser."""

from pathlib import Path

import pytest

from tools.nmap_parser import parse_nmap_xml
from tools.schemas import Finding


@pytest.fixture
def sample_xml() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "nmap_sample.xml"


def test_parses_open_ports(sample_xml: Path):
    findings = parse_nmap_xml(sample_xml)
    assert len(findings) == 2


def test_finding_fields(sample_xml: Path):
    findings = parse_nmap_xml(sample_xml)
    by_port = {f.port: f for f in findings}

    assert 445 in by_port
    f445 = by_port[445]
    assert isinstance(f445, Finding)
    assert f445.host == "10.10.10.5"
    assert f445.protocol == "tcp"
    assert f445.service == "microsoft-ds"
    assert f445.product == "Samba smbd"
    assert f445.version == "3.0.20"
    assert f445.source == "nmap"
    assert "port445" in f445.evidence


def test_ids_are_sequential(sample_xml: Path):
    findings = parse_nmap_xml(sample_xml)
    assert [f.id for f in findings] == ["F-0001", "F-0002"]


def test_invalid_file_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("/nonexistent/path/file.xml")

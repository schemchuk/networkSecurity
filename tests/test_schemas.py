"""Tests for Pydantic data schemas."""

from datetime import datetime, timezone

from tools.schemas import CVE, Event, Finding


def test_finding_round_trip():
    original = Finding(
        id="F-0001",
        host="10.10.10.5",
        port=445,
        protocol="tcp",
        service="microsoft-ds",
        product="Samba",
        version="3.0.20",
        source="nmap",
        cves=[CVE(id="CVE-2007-2447", cvss=6.0, source="searchsploit")],
        severity="high",
        priority=1,
        summary="Risk summary",
        mitigation="Patch it",
        detection="IDS alert",
        next_steps=["verify exploitation path"],
        evidence="runs/x/raw/nmap.xml#port445",
    )

    json_str = original.model_dump_json()
    restored = Finding.model_validate_json(json_str)

    assert restored.id == original.id
    assert restored.host == original.host
    assert restored.port == original.port
    assert restored.protocol == original.protocol
    assert restored.service == original.service
    assert restored.product == original.product
    assert restored.version == original.version
    assert restored.source == original.source
    assert len(restored.cves) == 1
    assert restored.cves[0].id == "CVE-2007-2447"
    assert restored.cves[0].cvss == 6.0
    assert restored.cves[0].source == "searchsploit"
    assert restored.severity == original.severity
    assert restored.priority == original.priority
    assert restored.summary == original.summary
    assert restored.mitigation == original.mitigation
    assert restored.detection == original.detection
    assert restored.next_steps == original.next_steps
    assert restored.evidence == original.evidence


def test_event_now_has_utc_datetime():
    event = Event.now(run_id="x", agent="recon", type="note")

    assert isinstance(event.ts, datetime)
    assert event.ts.tzinfo is not None
    assert event.ts.tzinfo == timezone.utc
    assert event.run_id == "x"
    assert event.agent == "recon"
    assert event.type == "note"

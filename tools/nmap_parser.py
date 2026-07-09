"""Deterministic parser for nmap XML output.

Produces normalized ``Finding`` objects per open port, per ARCHITECTURE.md §7.
CVE lookup is intentionally out of scope here (handled by M2).
"""

from __future__ import annotations

from pathlib import Path

from libnmap.parser import NmapParser
from libnmap.objects.service import NmapService

from tools.schemas import Finding, Severity


def _service_to_finding(
    host_address: str,
    service: NmapService,
    source_path: Path,
    finding_id: str,
) -> Finding:
    """Convert a single open Nmap service into a Finding.

    Reads product/version from libnmap's structured ``service_dict`` rather than
    parsing the banner string, which also embeds extrainfo/ostype and is fragile.
    """
    details = service.service_dict
    product = (details.get("product") or "").strip() or None
    version = (details.get("version") or "").strip() or None

    return Finding(
        id=finding_id,
        host=host_address,
        port=service.port,
        protocol=service.protocol,
        service=service.service,
        product=product,
        version=version,
        source="nmap",
        severity=Severity.INFO,
        evidence=f"{source_path}#port{service.port}",
    )


def parse_nmap_xml(path: str | Path) -> list[Finding]:
    """Parse an nmap XML file and return a list of findings for open ports.

    Args:
        path: Path to the nmap XML output file.

    Returns:
        List of ``Finding`` objects, one per open port per up host.

    Raises:
        ValueError: If the file cannot be parsed as nmap XML.
    """
    source_path = Path(path)

    try:
        nmap_report = NmapParser.parse_fromfile(str(source_path))
    except Exception as exc:
        raise ValueError(f"Failed to parse nmap XML from {source_path}: {exc}") from exc

    findings: list[Finding] = []
    counter = 1

    for host in nmap_report.hosts:
        if host.status != "up":
            continue

        host_address = host.address
        for service in host.services:
            if service.state != "open":
                continue

            finding_id = f"F-{counter:04d}"
            findings.append(
                _service_to_finding(
                    host_address=host_address,
                    service=service,
                    source_path=source_path,
                    finding_id=finding_id,
                )
            )
            counter += 1

    return findings

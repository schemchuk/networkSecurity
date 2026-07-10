"""Deterministic CVE lookup via local exploitdb (searchsploit).

Uses ``searchsploit --json`` to map a product/version pair to real CVE
identifiers. LLM does not invent CVE numbers here.
"""

from __future__ import annotations

import json
import subprocess

from tools.schemas import CVE


class CVELookupError(Exception):
    """Raised when CVE lookup cannot be performed."""


def search_cves(
    product: str | None,
    version: str | None = None,
    timeout: float = 20.0,
) -> list[CVE]:
    """Return real CVE references for a product/version using searchsploit.

    Args:
        product: Product name (e.g. ``"Samba"``).
        version: Optional version string (e.g. ``"3.0.20"``).
        timeout: Maximum seconds to wait for ``searchsploit``.

    Returns:
        Unique CVE references found in the local exploitdb, ordered by first
        appearance, with ``source="exploitdb"`` and ``cvss=None``.

    Raises:
        CVELookupError: If the ``searchsploit`` binary is missing.
    """
    if not product or not product.strip():
        return []

    query = f"{product} {version or ''}".strip()

    try:
        result = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise CVELookupError(
            "searchsploit not found. Install exploitdb to use CVE lookup."
        ) from exc

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    raw_entries = data.get("RESULTS_EXPLOIT", [])
    if not isinstance(raw_entries, list):
        return []

    seen: set[str] = set()
    cves: list[CVE] = []

    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        codes = entry.get("Codes", "")
        if not isinstance(codes, str):
            continue
        for code in codes.split(";"):
            code = code.strip()
            if code.startswith("CVE-") and code not in seen:
                seen.add(code)
                cves.append(CVE(id=code, cvss=None, source="exploitdb"))

    return cves

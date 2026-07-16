"""Scope enforcement: engagement authorization and target validation.

Before running against real systems the operator must provide a signed
engagement document that lists the authorized targets. This module loads
and validates that document and checks individual targets against it.
"""

from __future__ import annotations

import ipaddress
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator


class ScopeError(Exception):
    """Raised when a target is outside the authorized engagement scope."""


class Engagement(BaseModel):
    """A signed engagement authorizing work against a defined target set."""

    client: str
    authorized_by: str
    authorization_ref: str
    authorized_targets: list[str]
    start_date: date | None = None
    end_date: date | None = None

    @field_validator("authorized_targets")
    @classmethod
    def _targets_not_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("authorized_targets must contain at least one target")
        return value


def load_engagement(path: str | Path) -> Engagement:
    """Load and validate an engagement definition from a YAML file.

    Args:
        path: Path to the YAML engagement file.

    Returns:
        A validated ``Engagement`` instance.

    Raises:
        ScopeError: If the file cannot be read or parsed.
    """
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ScopeError(f"Failed to load engagement from {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScopeError(f"Engagement file {path} must contain a YAML mapping")

    try:
        return Engagement.model_validate(raw)
    except Exception as exc:
        raise ScopeError(f"Invalid engagement in {path}: {exc}") from exc


def _is_cidr(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the network if *value* is a CIDR, otherwise ``None``."""
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _is_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the IP address if *value* is a valid IP, otherwise ``None``."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_in_scope(target: str, engagement: Engagement) -> bool:
    """Check whether *target* is authorized by *engagement*.

    Matching rules, in order:

    * CIDR entries match IP targets that fall inside the network.
    * Plain IP entries match the exact IP target.
    * Hostname entries match non-IP targets case-insensitively.

    Args:
        target: The target to validate (IP, CIDR, or hostname).
        engagement: The authorized engagement definition.

    Returns:
        ``True`` if the target matches at least one authorized target.
    """
    target_ip = _is_ip(target)
    target_host = target.strip().lower() if target_ip is None else None

    for raw_entry in engagement.authorized_targets:
        entry = raw_entry.strip()
        if not entry:
            continue

        network = _is_cidr(entry)
        if network is not None:
            if target_ip is not None and target_ip in network:
                return True
            continue

        ip = _is_ip(entry)
        if ip is not None:
            if target_ip is not None and target_ip == ip:
                return True
            continue

        # Hostname: only non-IP targets can match.
        if target_host is not None and target_host == entry.lower():
            return True

    return False


def assert_in_scope(target: str, engagement: Engagement) -> None:
    """Raise ``ScopeError`` if *target* is not authorized.

    Args:
        target: The target to validate.
        engagement: The authorized engagement definition.

    Raises:
        ScopeError: With a clear message identifying the target and engagement.
    """
    if not is_in_scope(target, engagement):
        raise ScopeError(
            f"Target {target!r} is not in scope for engagement "
            f"{engagement.authorization_ref!r} ({engagement.client})"
        )


def check_window(engagement: Engagement, when: date) -> bool:
    """Return ``True`` if *when* is within the engagement date window.

    If ``start_date`` or ``end_date`` are omitted, the corresponding boundary
    is considered open-ended.

    Args:
        engagement: The engagement whose window to check.
        when: The date to validate.

    Returns:
        ``True`` when the date is within the configured window.
    """
    if engagement.start_date is not None and when < engagement.start_date:
        return False
    if engagement.end_date is not None and when > engagement.end_date:
        return False
    return True

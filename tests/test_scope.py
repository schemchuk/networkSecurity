"""Tests for scope enforcement and engagement validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.scope import (
    Engagement,
    ScopeError,
    assert_in_scope,
    check_window,
    is_in_scope,
    load_engagement,
)


@pytest.fixture
def sample_engagement() -> Engagement:
    return Engagement(
        client="Example Corp",
        authorized_by="Jane Doe, CISO",
        authorization_ref="PENTEST-2026-001",
        authorized_targets=["192.168.56.0/24", "10.0.0.5", "app.example-lab.local"],
        start_date=None,
        end_date=None,
    )


def test_exact_ip_in_scope(sample_engagement: Engagement):
    assert is_in_scope("10.0.0.5", sample_engagement) is True
    assert is_in_scope("10.0.0.6", sample_engagement) is False


def test_cidr_in_scope(sample_engagement: Engagement):
    assert is_in_scope("192.168.56.101", sample_engagement) is True
    assert is_in_scope("192.168.57.1", sample_engagement) is False


def test_hostname_in_scope(sample_engagement: Engagement):
    assert is_in_scope("app.example-lab.local", sample_engagement) is True
    assert is_in_scope("APP.EXAMPLE-LAB.LOCAL", sample_engagement) is True
    assert is_in_scope("other.example-lab.local", sample_engagement) is False


def test_hostname_target_does_not_match_ip_entry(sample_engagement: Engagement):
    # A hostname target should not accidentally match a numeric authorization entry.
    assert is_in_scope("10.0.0.5", sample_engagement) is True
    assert is_in_scope("not-an-ip", sample_engagement) is False


def test_assert_raises_out_of_scope(sample_engagement: Engagement):
    assert_in_scope("10.0.0.5", sample_engagement)

    with pytest.raises(ScopeError) as exc_info:
        assert_in_scope("10.0.0.6", sample_engagement)

    assert "10.0.0.6" in str(exc_info.value)
    assert "PENTEST-2026-001" in str(exc_info.value)


def test_load_engagement():
    project_root = Path(__file__).resolve().parent.parent
    path = project_root / "configs" / "engagement.example.yaml"
    engagement = load_engagement(path)

    assert engagement.client == "Example Corp"
    assert engagement.authorized_by == "Jane Doe, CISO"
    assert engagement.authorization_ref == "PENTEST-2026-001 (signed 2026-08-01)"
    assert "192.168.56.0/24" in engagement.authorized_targets
    assert "10.0.0.5" in engagement.authorized_targets
    assert "app.example-lab.local" in engagement.authorized_targets


def test_load_engagement_missing_file():
    with pytest.raises(ScopeError):
        load_engagement("/nonexistent/engagement.yaml")


def test_check_window_with_dates():
    from datetime import date

    engagement = Engagement(
        client="X",
        authorized_by="Y",
        authorization_ref="Z",
        authorized_targets=["10.0.0.1"],
        start_date=date(2026, 8, 1),
        end_date=date(2026, 8, 15),
    )

    assert check_window(engagement, date(2026, 8, 1)) is True
    assert check_window(engagement, date(2026, 8, 15)) is True
    assert check_window(engagement, date(2026, 7, 31)) is False
    assert check_window(engagement, date(2026, 8, 16)) is False


def test_check_window_without_dates():
    from datetime import date

    engagement = Engagement(
        client="X",
        authorized_by="Y",
        authorization_ref="Z",
        authorized_targets=["10.0.0.1"],
    )

    assert check_window(engagement, date(2026, 1, 1)) is True


def test_engagement_requires_at_least_one_target():
    with pytest.raises(ValueError):
        Engagement(
            client="X",
            authorized_by="Y",
            authorization_ref="Z",
            authorized_targets=[],
        )

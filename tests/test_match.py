"""Unit tests for deterministic matching (pure — no DB/Docker)."""

import pytest

from depwatch.agent.match import to_advisory_ecosystem, version_in_range


def test_ecosystem_mapping():
    assert to_advisory_ecosystem("pypi") == "pip"
    assert to_advisory_ecosystem("golang") == "go"
    assert to_advisory_ecosystem("gem") == "rubygems"
    assert to_advisory_ecosystem("npm") == "npm"  # identity
    assert to_advisory_ecosystem("maven") == "maven"  # identity


@pytest.mark.parametrize(
    "scheme,version,rng,expected",
    [
        ("npm", "4.2.3", ">= 4.2.1, < 4.2.5", True),
        ("npm", "4.2.5", ">= 4.2.1, < 4.2.5", False),  # upper bound exclusive
        ("npm", "4.2.0", ">= 4.2.1, < 4.2.5", False),
        ("npm", "1.11.0", "< 1.12.0", True),
        ("npm", "1.12.0", "< 1.12.0", False),
        ("npm", "2.14.2", "= 2.14.2", True),
        ("npm", "2.14.1", "= 2.14.2", False),
        ("npm", "2.6.1", "<= 2.6.1", True),  # inclusive
        ("pypi", "3.12.5", ">= 3.12.0, <= 3.12.5", True),
        ("pypi", "3.12.6", ">= 3.12.0, <= 3.12.5", False),
    ],
)
def test_version_in_range(scheme, version, rng, expected):
    assert version_in_range(scheme, version, rng) is expected


def test_version_in_range_unparseable_returns_none():
    assert version_in_range("bogus-scheme", "1.0.0", ">= 1.0.0") is None

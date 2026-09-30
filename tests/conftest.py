"""Shared pytest fixtures.

Every test runs offline: the API key is removed and AI_OFFLINE is set, so no
test can reach the network or depend on a Claude reply.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SAMPLE_DIR = os.path.join(ROOT, "sample_data")


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("AI_OFFLINE", "1")


@pytest.fixture
def sample_path():
    """Path of a bundled capture by short name: sample_path("weak")."""

    def _path(name):
        path = os.path.join(SAMPLE_DIR, "sample_%s.pcap" % name)
        assert os.path.isfile(path), path
        return path

    return _path

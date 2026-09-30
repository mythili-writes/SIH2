"""config.py: defaults, validated environment overrides, dependency pins."""

import importlib
import os
import re

import pytest

import config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def reload_config(monkeypatch, **env):
    """Re-import config.py with the given environment, restoring it afterwards."""
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return importlib.reload(config)


@pytest.fixture(autouse=True)
def _restore_config():
    yield
    for name in ("IPSEC_MAX_CAPTURE_MB", "IPSEC_MAX_PACKETS", "IPSEC_LOG_LEVEL"):
        os.environ.pop(name, None)
    importlib.reload(config)


def test_defaults(monkeypatch):
    fresh = reload_config(monkeypatch)
    assert fresh.MAX_CAPTURE_BYTES == 200 * 1024 * 1024
    assert fresh.MAX_PACKETS == 200_000
    assert fresh.RISK_LEVEL_THRESHOLDS == (("Critical", 80), ("High", 60), ("Medium", 35))
    assert fresh.TRAFFIC_MIN_CONFIDENCE == 0.4
    assert fresh.LOG_LEVEL == "INFO"
    assert fresh.CONFIG_WARNINGS == []


def test_valid_overrides(monkeypatch):
    fresh = reload_config(
        monkeypatch, IPSEC_MAX_CAPTURE_MB="50", IPSEC_MAX_PACKETS="1000", IPSEC_LOG_LEVEL="debug"
    )
    assert fresh.MAX_CAPTURE_BYTES == 50 * 1024 * 1024
    assert fresh.MAX_PACKETS == 1000
    assert fresh.LOG_LEVEL == "DEBUG"


@pytest.mark.parametrize(
    "name, value",
    [
        ("IPSEC_MAX_PACKETS", "lots"),
        ("IPSEC_MAX_PACKETS", "0"),
        ("IPSEC_MAX_CAPTURE_MB", "-5"),
        ("IPSEC_LOG_LEVEL", "LOUD"),
    ],
)
def test_bad_overrides_fall_back_and_are_recorded(monkeypatch, name, value):
    fresh = reload_config(monkeypatch, **{name: value})
    assert fresh.MAX_PACKETS == 200_000
    assert fresh.MAX_CAPTURE_BYTES == 200 * 1024 * 1024
    assert fresh.LOG_LEVEL == "INFO"
    assert len(fresh.CONFIG_WARNINGS) == 1 and name in fresh.CONFIG_WARNINGS[0]


def test_env_example_documents_every_variable_the_code_reads():
    """Every os.environ / _env_* read in the codebase must appear in .env.example."""
    pattern = re.compile(
        r"""(?:environ(?:\.get)?\(\s*|environ\[\s*|_env_\w+\(\s*)["']([A-Z_]+)["']"""
    )
    read = set()
    for folder in ("backend", "ai_engine", "frontend", "."):
        base = os.path.join(ROOT, folder)
        for name in os.listdir(base):
            if name.endswith(".py"):
                with open(os.path.join(base, name), encoding="utf-8") as fh:
                    read.update(pattern.findall(fh.read()))
    with open(os.path.join(ROOT, ".env.example"), encoding="utf-8") as fh:
        documented = set(re.findall(r"^([A-Z_]+)=", fh.read(), re.MULTILINE))
    assert read, "the scan found no environment reads at all"
    assert read <= documented, "undocumented: %s" % sorted(read - documented)


def _pins(path):
    """{package: version} for every `name==version` line in a requirements file."""
    pins = {}
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if "==" in line:
                name, version = line.split("==", 1)
                pins[name.strip().lower()] = version.strip()
    return pins


def test_every_dependency_is_pinned_exactly():
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as fh:
        lines = [line.split("#", 1)[0].strip() for line in fh]
    requirements = [line for line in lines if line]
    assert requirements and all("==" in line for line in requirements), requirements


@pytest.mark.parametrize(
    "component",
    ["backend/requirements.txt", "frontend/requirements.txt", "ai_engine/requirements.txt"],
)
def test_component_requirements_agree_with_the_root(component):
    root, sub = _pins("requirements.txt"), _pins(component)
    assert sub, component
    assert {name: root.get(name) for name in sub} == sub

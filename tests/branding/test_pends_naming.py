"""Branding-consistency regression tests.

These lock in the project rename to ``pends``: they fail if any legacy
brand token (the original name or the interim swap that briefly replaced it)
leaks back into tracked files, or if the renamed package/CLI paths regress.

The scanner intentionally skips its own directory, ``.git``, caches, and
binary assets. Legacy needles are assembled from fragments so this file does
not match its own assertions.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_DIR = Path(__file__).resolve().parent

# Assembled from fragments so this test file is not itself a match.
LEGACY_STRING = "vio" + "lin"
LEGACY_INTERIM = "Dark" + "DeepSeek"
LEGACY_NEEDLES = (LEGACY_STRING, LEGACY_INTERIM)

# Legacy package/CLI names, also assembled from fragments.
LEGACY_PKG_DIR = LEGACY_STRING + "_guard"
LEGACY_CLI = LEGACY_PKG_DIR + ".py"

# Only scan human-authored text; skip binaries and vendored noise.
TEXT_SUFFIXES = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".sh", ".ps1",
    ".json", ".txt", ".cfg", ".ini", ".lock", ".gitignore",
}
SKIP_DIR_NAMES = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv"}


def _tracked_text_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if SELF_DIR in path.parents:
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".gitignore"}:
            continue
        files.append(path)
    return files


@pytest.mark.parametrize("needle", LEGACY_NEEDLES)
def test_no_legacy_brand_tokens_in_contents(needle: str) -> None:
    """No tracked text file may contain a legacy brand token (case-insensitive)."""
    offenders: list[str] = []
    lowered = needle.lower()
    for path in _tracked_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if lowered in text.lower():
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"legacy token {needle!r} found in: {offenders}"


def test_no_legacy_brand_tokens_in_paths() -> None:
    """No file or directory name may contain a legacy brand token."""
    offenders: list[str] = []
    for path in REPO_ROOT.rglob("*"):
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if SELF_DIR in path.parents:
            continue
        name = path.name.lower()
        if any(n.lower() in name for n in LEGACY_NEEDLES):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"legacy token in path names: {offenders}"


def test_pends_guard_package_importable() -> None:
    """The renamed guard package imports under its new name."""
    module = importlib.import_module("plugins.pends_guard")
    assert module.__name__ == "plugins.pends_guard"


def test_renamed_paths_present_and_legacy_absent() -> None:
    """New package/CLI paths exist; legacy ones are gone."""
    assert (REPO_ROOT / "plugins" / "pends_guard").is_dir()
    assert (REPO_ROOT / "scripts" / "pends_guard.py").is_file()
    assert not (REPO_ROOT / "plugins" / LEGACY_PKG_DIR).exists()
    assert not (REPO_ROOT / "scripts" / LEGACY_CLI).exists()


def test_pyproject_name_is_pends() -> None:
    """Distribution name is the new brand."""
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["name"] == "pends"

import pytest

from importlib import metadata


def _import_cli(monkeypatch):
    """Import cli module with patched metadata.version"""
    monkeypatch.setattr(metadata, "version", lambda name: "0.0.0")
    from wafmap.cli import normalize_url
    return normalize_url


def test_normalize_url_scheme_added(monkeypatch):
    normalize_url = _import_cli(monkeypatch)
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_preserves_scheme(monkeypatch):
    normalize_url = _import_cli(monkeypatch)
    assert normalize_url("http://example.com") == "http://example.com"



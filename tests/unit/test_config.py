import importlib

import pytest

import core.config as config


def test_get_bool_true_variants(monkeypatch):
    for value in ["1", "true", "yes", "on", " TRUE "]:
        monkeypatch.setenv("TEST_BOOL", value)
        assert config._get_bool("TEST_BOOL", False) is True


def test_get_bool_false_variants(monkeypatch):
    for value in ["0", "false", "no", "off", " FALSE "]:
        monkeypatch.setenv("TEST_BOOL", value)
        assert config._get_bool("TEST_BOOL", True) is False


def test_get_bool_invalid(monkeypatch):
    monkeypatch.setenv("TEST_BOOL", "maybe")
    with pytest.raises(ValueError):
        config._get_bool("TEST_BOOL", True)


def test_get_int_default(monkeypatch):
    monkeypatch.delenv("TEST_INT", raising=False)
    assert config._get_int("TEST_INT", 7) == 7


def test_load_settings(monkeypatch):
    monkeypatch.setenv("MITMPROXY_MCP_PROXY_HOST", "0.0.0.0")
    monkeypatch.setenv("MITMPROXY_MCP_PROXY_PORT", "9000")
    monkeypatch.setenv("MITMPROXY_MCP_REDACT_HEADERS", "false")
    loaded = config.load_settings()
    assert loaded.proxy_host == "0.0.0.0"
    assert loaded.proxy_port == 9000
    assert loaded.redact_headers is False


def test_module_settings_loads(monkeypatch):
    monkeypatch.setenv("MITMPROXY_MCP_MCP_TRANSPORT", "sse")
    reloaded = importlib.reload(config)
    assert reloaded.settings.mcp_transport == "sse"

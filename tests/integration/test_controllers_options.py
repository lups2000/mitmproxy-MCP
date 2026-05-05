import pytest

from core.controllers.mitmproxy_controller import MitmproxyController


def test_option_commands_require_running_mitmproxy():
    controller = MitmproxyController()

    with pytest.raises(RuntimeError):
        controller.list_options()

    with pytest.raises(RuntimeError):
        controller.get_option("intercept")

    with pytest.raises(RuntimeError):
        controller.set_option("intercept", "~u example.com")


def test_list_options_filters_real_runtime_options(integration_env):
    result = integration_env.controller.list_options("intercept")
    names = {item["name"] for item in result}

    assert "intercept" in names
    assert "intercept_active" in names


def test_get_option_reads_real_runtime_metadata(integration_env):
    result = integration_env.controller.get_option("intercept")

    assert result["name"] == "intercept"
    assert result["type"] == "optional str"
    assert "help" in result


def test_get_option_rejects_unknown_names(integration_env):
    with pytest.raises(ValueError):
        integration_env.controller.get_option("does_not_exist")


def test_set_option_supports_string_bool_int_list_and_none(integration_env):
    string_result = integration_env.controller.set_option("intercept", "~u example.com")
    bool_result = integration_env.controller.set_option("intercept_active", True)
    int_result = integration_env.controller.set_option("key_size", 4096)
    list_result = integration_env.controller.set_option("tcp_hosts", ["example.com"])
    none_result = integration_env.controller.set_option("intercept", None)

    assert string_result["value"] == "~u example.com"
    assert bool_result["value"] is True
    assert int_result["value"] == 4096
    assert list_result["value"] == ["example.com"]
    assert none_result["value"] is None
    assert integration_env.master.options.intercept is None


def test_set_option_rejects_blocked_unknown_and_invalid_values(integration_env):
    with pytest.raises(ValueError):
        integration_env.controller.set_option("listen_port", 9999)

    with pytest.raises(ValueError):
        integration_env.controller.set_option("unknown_option", "x")

    with pytest.raises(ValueError):
        integration_env.controller.set_option("intercept", {"bad": "type"})

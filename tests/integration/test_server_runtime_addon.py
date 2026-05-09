import asyncio
from types import SimpleNamespace

import pytest
from mitmproxy.test import tflow

from core.addon import MCPFlowCaptureAddon
from core.runtime import run_mitmproxy
from core.server import SUPPORTED_TRANSPORTS, _validate_transport, main, run_transport_async
from tests.helpers import make_http_flow


def test_validate_transport():
    for transport in SUPPORTED_TRANSPORTS:
        _validate_transport(transport)

    with pytest.raises(ValueError):
        _validate_transport("bad")


def test_run_transport_async_dispatches_to_selected_transport(monkeypatch):
    called = []

    async def streamable():
        called.append("streamable")

    async def sse():
        called.append("sse")

    monkeypatch.setattr("core.server.mcp.run_streamable_http_async", streamable)
    monkeypatch.setattr("core.server.mcp.run_sse_async", sse)

    asyncio.run(run_transport_async("streamable-http"))
    asyncio.run(run_transport_async("sse"))

    assert called == ["streamable", "sse"]


def test_server_main_raises():
    with pytest.raises(RuntimeError):
        main()


def test_addon_load_registers_expected_options():
    class DummyLoader:
        def __init__(self) -> None:
            self.options = []

        def add_option(self, *args, **kwargs) -> None:
            self.options.append((args, kwargs))

    addon = MCPFlowCaptureAddon()
    loader = DummyLoader()

    addon.load(loader)

    assert len(loader.options) == 3


def test_read_and_mark_tools_follow_real_projection_state(addon_env, mcp_tools):
    flow = tflow.tflow(resp=True)
    addon_env.view.add([flow])

    assert len(mcp_tools["list_captured_flows"]()) == 1
    assert mcp_tools["get_captured_flow"](flow.id)["id"] == flow.id
    assert mcp_tools["get_flow_count"]()["count"] == 1
    assert mcp_tools["get_intercepted_flows"]() == []

    mark_result = mcp_tools["mark_flow"](flow.id, "blue")
    comment_result = mcp_tools["comment_flow"](flow.id, "note")
    marked_list = mcp_tools["list_marked_flows"]()
    unmark_result = mcp_tools["unmark_flow"](flow.id)

    assert mark_result["marker"] == ":large_blue_circle:"
    assert comment_result["comment"] == "note"
    assert len(marked_list) == 1
    assert marked_list[0]["marker"] == ":large_blue_circle:"
    assert unmark_result == {"flow_id": flow.id, "marked": False, "marker": None}


def test_diff_tool_compares_redacted_flow_projection(addon_env, mcp_tools):
    left = make_http_flow(url="https://example.com/items", method="GET", status_code=200)
    right = make_http_flow(
        url="https://example.com/items?foo=1&token=secret",
        method="POST",
        status_code=500,
        reason="Server Error",
        marked=":red_circle:",
        comment="review me",
        intercepted=True,
        error_message="boom",
    )
    addon_env.view.add([left, right])

    result = mcp_tools["diff_flows"](left.id, right.id)

    assert result["left_flow_id"] == left.id
    assert result["right_flow_id"] == right.id
    assert result["different"] is True
    assert result["differences"]["method"] == {"left": "GET", "right": "POST"}
    assert result["differences"]["status_code"] == {"left": 200, "right": 500}
    assert result["differences"]["marker"] == {"left": None, "right": ":red_circle:"}


def test_control_and_option_tools_update_real_runtime(addon_env, mcp_tools):
    flow1 = tflow.tflow(resp=True)
    flow2 = tflow.tflow(resp=True)
    flow1.intercept()
    flow2.intercept()
    addon_env.view.add([flow1, flow2])

    option_list = mcp_tools["list_options"]("intercept")
    option_detail = mcp_tools["get_option"]("intercept")
    set_option_result = mcp_tools["set_option"]("intercept_active", True)
    intercept_result = mcp_tools["set_intercept"]("~u example.com", True)
    intercepted_flows = mcp_tools["get_intercepted_flows"]()
    resume_one = mcp_tools["resume_flow"](flow1.id)
    resume_all = mcp_tools["resume_all"]()
    disable_result = mcp_tools["set_intercept"]("", False)

    assert any(item["name"] == "intercept" for item in option_list)
    assert option_detail["name"] == "intercept"
    assert set_option_result["value"] is True
    assert intercept_result["active"] is True
    assert {item["id"] for item in intercepted_flows} == {flow1.id, flow2.id}
    assert resume_one["resumed"] is True
    assert resume_all["resumed_count"] == 1
    assert disable_result["active"] is False


def test_transfer_tools_change_real_view_and_projection(addon_env, mcp_tools, tmp_path):
    flow = tflow.tflow(resp=True)
    addon_env.view.add([flow])

    duplicate_result = mcp_tools["duplicate_flow"](flow.id)
    assert duplicate_result["duplicated"] is True
    assert mcp_tools["get_flow_count"]()["count"] == 2

    export_path = str(tmp_path / "flows.flow")
    export_result = mcp_tools["export_flows"](export_path)
    assert export_result["path"] == export_path
    assert export_result["exported_count"] == 2

    delete_result = mcp_tools["delete_flow"](flow.id)
    assert delete_result == {"flow_id": flow.id, "deleted": True}

    clear_result = mcp_tools["clear_captured_flows"]()
    assert clear_result["deleted_count"] == 1
    assert mcp_tools["list_captured_flows"]() == []

    import_result = mcp_tools["import_flows"](export_path)
    assert import_result["path"] == export_path
    assert import_result["imported_count"] >= 1
    assert len(mcp_tools["list_captured_flows"]()) >= 1


def test_revert_and_kill_tools_behave_like_mitmproxy(addon_env, mcp_tools):
    flow = tflow.tflow(resp=True)
    addon_env.view.add([flow])
    flow.backup()
    addon_env.master.commands.call("flow.set", [flow], "method", "POST")

    revert_result = mcp_tools["revert_flow"](flow.id)
    assert revert_result == {"flow_id": flow.id, "reverted": True}

    flow.intercept()
    addon_env.addon._handle_view_update(flow)
    kill_result = mcp_tools["kill_flow"](flow.id)

    assert kill_result["killed"] is True
    assert kill_result["error_message"] == "Connection killed."


def test_addon_signal_handlers_sync_add_update_remove_and_refresh(addon_env, mcp_tools):
    flow = tflow.tflow(resp=True)
    addon_env.addon._handle_view_add(flow)
    assert mcp_tools["get_flow_count"]()["count"] == 1

    flow.comment = "updated"
    addon_env.addon._handle_view_update(flow)
    assert mcp_tools["get_captured_flow"](flow.id)["comment"] == "updated"

    addon_env.addon._handle_view_remove(flow, 0)
    assert mcp_tools["get_flow_count"]()["count"] == 0

    addon_env.addon._handle_view_add(flow)
    addon_env.addon._handle_store_remove(flow)
    assert mcp_tools["get_flow_count"]()["count"] == 0

    addon_env.view.add([flow])
    addon_env.addon._handle_view_refresh()
    addon_env.addon._handle_store_refresh()
    assert mcp_tools["get_flow_count"]()["count"] == 1


def test_addon_sync_from_empty_view_clears_projection(addon_env, mcp_tools):
    addon_env.addon._disconnect_view_signals()
    addon_env.addon._sync_from_mitmproxy_view()
    assert mcp_tools["list_captured_flows"]() == []


def test_addon_running_is_idempotent(addon_env):
    existing = addon_env.addon._mcp_thread
    addon_env.addon.running()
    assert addon_env.addon._mcp_thread is existing


def test_addon_handlers_ignore_non_http_flows(addon_env, mcp_tools):
    class DummyFlow:
        id = "dummy"

    dummy = DummyFlow()

    addon_env.addon._handle_view_add(dummy)
    addon_env.addon._handle_view_update(dummy)
    assert mcp_tools["list_captured_flows"]() == []

    addon_env.addon._handle_view_remove(dummy, 0)
    addon_env.addon._handle_store_remove(dummy)
    assert mcp_tools["list_captured_flows"]() == []


def test_run_mitmproxy_builds_master_and_applies_settings(monkeypatch):
    events = []

    class DummyAddons:
        def add(self, *addons):
            events.append(("addons", len(addons)))

    class DummyOptions:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class DummyMaster:
        def __init__(self, opts, with_termlog, with_dumper):
            events.append(("init", opts.kwargs, with_termlog, with_dumper))
            self.addons = DummyAddons()
            self.options = SimpleNamespace(update=lambda **kwargs: events.append(("update", kwargs)))

        async def run(self):
            events.append(("run", None))

    monkeypatch.setattr("core.runtime.options.Options", DummyOptions)
    monkeypatch.setattr("core.runtime.DumpMaster", DummyMaster)
    monkeypatch.setattr("core.runtime.mitm_addons", [object()])
    monkeypatch.setattr(
        "core.runtime.settings",
        SimpleNamespace(
            proxy_host="127.0.0.1",
            proxy_port=8080,
            mcp_host="127.0.0.1",
            mcp_port=8000,
            mcp_transport="streamable-http",
        ),
    )

    asyncio.run(run_mitmproxy())

    assert [event[0] for event in events] == ["init", "addons", "update", "run"]

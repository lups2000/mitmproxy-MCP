import os

import pytest
from mitmproxy.test import tflow


def test_replay_flow_uses_real_mitmproxy_replay(integration_env):
    flow = tflow.tflow(resp=True)
    flow.live = False
    integration_env.view.add([flow])

    result = integration_env.controller.replay_flow(flow.id)

    assert result == {"flow_id": flow.id, "queued": True}
    assert flow.is_replay == "request"


def test_marker_and_comment_change_real_flow_state(integration_env):
    flow = tflow.tflow(resp=True)
    integration_env.view.add([flow])

    marker_result = integration_env.controller.set_flow_marker(flow.id, ":red_circle:")
    comment_result = integration_env.controller.set_flow_comment(flow.id, "hello")

    assert marker_result == {"flow_id": flow.id, "marked": True, "marker": ":red_circle:"}
    assert comment_result == {"flow_id": flow.id, "comment": "hello"}
    assert flow.marked == ":red_circle:"
    assert flow.comment == "hello"


def test_set_intercept_resume_and_resume_all_flow_through_real_view(integration_env):
    flow1 = tflow.tflow(resp=True)
    flow2 = tflow.tflow(resp=True)
    flow1.intercept()
    flow2.intercept()
    integration_env.view.add([flow1, flow2])

    intercept_result = integration_env.controller.set_intercept("~u example.com", True)
    single_resume = integration_env.controller.resume_flow(flow1.id)
    bulk_resume = integration_env.controller.resume_all_flows()
    disable_result = integration_env.controller.set_intercept("", False)

    assert intercept_result["active"] is True
    assert intercept_result["filter"] == "~u example.com"
    assert single_resume == {"flow_id": flow1.id, "resumed": True, "intercepted": False}
    assert bulk_resume["resumed_count"] == 1
    assert disable_result["active"] is False
    assert disable_result["filter"] is None


def test_resume_non_intercepted_flow_reports_false(integration_env):
    flow = tflow.tflow(resp=True)
    integration_env.view.add([flow])

    result = integration_env.controller.resume_flow(flow.id)

    assert result == {"flow_id": flow.id, "resumed": False, "intercepted": False}


def test_kill_flow_marks_connection_killed(integration_env):
    flow = tflow.tflow(resp=True)
    flow.intercept()
    integration_env.view.add([flow])

    result = integration_env.controller.kill_flow(flow.id)

    assert result["killed"] is True
    assert result["intercepted"] is False
    assert result["error_message"] == "Connection killed."


def test_revert_flow_tracks_modified_and_unmodified_cases(integration_env):
    flow = tflow.tflow(resp=True)
    integration_env.view.add([flow])

    unchanged = integration_env.controller.revert_flow(flow.id)
    flow.backup()
    integration_env.master.commands.call("flow.set", [flow], "method", "POST")
    reverted = integration_env.controller.revert_flow(flow.id)

    assert unchanged == {"flow_id": flow.id, "reverted": False}
    assert reverted == {"flow_id": flow.id, "reverted": True}
    assert flow.request.method == "GET"


def test_duplicate_delete_and_clear_change_real_view(integration_env):
    flow1 = tflow.tflow(resp=True)
    flow2 = tflow.tflow(resp=True)
    integration_env.view.add([flow1, flow2])

    duplicate = integration_env.controller.duplicate_flow(flow1.id)
    flows_after_duplicate = integration_env.master.commands.call("view.flows.resolve", "@all")
    deleted = integration_env.controller.delete_flow(flow1.id)
    flows_after_delete = integration_env.master.commands.call("view.flows.resolve", "@all")
    cleared = integration_env.controller.clear_flows()
    flows_after_clear = integration_env.master.commands.call("view.flows.resolve", "@all")

    assert duplicate["source_flow_id"] == flow1.id
    assert duplicate["duplicated"] is True
    assert duplicate["duplicated_flow_id"] in {flow.id for flow in flows_after_duplicate}
    assert len(flows_after_duplicate) == 3

    assert deleted == {"flow_id": flow1.id, "deleted": True}
    assert flow1.id not in {flow.id for flow in flows_after_delete}

    assert cleared["deleted_count"] == len(flows_after_delete)
    assert flows_after_clear == []


def test_import_and_export_flows_round_trip_real_view(tmp_path, integration_env):
    original = tflow.tflow(resp=True)
    integration_env.view.add([original])

    dump_path = os.path.join(tmp_path, "flows.flow")
    har_path = os.path.join(tmp_path, "flows.har")

    export_dump = integration_env.controller.export_flows(dump_path)
    assert export_dump == {"path": dump_path, "format": "mitmproxy", "exported_count": 1}

    clear_result = integration_env.controller.clear_flows()
    assert clear_result["deleted_count"] == 1

    import_result = integration_env.controller.import_flows(dump_path)
    assert import_result["path"] == dump_path
    assert import_result["imported_count"] >= 1
    assert import_result["skipped_count"] == 0

    export_har = integration_env.controller.export_flows(har_path)
    assert export_har["path"] == har_path
    assert export_har["format"] == "har"
    assert export_har["exported_count"] >= 1


def test_import_flows_failure_raises_value_error(integration_env):
    with pytest.raises(ValueError):
        integration_env.controller.import_flows("/does/not/exist.flow")


def test_flow_commands_reject_unknown_flow_ids(integration_env):
    for operation in (
        integration_env.controller.replay_flow,
        lambda flow_id: integration_env.controller.set_flow_marker(flow_id, ":red_circle:"),
        lambda flow_id: integration_env.controller.set_flow_comment(flow_id, "note"),
        integration_env.controller.resume_flow,
        integration_env.controller.kill_flow,
        integration_env.controller.revert_flow,
        integration_env.controller.delete_flow,
        integration_env.controller.duplicate_flow,
    ):
        with pytest.raises(ValueError):
            operation("missing-id")

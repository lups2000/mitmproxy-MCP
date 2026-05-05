from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
from mitmproxy.addons import clientplayback
from mitmproxy.addons import comment
from mitmproxy.addons import intercept
from mitmproxy.addons import save
from mitmproxy.addons import savehar
from mitmproxy.addons import view
from mitmproxy.test import taddons

from core.addon import MCPFlowCaptureAddon
from core.controllers import mitmproxy_controller
from core.server import mcp
from core.store import flow_projection_store
from tests.helpers import make_http_flow


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_flow():
    return make_http_flow(
        request_body=b'{"password":"secret","safe":"ok"}',
        response_body=b'{"token":"secret","safe":"ok"}',
    )


@pytest.fixture
def integration_env(monkeypatch):
    with taddons.context(
        view.View(),
        comment.Comment(),
        intercept.Intercept(),
        clientplayback.ClientPlayback(),
        save.Save(),
        savehar.SaveHar(),
    ) as tctx:
        monkeypatch.setattr(tctx.master.event_loop, "call_soon_threadsafe", lambda cb, *args: cb(*args))
        mitmproxy_controller.attach_master(tctx.master)
        yield SimpleNamespace(
            tctx=tctx,
            master=tctx.master,
            view=tctx.master.addons.get("view"),
            controller=mitmproxy_controller,
        )
        mitmproxy_controller.detach_master()


@pytest.fixture
def addon_env(monkeypatch):
    addon = MCPFlowCaptureAddon()

    class DummyThread:
        def __init__(self, target=None, args=(), name=None, daemon=None):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr("core.addon.threading.Thread", DummyThread)
    monkeypatch.setattr(addon, "_run_mcp_server", lambda transport: None)

    with taddons.context(
        view.View(),
        comment.Comment(),
        intercept.Intercept(),
        clientplayback.ClientPlayback(),
        save.Save(),
        savehar.SaveHar(),
        addon,
    ) as tctx:
        monkeypatch.setattr(tctx.master.event_loop, "call_soon_threadsafe", lambda cb, *args: cb(*args))
        flow_projection_store.replace_from_mitmproxy_flows([])
        addon.running()
        yield SimpleNamespace(
            tctx=tctx,
            master=tctx.master,
            view=tctx.master.addons.get("view"),
            addon=addon,
            controller=mitmproxy_controller,
        )
        addon.done()
        flow_projection_store.replace_from_mitmproxy_flows([])


@pytest.fixture
def mcp_tools():
    return {name: tool.fn for name, tool in mcp._tool_manager._tools.items()}

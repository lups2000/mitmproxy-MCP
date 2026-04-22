from __future__ import annotations

from concurrent.futures import Future
from collections.abc import Sequence
from typing import Any
from typing import cast

from mitmproxy import flow as mitm_flow
from mitmproxy import http
from mitmproxy.master import Master


class MitmproxyController:
    def __init__(self) -> None:
        self._master: Master | None = None

    def attach_master(self, master: Master) -> None:
        self._master = master

    def detach_master(self) -> None:
        self._master = None

    def replay_flow(self, flow: http.HTTPFlow) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _enqueue_replay() -> None:
            try:
                replay_flow = flow.copy()
                master.commands.call("replay.client", [replay_flow])
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "replay_flow_id": replay_flow.id,
                        "queued": True,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_enqueue_replay)
        return result.result(timeout=5)

    def set_flow_marker(self, flow_id: str, marker: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _set_mark() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                master.commands.call("flow.mark", [flow], marker)
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "marked": bool(flow.marked),
                        "marker": flow.marked or None,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_set_mark)
        return result.result(timeout=5)

    def _require_master(self) -> Master:
        if self._master is None:
            raise RuntimeError("mitmproxy is not running, so active flow commands are unavailable.")

        return self._master

    def _resolve_http_flow(self, master: Master, flow_id: str) -> http.HTTPFlow:
        flows = cast(Sequence[mitm_flow.Flow], master.commands.call("view.flows.resolve", f"@{flow_id}"))
        if not flows:
            raise ValueError(f"Unknown flow_id: {flow_id}")

        flow = flows[0]
        if not isinstance(flow, http.HTTPFlow):
            raise ValueError(f"Flow is not an HTTP flow: {flow_id}")

        return flow


mitmproxy_controller = MitmproxyController()

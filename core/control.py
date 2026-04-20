from __future__ import annotations

from concurrent.futures import Future
from typing import Any

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

    def _require_master(self) -> Master:
        if self._master is None:
            raise RuntimeError("mitmproxy is not running, so active flow commands are unavailable.")

        return self._master


mitmproxy_controller = MitmproxyController()

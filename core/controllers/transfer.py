from __future__ import annotations

import os
from concurrent.futures import Future
from typing import Any

from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import io as mitm_io


class TransferController:
    def import_flows(self, path: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _import_flows() -> None:
            try:
                expanded_path = os.path.expanduser(path)
                view = master.addons.get("view")
                if view is None:
                    raise RuntimeError("mitmproxy view addon is unavailable, so flow import cannot run.")

                imported_count = 0
                skipped_count = 0

                with open(expanded_path, "rb") as flow_file:
                    for imported_flow in mitm_io.FlowReader(flow_file).stream():
                        if isinstance(imported_flow, http.HTTPFlow):
                            view.add([imported_flow.copy()])
                            imported_count += 1
                        else:
                            skipped_count += 1

                result.set_result(
                    {
                        "path": expanded_path,
                        "imported_count": imported_count,
                        "skipped_count": skipped_count,
                    }
                )
            except (OSError, exceptions.FlowReadException) as exc:
                result.set_exception(ValueError(f"Failed to import flows from '{path}': {exc}"))
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_import_flows)
        return result.result(timeout=30)

    def export_flows(self, path: str, flow_spec: str = "@all") -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _export_flows() -> None:
            try:
                expanded_path = os.path.expanduser(path)
                flows = self._resolve_http_flows(master, flow_spec)

                if expanded_path.lower().endswith((".har", ".zhar")):
                    master.commands.call("save.har", flows, expanded_path)
                    export_format = "zhar" if expanded_path.lower().endswith(".zhar") else "har"
                else:
                    master.commands.call("save.file", flows, expanded_path)
                    export_format = "mitmproxy"

                result.set_result(
                    {
                        "path": expanded_path,
                        "format": export_format,
                        "exported_count": len(flows),
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_export_flows)
        return result.result(timeout=30)

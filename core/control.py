from __future__ import annotations

import os
from concurrent.futures import Future
from collections.abc import Sequence
from typing import Any
from typing import cast

from mitmproxy import exceptions
from mitmproxy import flow as mitm_flow
from mitmproxy import http
from mitmproxy import io as mitm_io
from mitmproxy import optmanager
from mitmproxy.master import Master


class MitmproxyController:
    _SET_OPTION_BLACKLIST = {
        "mode",
        "listen_host",
        "listen_port",
        "confdir",
        "certs",
        "cert_passphrase",
        "client_certs",
        "ssl_insecure",
        "ssl_verify_upstream_trusted_ca",
        "ssl_verify_upstream_trusted_confdir",
        "allow_hosts",
        "ignore_hosts",
    }

    def __init__(self) -> None:
        self._master: Master | None = None

    def attach_master(self, master: Master) -> None:
        self._master = master

    def detach_master(self) -> None:
        self._master = None

    def replay_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _enqueue_replay() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                master.commands.call("replay.client", [flow])
                result.set_result(
                    {
                        "flow_id": flow.id,
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

    def set_flow_comment(self, flow_id: str, comment: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _set_comment() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                master.commands.call("flow.comment", [flow], comment)
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "comment": flow.comment,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_set_comment)
        return result.result(timeout=5)

    def set_intercept(self, flow_filter: str, active: bool = True) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _set_intercept() -> None:
            try:
                if active:
                    master.commands.call("set", "intercept", flow_filter)
                    master.commands.call("set", "intercept_active", "true")
                else:
                    master.commands.call("set", "intercept_active", "false")
                    master.commands.call("set", "intercept")

                result.set_result(
                    {
                        "active": bool(master.options.intercept_active),
                        "filter": master.options.intercept,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_set_intercept)
        return result.result(timeout=5)

    def list_options(self, search: str | None = None) -> list[dict[str, Any]]:
        master = self._require_master()
        result: Future[list[dict[str, Any]]] = Future()

        def _list_options() -> None:
            try:
                keys = list(master.options.keys())
                if search:
                    normalized_search = search.lower()
                    keys = [key for key in keys if normalized_search in key.lower()]

                dumped = optmanager.dump_dicts(master.options, keys)
                result.set_result(
                    [
                        {
                            "name": name,
                            "type": metadata["type"],
                            "default": metadata["default"],
                            "value": metadata["value"],
                            "help": metadata["help"],
                            "choices": metadata["choices"],
                        }
                        for name, metadata in dumped.items()
                    ]
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_list_options)
        return result.result(timeout=5)

    def get_option(self, name: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _get_option() -> None:
            try:
                if name not in master.options.keys():
                    raise ValueError(f"Unknown option: {name}")

                metadata = optmanager.dump_dicts(master.options, [name])[name]
                result.set_result(
                    {
                        "name": name,
                        "type": metadata["type"],
                        "default": metadata["default"],
                        "value": metadata["value"],
                        "help": metadata["help"],
                        "choices": metadata["choices"],
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_get_option)
        return result.result(timeout=5)

    def set_option(self, name: str, value: Any) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _set_option() -> None:
            try:
                if name not in master.options.keys():
                    raise ValueError(f"Unknown option: {name}")

                if name in self._SET_OPTION_BLACKLIST:
                    raise ValueError(f"Setting option '{name}' is not allowed through MCP.")

                specs = self._build_option_specs(name, value)
                master.options.set(*specs)

                metadata = optmanager.dump_dicts(master.options, [name])[name]
                result.set_result(
                    {
                        "name": name,
                        "type": metadata["type"],
                        "default": metadata["default"],
                        "value": metadata["value"],
                        "help": metadata["help"],
                        "choices": metadata["choices"],
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_set_option)
        return result.result(timeout=5)

    def resume_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _resume_flow() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                was_intercepted = flow.intercepted
                master.commands.call("flow.resume", [flow])
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "resumed": was_intercepted and not flow.intercepted,
                        "intercepted": flow.intercepted,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_resume_flow)
        return result.result(timeout=5)

    def resume_all_flows(self) -> dict[str, int]:
        master = self._require_master()
        result: Future[dict[str, int]] = Future()

        def _resume_all_flows() -> None:
            try:
                flows = self._resolve_http_flows(master, "@all")
                intercepted_flows = [flow for flow in flows if flow.intercepted]
                master.commands.call("flow.resume", intercepted_flows)
                resumed_count = sum(1 for flow in intercepted_flows if not flow.intercepted)
                result.set_result({"resumed_count": resumed_count})
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_resume_all_flows)
        return result.result(timeout=5)

    def kill_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _kill_flow() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                was_intercepted = flow.intercepted
                master.commands.call("flow.kill", [flow])
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "killed": was_intercepted and flow.error is not None,
                        "intercepted": flow.intercepted,
                        "error_message": flow.error.msg if flow.error is not None else None,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_kill_flow)
        return result.result(timeout=5)

    def revert_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _revert_flow() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                was_modified = flow.modified()
                master.commands.call("flow.revert", [flow])
                result.set_result(
                    {
                        "flow_id": flow.id,
                        "reverted": was_modified and not flow.modified(),
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_revert_flow)
        return result.result(timeout=5)

    def clear_flows(self) -> dict[str, int]:
        master = self._require_master()
        result: Future[dict[str, int]] = Future()

        def _clear_flows() -> None:
            try:
                flows = cast(Sequence[mitm_flow.Flow], master.commands.call("view.flows.resolve", "@all"))
                deleted_count = sum(1 for flow in flows if isinstance(flow, http.HTTPFlow))
                master.commands.call("view.clear")
                result.set_result({"deleted_count": deleted_count})
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_clear_flows)
        return result.result(timeout=5)

    def delete_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _delete_flow() -> None:
            try:
                flow = self._resolve_http_flow(master, flow_id)
                master.commands.call("view.flows.remove", [flow])
                result.set_result({"flow_id": flow_id, "deleted": True})
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_delete_flow)
        return result.result(timeout=5)

    def duplicate_flow(self, flow_id: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _duplicate_flow() -> None:
            try:
                before_flow_ids = {flow.id for flow in self._resolve_http_flows(master, "@all")}
                flow = self._resolve_http_flow(master, flow_id)
                master.commands.call("view.flows.duplicate", [flow])
                after_flows = self._resolve_http_flows(master, "@all")
                duplicated_flow_ids = [flow.id for flow in after_flows if flow.id not in before_flow_ids]
                duplicated_flow_id = duplicated_flow_ids[0] if duplicated_flow_ids else None
                result.set_result(
                    {
                        "source_flow_id": flow_id,
                        "duplicated_flow_id": duplicated_flow_id,
                        "duplicated": duplicated_flow_id is not None,
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_duplicate_flow)
        return result.result(timeout=5)

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

    def _require_master(self) -> Master:
        if self._master is None:
            raise RuntimeError("mitmproxy is not running, so active flow commands are unavailable.")

        return self._master

    def _build_option_specs(self, name: str, value: Any) -> list[str]:
        if isinstance(value, bool):
            return [f"{name}={'true' if value else 'false'}"]

        if value is None:
            return [name]

        if isinstance(value, int):
            return [f"{name}={value}"]

        if isinstance(value, str):
            return [f"{name}={value}"]

        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return [f"{name}={item}" for item in value]

        raise ValueError(
            f"Unsupported value for option '{name}'. "
            "Supported value types are bool, int, str, null, and list[str]."
        )

    def _resolve_http_flow(self, master: Master, flow_id: str) -> http.HTTPFlow:
        flows = self._resolve_http_flows(master, f"@{flow_id}")
        if not flows:
            raise ValueError(f"Unknown flow_id: {flow_id}")

        return flows[0]

    def _resolve_http_flows(self, master: Master, flow_spec: str) -> list[http.HTTPFlow]:
        flows = cast(Sequence[mitm_flow.Flow], master.commands.call("view.flows.resolve", flow_spec))
        return [flow for flow in flows if isinstance(flow, http.HTTPFlow)]


mitmproxy_controller = MitmproxyController()

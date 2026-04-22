from __future__ import annotations

import asyncio
import threading

from mitmproxy import ctx
from mitmproxy import http

from .control import mitmproxy_controller
from .server import mcp
from .server import run_transport_async
from .server import SUPPORTED_TRANSPORTS

from .store import flow_store


class MCPFlowCaptureAddon:
    def __init__(self) -> None:
        self._mcp_thread: threading.Thread | None = None
        self._view = None

    def load(self, loader) -> None:
        loader.add_option("mcp_host", str, "127.0.0.1", "Host for the embedded MCP server.")
        loader.add_option("mcp_port", int, 8000, "Port for the embedded MCP server.")
        loader.add_option(
            "mcp_transport",
            str,
            "streamable-http",
            "Transport for the embedded MCP server.",
            choices=sorted(SUPPORTED_TRANSPORTS),
        )

    def running(self) -> None:
        if self._mcp_thread is not None:
            return

        transport = ctx.options.mcp_transport
        mitmproxy_controller.attach_master(ctx.master)
        self._connect_view_signals()
        self._sync_from_mitmproxy_view()
        mcp.settings.host = ctx.options.mcp_host
        mcp.settings.port = ctx.options.mcp_port

        self._mcp_thread = threading.Thread(
            target=self._run_mcp_server,
            args=(transport,),
            name="mitmproxy-mcp-server",
            daemon=True,
        )
        self._mcp_thread.start()

        ctx.log.info(f"MCP server started on {ctx.options.mcp_host}:{ctx.options.mcp_port} via {transport}")

    def response(self, flow: http.HTTPFlow) -> None:
        normalized_flow = flow_store.add_from_mitmproxy_flow(flow)
        ctx.log.info(f"Captured flow {normalized_flow.id} {normalized_flow.method} {normalized_flow.url}")

    def error(self, flow: http.HTTPFlow) -> None:
        normalized_flow = flow_store.add_from_mitmproxy_flow(flow)
        ctx.log.info(
            f"Captured errored flow {normalized_flow.id} {normalized_flow.method} {normalized_flow.url}: "
            f"{normalized_flow.error_message}"
        )

    def update(self, flows) -> None:
        for flow in flows:
            if isinstance(flow, http.HTTPFlow):
                flow_store.add_from_mitmproxy_flow(flow)

    def _run_mcp_server(self, transport: str) -> None:
        asyncio.run(run_transport_async(transport))

    def done(self) -> None:
        self._disconnect_view_signals()
        mitmproxy_controller.detach_master()

    def _connect_view_signals(self) -> None:
        view = ctx.master.addons.get("view")
        if view is None or view is self._view:
            return

        self._view = view
        view.sig_view_add.connect(self._handle_view_add)
        view.sig_view_update.connect(self._handle_view_update)
        view.sig_view_remove.connect(self._handle_view_remove)
        view.sig_view_refresh.connect(self._handle_view_refresh)
        view.sig_store_remove.connect(self._handle_store_remove)
        view.sig_store_refresh.connect(self._handle_store_refresh)

    def _disconnect_view_signals(self) -> None:
        if self._view is None:
            return

        self._view.sig_view_add.disconnect(self._handle_view_add)
        self._view.sig_view_update.disconnect(self._handle_view_update)
        self._view.sig_view_remove.disconnect(self._handle_view_remove)
        self._view.sig_view_refresh.disconnect(self._handle_view_refresh)
        self._view.sig_store_remove.disconnect(self._handle_store_remove)
        self._view.sig_store_refresh.disconnect(self._handle_store_refresh)
        self._view = None

    def _sync_from_mitmproxy_view(self) -> None:
        if self._view is None:
            flow_store.replace_from_mitmproxy_flows([])
            return

        http_flows = [flow for flow in self._view._store.values() if isinstance(flow, http.HTTPFlow)]
        flow_store.replace_from_mitmproxy_flows(http_flows)

    def _handle_view_add(self, flow) -> None:
        if isinstance(flow, http.HTTPFlow):
            flow_store.add_from_mitmproxy_flow(flow)

    def _handle_view_update(self, flow) -> None:
        if isinstance(flow, http.HTTPFlow):
            flow_store.add_from_mitmproxy_flow(flow)

    def _handle_view_remove(self, flow, index) -> None:
        flow_store.remove_flow(flow.id)

    def _handle_view_refresh(self) -> None:
        self._sync_from_mitmproxy_view()

    def _handle_store_remove(self, flow) -> None:
        flow_store.remove_flow(flow.id)

    def _handle_store_refresh(self) -> None:
        self._sync_from_mitmproxy_view()


addons = [MCPFlowCaptureAddon()]

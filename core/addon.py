from __future__ import annotations

import asyncio
import threading

from mitmproxy import ctx
from mitmproxy import http

from .server import mcp

from .store import flow_store


class MCPFlowCaptureAddon:
    def __init__(self) -> None:
        self._mcp_thread: threading.Thread | None = None

    def load(self, loader) -> None:
        loader.add_option("mcp_host", str, "127.0.0.1", "Host for the embedded MCP server.")
        loader.add_option("mcp_port", int, 8000, "Port for the embedded MCP server.")
        loader.add_option(
            "mcp_transport",
            str,
            "streamable-http",
            "Transport for the embedded MCP server.",
            choices=["streamable-http", "sse"],
        )

    def running(self) -> None:
        if self._mcp_thread is not None:
            return

        transport = ctx.options.mcp_transport
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

    def _run_mcp_server(self, transport: str) -> None:
        if transport == "streamable-http":
            asyncio.run(mcp.run_streamable_http_async())
        elif transport == "sse":
            asyncio.run(mcp.run_sse_async())
        else:
            raise ValueError(f"Unsupported MCP transport: {transport}")


addons = [MCPFlowCaptureAddon()]

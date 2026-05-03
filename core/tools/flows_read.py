from mcp.server.fastmcp import FastMCP

from ..store import flow_projection_store


def register_flow_read_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def list_captured_flows(
        limit: int = 20,
        offset: int = 0,
        error_only: bool = False,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        path_contains: str | None = None,
    ) -> list[dict]:
        """List redacted summaries of flows currently present in mitmproxy's view.

        Use this for browsing and filtering traffic before calling get_captured_flow.
        Filters are combined with AND semantics. error_only includes HTTP 4xx/5xx
        responses and mitmproxy transport errors.
        """
        return flow_projection_store.list_flows(
            limit=limit,
            offset=offset,
            marked=None,
            error_only=error_only,
            host=host,
            method=method,
            status_code=status_code,
            path_contains=path_contains,
        )

    @mcp.tool()
    def get_captured_flow(flow_id: str) -> dict | None:
        """Get one redacted flow detail by mitmproxy flow id.

        Use this after list_captured_flows when you need headers, body previews,
        error details, marker state, and request/response metadata.
        """
        return flow_projection_store.get_flow(flow_id)

    @mcp.tool()
    def get_flow_count(
        marked: bool | None = None,
        error_only: bool = False,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        path_contains: str | None = None,
    ) -> dict[str, int]:
        """Count flows currently present in mitmproxy's view.

        Supports the same main filters as list_captured_flows. Use this before
        listing when you need to understand result size or pagination.
        """
        return {
            "count": flow_projection_store.get_flow_count(
                marked=marked,
                error_only=error_only,
                host=host,
                method=method,
                status_code=status_code,
                path_contains=path_contains,
            )
        }

    @mcp.tool()
    def list_marked_flows(limit: int = 20, offset: int = 0) -> list[dict]:
        """List redacted summaries for flows with any mitmproxy marker set."""
        return flow_projection_store.list_flows(limit=limit, offset=offset, marked=True, error_only=False)

    @mcp.tool()
    def get_intercepted_flows(limit: int = 20, offset: int = 0) -> list[dict]:
        """List redacted summaries for flows that are currently intercepted."""
        return flow_projection_store.list_flows(
            limit=limit,
            offset=offset,
            marked=None,
            intercepted=True,
            error_only=False,
        )

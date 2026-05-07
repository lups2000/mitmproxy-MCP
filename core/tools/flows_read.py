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

        This reads from the MCP flow projection, which mirrors mitmproxy's current
        HTTP flow state without exposing raw unredacted objects.
        Use this for browsing traffic before calling get_captured_flow or a
        state-changing flow tool.
        Filters are combined with AND semantics. error_only includes HTTP 4xx/5xx
        responses and mitmproxy transport errors. limit and offset are for pagination.
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

        This reads from the MCP flow projection and returns detailed request,
        response, marker, comment, interception, and error information for one flow.
        Use this after list_captured_flows when you need more detail before acting.
        flow_id must be a mitmproxy flow id returned by list_captured_flows,
        list_marked_flows, get_intercepted_flows, or another flow tool result.
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

        This reads from the MCP flow projection and does not modify mitmproxy state.
        Use this before listing when you want result size, pagination planning,
        or a cheap existence check.
        It supports the same main filters as list_captured_flows, and those filters
        are combined with AND semantics.
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
        """List redacted summaries for flows with any mitmproxy marker set.

        This reads from the MCP flow projection and reflects the real marker state
        currently visible in mitmproxy and mitmweb.
        Use this after mark_flow when you want to review the current marked subset.
        limit and offset are for pagination.
        """
        return flow_projection_store.list_flows(limit=limit, offset=offset, marked=True, error_only=False)

    @mcp.tool()
    def get_intercepted_flows(limit: int = 20, offset: int = 0) -> list[dict]:
        """List redacted summaries for flows that are currently intercepted.

        This reads from the MCP flow projection and reflects real mitmproxy
        interception state.
        Use this before resume_flow, resume_all, or kill_flow when you need to
        inspect the flows that are currently paused.
        limit and offset are for pagination.
        """
        return flow_projection_store.list_flows(
            limit=limit,
            offset=offset,
            marked=None,
            intercepted=True,
            error_only=False,
        )

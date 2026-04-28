from mcp.server.fastmcp import FastMCP

from .config import settings
from .control import mitmproxy_controller
from .markers import normalize_marker
from .store import flow_projection_store

SUPPORTED_TRANSPORTS = {"sse", "streamable-http"}


mcp = FastMCP(
    "mitmproxy-mcp",
    instructions="Inspect HTTP flows captured from mitmproxy.",
    host=settings.mcp_host,
    port=settings.mcp_port,
)


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
def mark_flow(flow_id: str, marker: str = "red") -> dict:
    """Set a mitmproxy marker on a real flow.

    This updates mitmproxy state and is reflected in mitmweb. marker accepts
    color names red, orange, yellow, green, blue, purple, brown, or mitmproxy
    marker strings like :red_circle: and :large_blue_circle:.
    """
    normalized_marker = normalize_marker(marker)
    return mitmproxy_controller.set_flow_marker(flow_id, normalized_marker)


@mcp.tool()
def unmark_flow(flow_id: str) -> dict | None:
    """Remove the mitmproxy marker from a real flow."""
    return mitmproxy_controller.set_flow_marker(flow_id, "")


@mcp.tool()
def comment_flow(flow_id: str, comment: str) -> dict:
    """Set or replace the mitmproxy comment on a real flow.

    This updates mitmproxy state and is reflected in mitmweb. Pass an empty
    string to clear the existing comment.
    """
    return mitmproxy_controller.set_flow_comment(flow_id, comment)


@mcp.tool()
def clear_captured_flows() -> dict[str, int]:
    """Clear all flows from mitmproxy's real view/store.

    This is destructive and affects mitmweb too.
    """
    return mitmproxy_controller.clear_flows()


@mcp.tool()
def delete_flow(flow_id: str) -> dict:
    """Delete one flow from mitmproxy's real view/store.

    This is destructive and affects mitmweb too.
    """
    return mitmproxy_controller.delete_flow(flow_id)


@mcp.tool()
def replay_flow(flow_id: str) -> dict:
    """Replay a real flow using mitmproxy's native client replay.

    This re-sends the selected flow through mitmproxy using mitmproxy's replay
    machinery. Use duplicate_flow instead if you only want a copy in the view.
    """
    return mitmproxy_controller.replay_flow(flow_id)


@mcp.tool()
def duplicate_flow(flow_id: str) -> dict:
    """Duplicate one flow in mitmproxy's real view/store without sending it.

    The duplicate appears in mitmweb as a separate flow. Use replay_flow if
    you want to send the request again.
    """
    return mitmproxy_controller.duplicate_flow(flow_id)


async def run_transport_async(transport: str) -> None:
    _validate_transport(transport)

    if transport == "streamable-http":
        await mcp.run_streamable_http_async()
    else:
        await mcp.run_sse_async()


def _validate_transport(transport: str) -> None:
    if transport not in SUPPORTED_TRANSPORTS:
        supported = ", ".join(sorted(SUPPORTED_TRANSPORTS))
        raise ValueError(f"Unsupported MCP transport '{transport}'. Supported transports: {supported}")


def main() -> None:
    raise RuntimeError("Use mitmproxy addon mode to run this project. Standalone MCP server mode is not supported.")

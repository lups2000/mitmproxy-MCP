from mcp.server.fastmcp import FastMCP

from .config import settings
from .store import flow_store

SUPPORTED_TRANSPORTS = {"stdio", "sse", "streamable-http"}
ADDON_SUPPORTED_TRANSPORTS = {"sse", "streamable-http"}


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
    """List compact summaries for captured HTTP flows, with optional filters."""
    return flow_store.list_flows(
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
    """Fetch a full detailed flow by its mitmproxy flow id."""
    return flow_store.get_flow(flow_id)


@mcp.tool()
def get_flow_count(
    marked: bool | None = None,
    error_only: bool = False,
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    path_contains: str | None = None,
) -> dict[str, int]:
    """Count captured flows, optionally with the same filters as the list tool."""
    return {
        "count": flow_store.get_flow_count(
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
    """List only flows that have been marked."""
    return flow_store.list_flows(limit=limit, offset=offset, marked=True, error_only=False)


@mcp.tool()
def mark_flow(flow_id: str) -> dict | None:
    """Mark a flow as interesting for later investigation."""
    return flow_store.mark_flow(flow_id)


@mcp.tool()
def unmark_flow(flow_id: str) -> dict | None:
    """Remove the marked flag from a flow."""
    return flow_store.unmark_flow(flow_id)


@mcp.tool()
def clear_captured_flows() -> dict[str, int]:
    """Delete all captured flows from the local store."""
    deleted_count = flow_store.clear()
    return {"deleted_count": deleted_count}


def run_transport(transport: str) -> None:
    _validate_transport(transport, SUPPORTED_TRANSPORTS)
    mcp.run(transport=transport)


async def run_transport_async(transport: str, *, addon_mode: bool = False) -> None:
    supported_transports = ADDON_SUPPORTED_TRANSPORTS if addon_mode else SUPPORTED_TRANSPORTS
    _validate_transport(transport, supported_transports)

    if transport == "streamable-http":
        await mcp.run_streamable_http_async()
    elif transport == "sse":
        await mcp.run_sse_async()
    else:
        await mcp.run_stdio_async()


def _validate_transport(transport: str, supported_transports: set[str]) -> None:
    if transport not in supported_transports:
        supported = ", ".join(sorted(supported_transports))
        raise ValueError(f"Unsupported MCP transport '{transport}'. Supported transports: {supported}")


def main() -> None:
    run_transport(settings.mcp_transport)

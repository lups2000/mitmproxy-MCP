from mcp.server.fastmcp import FastMCP

from .config import settings
from .store import flow_store


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
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    path_contains: str | None = None,
    ) -> list[dict]:
    """List compact summaries for captured HTTP flows, with optional filters."""
    return flow_store.list_flows(
        limit=limit,
        offset=offset,
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
def get_captured_flow_request(flow_id: str) -> dict | None:
    """Fetch only the request-side view of a captured flow."""
    return flow_store.get_flow_request(flow_id)


@mcp.tool()
def get_captured_flow_response(flow_id: str) -> dict | None:
    """Fetch only the response-side view of a captured flow."""
    return flow_store.get_flow_response(flow_id)


@mcp.tool()
def clear_captured_flows() -> dict[str, int]:
    """Delete all captured flows from the local store."""
    deleted_count = flow_store.clear()
    return {"deleted_count": deleted_count}


def main() -> None:
    mcp.run(transport=settings.mcp_transport)

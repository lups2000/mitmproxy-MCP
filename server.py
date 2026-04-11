from mcp.server.fastmcp import FastMCP

from flow_store import flow_store


mcp = FastMCP("mitmproxy-mcp", instructions="Inspect HTTP flows captured from mitmproxy.")


@mcp.tool()
def list_captured_flows(limit: int = 20) -> list[dict]:
    """List the most recent captured HTTP flows."""
    return flow_store.list_flows(limit=limit)


@mcp.tool()
def get_captured_flow(flow_id: str) -> dict | None:
    """Fetch one captured flow by its mitmproxy flow id."""
    return flow_store.get_flow(flow_id)


@mcp.tool()
def clear_captured_flows() -> dict[str, int]:
    """Delete all captured flows from the local store."""
    deleted_count = flow_store.clear()
    return {"deleted_count": deleted_count}

if __name__ == "__main__":
    mcp.run()

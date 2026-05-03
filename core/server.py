from mcp.server.fastmcp import FastMCP

from .config import settings
from .tools import register_flow_control_tools
from .tools import register_flow_mark_tools
from .tools import register_flow_read_tools
from .tools import register_flow_transfer_tools
from .tools import register_option_tools

SUPPORTED_TRANSPORTS = {"sse", "streamable-http"}


mcp = FastMCP(
    "mitmproxy-mcp",
    instructions="Inspect HTTP flows captured from mitmproxy.",
    host=settings.mcp_host,
    port=settings.mcp_port,
)

register_flow_read_tools(mcp)
register_flow_mark_tools(mcp)
register_flow_control_tools(mcp)
register_flow_transfer_tools(mcp)
register_option_tools(mcp)


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

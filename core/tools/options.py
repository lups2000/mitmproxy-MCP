from mcp.server.fastmcp import FastMCP

from ..control import mitmproxy_controller


def register_option_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def list_options(search: str | None = None) -> list[dict]:
        """List mitmproxy runtime options from the real running instance.

        Use search to filter option names by substring when you are looking for
        specific areas such as intercept, mode, tls, or upstream.
        """
        return mitmproxy_controller.list_options(search)

    @mcp.tool()
    def get_option(name: str) -> dict:
        """Get one mitmproxy runtime option by exact name."""
        return mitmproxy_controller.get_option(name)

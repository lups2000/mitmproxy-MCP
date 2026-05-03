from mcp.server.fastmcp import FastMCP

from ..control import mitmproxy_controller
from ..markers import normalize_marker


def register_flow_mark_tools(mcp: FastMCP) -> None:
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

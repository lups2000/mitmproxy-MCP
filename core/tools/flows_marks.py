from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller
from ..markers import normalize_marker


def register_flow_mark_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def mark_flow(flow_id: str, marker: str = "red") -> dict:
        """Set a mitmproxy marker on one real flow.

        This changes real mitmproxy state and the result is reflected in mitmweb
        and in the MCP read tools.
        Use this when you want to visually classify or keep track of a flow.
        flow_id must be a mitmproxy flow id. marker accepts color names red,
        orange, yellow, green, blue, purple, brown, or mitmproxy marker strings
        such as :red_circle: and :large_blue_circle:.
        Use comment_flow if you want explanatory text rather than a visual marker.
        """
        normalized_marker = normalize_marker(marker)
        return mitmproxy_controller.set_flow_marker(flow_id, normalized_marker)

    @mcp.tool()
    def unmark_flow(flow_id: str) -> dict | None:
        """Remove the mitmproxy marker from one real flow.

        This changes real mitmproxy state and removes the marker from mitmweb
        and from the MCP read projection.
        Use this when a previously marked flow should no longer stand out.
        flow_id must be a mitmproxy flow id returned by a flow-listing tool.
        """
        return mitmproxy_controller.set_flow_marker(flow_id, "")

    @mcp.tool()
    def comment_flow(flow_id: str, comment: str) -> dict:
        """Set or replace the mitmproxy comment on one real flow.

        This changes real mitmproxy state and is reflected in mitmweb and in the
        MCP read tools.
        Use this when you want to attach human- or agent-readable notes to a flow.
        flow_id must be a mitmproxy flow id. Pass an empty string to clear the
        existing comment.
        Use mark_flow if you want lightweight visual categorization instead.
        """
        return mitmproxy_controller.set_flow_comment(flow_id, comment)

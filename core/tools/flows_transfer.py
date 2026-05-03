from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller


def register_flow_transfer_tools(mcp: FastMCP) -> None:
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

    @mcp.tool()
    def import_flows(path: str) -> dict:
        """Import flows from a mitmproxy flow file or HAR file into mitmproxy's real view/store.

        This loads flows into real mitmproxy state, so imported flows appear in
        mitmweb and become available through the MCP read tools as well.
        """
        return mitmproxy_controller.import_flows(path)

    @mcp.tool()
    def export_flows(path: str, flow_spec: str = "@all") -> dict:
        """Export flows from mitmproxy's real view/store into a file.

        The export format is selected from the output filename:
        .har or .zhar for HAR export, .mitm or .flow for mitmproxy flow dumps.
        flow_spec uses mitmproxy view selectors such as @all, @marked, @focus,
        or a mitmproxy filter expression.
        """
        return mitmproxy_controller.export_flows(path, flow_spec)

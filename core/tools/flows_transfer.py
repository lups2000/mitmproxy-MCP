from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller


def register_flow_transfer_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def clear_captured_flows() -> dict[str, int]:
        """Clear all flows from mitmproxy's real view/store.

        This changes real mitmproxy state, removes flows from mitmweb, and clears
        the MCP flow projection as well.
        Use this when you want to reset the current captured-flow workspace.
        This is destructive for the current in-memory flow set.
        Use delete_flow if you want to remove only one flow.
        """
        return mitmproxy_controller.clear_flows()

    @mcp.tool()
    def delete_flow(flow_id: str) -> dict:
        """Delete one flow from mitmproxy's real view/store.

        This changes real mitmproxy state, removes the flow from mitmweb, and
        removes it from the MCP flow projection.
        Use this when a single captured flow should be removed entirely.
        flow_id must be a mitmproxy flow id returned by a flow-listing tool.
        This is destructive for that flow. Use clear_captured_flows to remove all flows.
        """
        return mitmproxy_controller.delete_flow(flow_id)

    @mcp.tool()
    def replay_flow(flow_id: str) -> dict:
        """Replay one real flow using mitmproxy's native client replay.

        This changes real mitmproxy state and sends the selected request again
        through mitmproxy.
        Use this when you want to reproduce a captured request against the upstream
        destination.
        flow_id must be a mitmproxy flow id. Replay sends traffic; it does not just
        create another visible copy.
        Use duplicate_flow if you only want a second flow in the view without sending it.
        """
        return mitmproxy_controller.replay_flow(flow_id)

    @mcp.tool()
    def duplicate_flow(flow_id: str) -> dict:
        """Duplicate one flow in mitmproxy's real view/store without sending it.

        This changes real mitmproxy state by creating another visible flow in the
        view and in mitmweb, but it does not send network traffic.
        Use this when you want a second copy to inspect, mark, or later replay.
        flow_id must be a mitmproxy flow id returned by a flow-listing tool.
        Use replay_flow if you want to send the request again.
        """
        return mitmproxy_controller.duplicate_flow(flow_id)

    @mcp.tool()
    def import_flows(path: str) -> dict:
        """Import flows from a mitmproxy flow file or HAR file into mitmproxy's real view/store.

        This changes real mitmproxy state, so imported flows appear in mitmweb and
        become available through the MCP read tools.
        Use this when you want to inspect or work with historical traffic, not only
        live captured traffic.
        path should point to a readable HAR file or mitmproxy dump file on disk.
        Use export_flows if you want to save the current mitmproxy flows to disk.
        """
        return mitmproxy_controller.import_flows(path)

    @mcp.tool()
    def export_flows(path: str, flow_spec: str = "@all") -> dict:
        """Export flows from mitmproxy's real view/store into a file.

        This reads real mitmproxy flow state and writes a file to disk.
        Use this when you want to save the current flow set for later analysis,
        sharing, or re-import.
        path selects the output format by extension: .har or .zhar for HAR export,
        and .mitm or .flow for mitmproxy flow dumps.
        flow_spec uses mitmproxy selectors such as @all, @marked, @focus, or a
        mitmproxy filter expression. Use import_flows to load saved flows back in.
        """
        return mitmproxy_controller.export_flows(path, flow_spec)

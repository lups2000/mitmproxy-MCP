from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller


def register_flow_control_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def set_intercept(flow_filter: str, active: bool = True) -> dict:
        """Enable or disable mitmproxy interception using a mitmproxy filter expression.

        This changes real mitmproxy runtime state and affects how future matching
        flows are paused in mitmproxy and mitmweb.
        Use this when you want new matching flows to stop for inspection before
        resuming or killing them.
        flow_filter should be a valid mitmproxy filter such as ~u example.com,
        ~m POST, ~q, or ~s. When active is false, interception is disabled.
        """
        return mitmproxy_controller.set_intercept(flow_filter, active)

    @mcp.tool()
    def resume_flow(flow_id: str) -> dict:
        """Resume one real flow if it is currently intercepted.

        This changes real mitmproxy state and lets the paused flow continue.
        Use this when a single intercepted flow has been reviewed and should proceed.
        flow_id must identify a currently intercepted flow.
        Use resume_all if you want to continue every intercepted flow at once.
        """
        return mitmproxy_controller.resume_flow(flow_id)

    @mcp.tool()
    def resume_all() -> dict[str, int]:
        """Resume all currently intercepted HTTP flows.

        This changes real mitmproxy state and lets every paused flow continue.
        Use this when you no longer want any current interceptions to remain paused.
        This acts on the full current intercepted set, not on a filtered subset.
        Use resume_flow if you want to continue only one flow.
        """
        return mitmproxy_controller.resume_all_flows()

    @mcp.tool()
    def kill_flow(flow_id: str) -> dict:
        """Kill one real intercepted or live flow.

        This changes real mitmproxy state, terminates the flow, and usually leaves
        an error such as "Connection killed." on the flow.
        Use this when an intercepted or in-progress flow should not continue.
        flow_id must be a mitmproxy flow id. This is destructive for that flow's
        network execution. Use resume_flow if the goal is to let the flow continue.
        """
        return mitmproxy_controller.kill_flow(flow_id)

    @mcp.tool()
    def revert_flow(flow_id: str) -> dict:
        """Revert one modified real flow to its last backed-up mitmproxy state.

        This changes real mitmproxy state and is reflected in mitmweb and the MCP
        read projection.
        Use this after flow modifications when a backed-up prior state should be
        restored.
        flow_id must be a mitmproxy flow id. A flow can only be reverted if
        mitmproxy has backup state for it.
        """
        return mitmproxy_controller.revert_flow(flow_id)

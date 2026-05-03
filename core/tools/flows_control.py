from mcp.server.fastmcp import FastMCP

from ..control import mitmproxy_controller


def register_flow_control_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def set_intercept(flow_filter: str, active: bool = True) -> dict:
        """Enable or disable mitmproxy interception using a mitmproxy filter expression.

        When active is true, flow_filter should be a valid mitmproxy filter such as
        ~u example.com or ~m POST. When active is false, interception is disabled.
        """
        return mitmproxy_controller.set_intercept(flow_filter, active)

    @mcp.tool()
    def resume_flow(flow_id: str) -> dict:
        """Resume a real flow if it is currently intercepted."""
        return mitmproxy_controller.resume_flow(flow_id)

    @mcp.tool()
    def resume_all() -> dict[str, int]:
        """Resume all currently intercepted HTTP flows."""
        return mitmproxy_controller.resume_all_flows()

    @mcp.tool()
    def kill_flow(flow_id: str) -> dict:
        """Kill a real live flow if mitmproxy still considers it killable."""
        return mitmproxy_controller.kill_flow(flow_id)

    @mcp.tool()
    def revert_flow(flow_id: str) -> dict:
        """Revert a modified real flow to its last backed-up mitmproxy state."""
        return mitmproxy_controller.revert_flow(flow_id)

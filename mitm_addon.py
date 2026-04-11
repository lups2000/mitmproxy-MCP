from mitmproxy import ctx
from mitmproxy import http

from flow_store import flow_store


class MCPFlowCaptureAddon:
    def response(self, flow: http.HTTPFlow) -> None:
        normalized_flow = flow_store.add_from_mitmproxy_flow(flow)
        ctx.log.info(f"Captured flow {normalized_flow.id} {normalized_flow.method} {normalized_flow.url}")


addons = [MCPFlowCaptureAddon()]

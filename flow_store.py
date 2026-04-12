from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from mitmproxy import http


@dataclass
class NormalizedFlow:
    id: str
    timestamp: str
    method: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    http_version: str
    status_code: int | None
    response_reason: str | None
    request_content_type: str
    response_content_type: str
    request_body_size: int
    response_body_size: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body_preview: str
    response_body_preview: str


class FlowStore:
    def __init__(self, max_flows: int = 1_000) -> None:
        self.max_flows = max_flows
        self._flows: list[NormalizedFlow] = []

    def add_from_mitmproxy_flow(self, flow: http.HTTPFlow) -> NormalizedFlow:
        normalized_flow = self._normalize_flow(flow)
        self._flows.append(normalized_flow)

        if len(self._flows) > self.max_flows:
            self._flows = self._flows[-self.max_flows :]

        return normalized_flow

    def list_flows(self, limit: int = 20) -> list[dict[str, Any]]:
        return [asdict(flow) for flow in self._flows[-limit:]]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        for flow in reversed(self._flows):
            if flow.id == flow_id:
                return asdict(flow)

        return None

    def clear(self) -> int:
        deleted_count = len(self._flows)
        self._flows.clear()
        return deleted_count

    def _normalize_flow(self, flow: http.HTTPFlow) -> NormalizedFlow:
        response = flow.response

        return NormalizedFlow(
            id=flow.id,
            timestamp=datetime.now(UTC).isoformat(),
            method=flow.request.method,
            url=flow.request.pretty_url,
            scheme=flow.request.scheme,
            host=flow.request.host,
            port=flow.request.port,
            path=flow.request.path,
            query=flow.request.query.string if flow.request.query else "",
            http_version=flow.request.http_version,
            status_code=response.status_code if response else None,
            response_reason=response.reason if response else None,
            request_content_type=flow.request.headers.get("content-type", ""),
            response_content_type=response.headers.get("content-type", "") if response else "",
            request_body_size=len(flow.request.content or b""),
            response_body_size=len(response.content or b"") if response else 0,
            request_headers=dict(flow.request.headers),
            response_headers=dict(response.headers) if response else {},
            request_body_preview=_preview_bytes(flow.request.content),
            response_body_preview=_preview_bytes(response.content) if response else "",
        )


flow_store = FlowStore()


def _preview_bytes(data: bytes | None, limit: int = 200) -> str:
    if not data:
        return ""

    return data[:limit].decode("utf-8", errors="replace")

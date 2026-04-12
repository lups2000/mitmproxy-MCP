from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from mitmproxy import http

from .config import settings
from .models import FlowDetail
from .models import FlowSummary


class FlowStore:
    def __init__(self, max_flows: int = settings.max_flows) -> None:
        self.max_flows = max_flows
        self._flows: OrderedDict[str, FlowDetail] = OrderedDict()

    def add_from_mitmproxy_flow(self, flow: http.HTTPFlow) -> FlowDetail:
        flow_detail = self._normalize_flow(flow)

        # Preserve insertion order while allowing O(1) lookup by flow id.
        if flow_detail.id in self._flows:
            del self._flows[flow_detail.id]
        self._flows[flow_detail.id] = flow_detail

        if len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)

        return flow_detail

    def list_flows(self, limit: int = 20) -> list[dict[str, Any]]:
        recent_flows = list(self._flows.values())[-limit:]
        return [asdict(self._to_summary(flow)) for flow in recent_flows]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        flow = self._flows.get(flow_id)
        return asdict(flow) if flow else None

    def clear(self) -> int:
        deleted_count = len(self._flows)
        self._flows.clear()
        return deleted_count

    def _normalize_flow(self, flow: http.HTTPFlow) -> FlowDetail:
        response = flow.response

        return FlowDetail(
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

    def _to_summary(self, flow: FlowDetail) -> FlowSummary:
        return FlowSummary(
            id=flow.id,
            timestamp=flow.timestamp,
            method=flow.method,
            host=flow.host,
            path=flow.path,
            query=flow.query,
            url=flow.url,
            status_code=flow.status_code,
            response_reason=flow.response_reason,
            request_content_type=flow.request_content_type,
            response_content_type=flow.response_content_type,
            request_body_size=flow.request_body_size,
            response_body_size=flow.response_body_size,
        )


flow_store = FlowStore()


def _preview_bytes(data: bytes | None, limit: int = settings.body_preview_limit) -> str:
    if not data:
        return ""

    return data[:limit].decode("utf-8", errors="replace")

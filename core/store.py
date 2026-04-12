from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from mitmproxy import http

from .config import settings
from .models import FlowDetail
from .models import FlowSummary
from .privacy import redact_body_preview
from .privacy import redact_headers
from .privacy import redact_query_items


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

    def list_flows(
        self,
        limit: int = 20,
        offset: int = 0,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        path_contains: str | None = None,
    ) -> list[dict[str, Any]]:
        matching_flows = self._filter_flows(
            host=host,
            method=method,
            status_code=status_code,
            path_contains=path_contains,
        )
        paginated_flows = matching_flows[offset : offset + limit]
        return [asdict(self._to_summary(flow)) for flow in paginated_flows]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        flow = self._flows.get(flow_id)
        return asdict(flow) if flow else None

    def get_flow_request(self, flow_id: str) -> dict[str, Any] | None:
        flow = self._flows.get(flow_id)
        if flow is None:
            return None

        return {
            "id": flow.id,
            "timestamp": flow.timestamp,
            "method": flow.method,
            "url": flow.url,
            "scheme": flow.scheme,
            "host": flow.host,
            "port": flow.port,
            "path": flow.path,
            "query": flow.query,
            "http_version": flow.http_version,
            "content_type": flow.request_content_type,
            "body_size": flow.request_body_size,
            "headers": flow.request_headers,
            "body_preview": flow.request_body_preview,
        }

    def get_flow_response(self, flow_id: str) -> dict[str, Any] | None:
        flow = self._flows.get(flow_id)
        if flow is None:
            return None

        return {
            "id": flow.id,
            "timestamp": flow.timestamp,
            "status_code": flow.status_code,
            "reason": flow.response_reason,
            "content_type": flow.response_content_type,
            "body_size": flow.response_body_size,
            "headers": flow.response_headers,
            "body_preview": flow.response_body_preview,
        }

    def clear(self) -> int:
        deleted_count = len(self._flows)
        self._flows.clear()
        return deleted_count

    def _filter_flows(
        self,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        path_contains: str | None = None,
    ) -> list[FlowDetail]:
        normalized_method = method.upper() if method is not None else None
        matching_flows: list[FlowDetail] = []

        for flow in self._flows.values():
            if host is not None and flow.host != host:
                continue

            if normalized_method is not None and flow.method.upper() != normalized_method:
                continue

            if status_code is not None and flow.status_code != status_code:
                continue

            if path_contains is not None and path_contains not in flow.path:
                continue

            matching_flows.append(flow)

        return matching_flows

    def _normalize_flow(self, flow: http.HTTPFlow) -> FlowDetail:
        response = flow.response
        redacted_request_headers = redact_headers(dict(flow.request.headers))
        redacted_response_headers = redact_headers(dict(response.headers) if response else {})
        redacted_query_items = redact_query_items(list(flow.request.query.items(multi=True)))
        redacted_query = "&".join(f"{name}={value}" for name, value in redacted_query_items)
        redacted_url = self._build_redacted_url(flow, redacted_query)
        request_body_preview = redact_body_preview(_preview_bytes(flow.request.content))
        response_body_preview = redact_body_preview(_preview_bytes(response.content) if response else "")

        return FlowDetail(
            id=flow.id,
            timestamp=datetime.now(UTC).isoformat(),
            method=flow.request.method,
            url=redacted_url,
            scheme=flow.request.scheme,
            host=flow.request.host,
            port=flow.request.port,
            path=flow.request.path,
            query=redacted_query,
            http_version=flow.request.http_version,
            status_code=response.status_code if response else None,
            response_reason=response.reason if response else None,
            request_content_type=redacted_request_headers.get("content-type", ""),
            response_content_type=redacted_response_headers.get("content-type", ""),
            request_body_size=len(flow.request.content or b""),
            response_body_size=len(response.content or b"") if response else 0,
            request_headers=redacted_request_headers,
            response_headers=redacted_response_headers,
            request_body_preview=request_body_preview,
            response_body_preview=response_body_preview,
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

    def _build_redacted_url(self, flow: http.HTTPFlow, redacted_query: str) -> str:
        default_port = 443 if flow.request.scheme == "https" else 80
        port_part = "" if flow.request.port == default_port else f":{flow.request.port}"
        query_part = f"?{redacted_query}" if redacted_query else ""
        return f"{flow.request.scheme}://{flow.request.host}{port_part}{flow.request.path}{query_part}"


flow_store = FlowStore()


def _preview_bytes(data: bytes | None, limit: int = settings.body_preview_limit) -> str:
    if not data:
        return ""

    return data[:limit].decode("utf-8", errors="replace")

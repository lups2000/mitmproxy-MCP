from dataclasses import dataclass


@dataclass
class FlowSummary:
    id: str
    timestamp: str
    method: str
    host: str
    path: str
    query: str
    url: str
    status_code: int | None
    response_reason: str | None
    has_error: bool
    error_message: str | None
    request_content_type: str
    response_content_type: str
    request_body_size: int
    response_body_size: int
    marked: bool


@dataclass
class FlowDetail:
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
    has_error: bool
    error_message: str | None
    request_content_type: str
    response_content_type: str
    request_body_size: int
    response_body_size: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body_preview: str
    response_body_preview: str
    marked: bool

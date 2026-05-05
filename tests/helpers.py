from __future__ import annotations

from mitmproxy import connection
from mitmproxy import flow as mitm_flow
from mitmproxy import http


def make_http_flow(
    url: str = "https://example.com/path?foo=1&token=secret",
    method: str = "GET",
    status_code: int = 200,
    reason: str = "OK",
    request_body: bytes | None = None,
    response_body: bytes | None = b"response",
    marked: str = "",
    comment: str = "",
    intercepted: bool = False,
    error_message: str | None = None,
) -> http.HTTPFlow:
    client = connection.Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080), timestamp_start=1.0)
    server = connection.Server(address=("example.com", 443))
    flow = http.HTTPFlow(client, server)
    request = http.Request.make(method, url, request_body or b"", {"Authorization": "Bearer token", "Content-Type": "application/json"})
    request.http_version = "HTTP/1.1"
    flow.request = request
    if status_code is not None:
        flow.response = http.Response.make(
            status_code,
            response_body or b"",
            {"Set-Cookie": "session=secret", "Content-Type": "application/json"},
        )
        flow.response.reason = reason
    else:
        flow.response = None
    flow.marked = marked
    flow.comment = comment
    flow.intercepted = intercepted
    if error_message:
        flow.error = mitm_flow.Error(error_message)
    return flow

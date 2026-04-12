import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    mcp_transport: str = "streamable-http"
    max_flows: int = 1_000
    body_preview_limit: int = 200
    redaction_enabled: bool = True
    redact_headers: bool = True
    redact_query_params: bool = True
    redact_body_previews: bool = True


def load_settings() -> Settings:
    return Settings(
        proxy_host=_get_str("MITMPROXY_MCP_PROXY_HOST", "127.0.0.1"),
        proxy_port=_get_int("MITMPROXY_MCP_PROXY_PORT", 8080),
        mcp_host=_get_str("MITMPROXY_MCP_MCP_HOST", "127.0.0.1"),
        mcp_port=_get_int("MITMPROXY_MCP_MCP_PORT", 8000),
        mcp_transport=_get_str("MITMPROXY_MCP_MCP_TRANSPORT", "streamable-http"),
        max_flows=_get_int("MITMPROXY_MCP_MAX_FLOWS", 1_000),
        body_preview_limit=_get_int("MITMPROXY_MCP_BODY_PREVIEW_LIMIT", 200),
        redaction_enabled=_get_bool("MITMPROXY_MCP_REDACTION_ENABLED", True),
        redact_headers=_get_bool("MITMPROXY_MCP_REDACT_HEADERS", True),
        redact_query_params=_get_bool("MITMPROXY_MCP_REDACT_QUERY_PARAMS", True),
        redact_body_previews=_get_bool("MITMPROXY_MCP_REDACT_BODY_PREVIEWS", True),
    )


def _get_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    raise ValueError(f"Invalid boolean value for {name}: {value}")


settings = load_settings()

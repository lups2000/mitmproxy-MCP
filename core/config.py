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


settings = Settings()

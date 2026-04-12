import json

from .config import settings


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "api-key",
}

SENSITIVE_QUERY_PARAM_NAMES = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "secret",
    "session",
    "sessionid",
}

REDACTED_VALUE = "[REDACTED]"
SENSITIVE_BODY_FIELD_NAMES = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "apikey",
    "key",
    "session",
    "sessionid",
}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    if not settings.redaction_enabled or not settings.redact_headers:
        return headers

    return {
        name: (REDACTED_VALUE if name.lower() in SENSITIVE_HEADER_NAMES else value)
        for name, value in headers.items()
    }


def redact_query_items(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    if not settings.redaction_enabled or not settings.redact_query_params:
        return items

    return [
        (name, REDACTED_VALUE if name.lower() in SENSITIVE_QUERY_PARAM_NAMES else value)
        for name, value in items
    ]


def redact_body_preview(preview: str) -> str:
    if not settings.redaction_enabled or not settings.redact_body_previews:
        return preview

    if not preview:
        return preview

    try:
        parsed = json.loads(preview)
    except json.JSONDecodeError:
        return preview

    redacted = _redact_json_value(parsed)
    return json.dumps(redacted, ensure_ascii=True)


def _redact_json_value(value):
    if isinstance(value, dict):
        return {
            key: (REDACTED_VALUE if key.lower() in SENSITIVE_BODY_FIELD_NAMES else _redact_json_value(inner_value))
            for key, inner_value in value.items()
        }

    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]

    return value

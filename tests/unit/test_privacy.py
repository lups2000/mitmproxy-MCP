import json

from core import privacy


def test_redact_headers_sensitive_values(monkeypatch):
    monkeypatch.setattr(privacy, "settings", type("S", (), {"redaction_enabled": True, "redact_headers": True})())
    headers = {"Authorization": "secret", "X-Test": "ok"}
    assert privacy.redact_headers(headers) == {"Authorization": privacy.REDACTED_VALUE, "X-Test": "ok"}


def test_redact_headers_disabled(monkeypatch):
    monkeypatch.setattr(privacy, "settings", type("S", (), {"redaction_enabled": False, "redact_headers": True})())
    headers = {"Authorization": "secret"}
    assert privacy.redact_headers(headers) is headers


def test_redact_query_items(monkeypatch):
    monkeypatch.setattr(privacy, "settings", type("S", (), {"redaction_enabled": True, "redact_query_params": True})())
    assert privacy.redact_query_items([("token", "abc"), ("page", "1")]) == [
        ("token", privacy.REDACTED_VALUE),
        ("page", "1"),
    ]


def test_redact_query_items_disabled(monkeypatch):
    monkeypatch.setattr(privacy, "settings", type("S", (), {"redaction_enabled": True, "redact_query_params": False})())
    items = [("token", "abc")]
    assert privacy.redact_query_items(items) is items


def test_redact_body_preview_empty(monkeypatch):
    monkeypatch.setattr(
        privacy,
        "settings",
        type("S", (), {"redaction_enabled": True, "redact_body_previews": True})(),
    )
    assert privacy.redact_body_preview("") == ""


def test_redact_body_preview_non_json(monkeypatch):
    monkeypatch.setattr(
        privacy,
        "settings",
        type("S", (), {"redaction_enabled": True, "redact_body_previews": True})(),
    )
    assert privacy.redact_body_preview("not-json") == "not-json"


def test_redact_body_preview_json(monkeypatch):
    monkeypatch.setattr(
        privacy,
        "settings",
        type("S", (), {"redaction_enabled": True, "redact_body_previews": True})(),
    )
    payload = '{"password":"secret","nested":{"token":"abc","safe":"ok"},"items":[{"apikey":"x"}]}'
    redacted = json.loads(privacy.redact_body_preview(payload))
    assert redacted["password"] == privacy.REDACTED_VALUE
    assert redacted["nested"]["token"] == privacy.REDACTED_VALUE
    assert redacted["nested"]["safe"] == "ok"
    assert redacted["items"][0]["apikey"] == privacy.REDACTED_VALUE


def test_redact_body_preview_disabled(monkeypatch):
    monkeypatch.setattr(
        privacy,
        "settings",
        type("S", (), {"redaction_enabled": False, "redact_body_previews": True})(),
    )
    payload = '{"password":"secret"}'
    assert privacy.redact_body_preview(payload) == payload

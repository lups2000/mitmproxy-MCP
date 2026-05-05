from core.markers import normalize_marker


def test_normalize_marker_color_name():
    assert normalize_marker(" blue ") == ":large_blue_circle:"


def test_normalize_marker_existing_value():
    assert normalize_marker(":red_circle:") == ":red_circle:"


def test_normalize_marker_invalid():
    try:
        normalize_marker("pink")
    except ValueError as exc:
        assert "Unsupported marker" in str(exc)
    else:
        raise AssertionError("Expected ValueError")

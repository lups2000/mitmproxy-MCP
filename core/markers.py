SUPPORTED_MARKERS = {
    "red": ":red_circle:",
    "orange": ":orange_circle:",
    "yellow": ":yellow_circle:",
    "green": ":green_circle:",
    "blue": ":large_blue_circle:",
    "purple": ":purple_circle:",
    "brown": ":brown_circle:",
}

SUPPORTED_MARKER_VALUES = set(SUPPORTED_MARKERS.values())


def normalize_marker(marker: str) -> str:
    normalized_marker = marker.strip().lower()

    if normalized_marker in SUPPORTED_MARKERS:
        return SUPPORTED_MARKERS[normalized_marker]

    if normalized_marker in SUPPORTED_MARKER_VALUES:
        return normalized_marker

    supported = ", ".join(sorted([*SUPPORTED_MARKERS, *SUPPORTED_MARKER_VALUES]))
    raise ValueError(f"Unsupported marker '{marker}'. Supported markers: {supported}")

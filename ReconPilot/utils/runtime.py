from __future__ import annotations


def format_duration(seconds: float | int | None) -> str:
    """Return an observed runtime as a compact human-readable duration."""
    try:
        total = max(0, int(round(float(seconds))))
    except (TypeError, ValueError):
        return "unknown"

    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: list[str] = []
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if secs or not parts:
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")

    return " ".join(parts)

"""ASCII art detection (stub).

Detects ASCII art patterns that may be used to visually encode
attack payloads.  Full implementation pending.
"""

from dataclasses import dataclass


@dataclass
class AsciiArtResult:
    """Result of ASCII art detection."""
    detected: bool = False
    confidence: float = 0.0
    decoded_text: str = ""


def detect_ascii_art(text):
    """Detect ASCII art in text.

    Stub implementation — returns no detection.
    """
    return AsciiArtResult()

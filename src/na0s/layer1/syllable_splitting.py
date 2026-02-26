"""Syllable-splitting de-hyphenation (stub).

Detects and rejoins suspiciously hyphenated words that may be evasion
attempts (e.g., "ig-nore" → "ignore").  Full implementation pending.
"""

from dataclasses import dataclass, field


@dataclass
class SplittingResult:
    """Result of syllable-splitting analysis."""
    dehyphenated_text: str = ""
    detected: bool = False
    rejoined_words: list = field(default_factory=list)


def dehyphenate_suspicious(text):
    """Return text with suspiciously hyphenated words rejoined.

    Stub implementation — returns the input unchanged.
    """
    return SplittingResult(dehyphenated_text=text, detected=False)

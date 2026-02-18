"""Unicode steganography detection and extraction for Layer 0.

Detects and extracts hidden content encoded via:

1. **Unicode Tag Characters** (U+E0001-U+E007F)
   Tag characters mirror ASCII: each maps to its ASCII equivalent by
   subtracting 0xE0000.  Attackers embed invisible prompts by converting
   ASCII text to tag characters.  Discovered by Riley Goodside (Jan 2024)
   and documented extensively (arXiv 2504.11168, Cisco/Robust Intelligence,
   AWS Security Blog).  LLM tokenizers decode these back to ASCII, making
   the hidden text executable as a prompt injection.

   Legitimate use: emoji flag sequences (🏴󠁧󠁢󠁥󠁮󠁧󠁿 = gbeng).  We preserve
   flag sequences and only flag/extract non-flag tag character runs.

2. **Variation Selectors** (VS1-VS16: U+FE00-U+FE0F,
   VS17-VS256: U+E0100-U+E01EF)
   Variation Selectors modify the preceding base character's glyph.
   Legitimate uses: emoji presentation (U+FE0F), CJK ideographic variants.
   Steganographic abuse: encoding bits in VS choices after base characters,
   or using excessive VS sequences to hide data.

References:
    - arXiv 2504.11168: Bypassing Prompt Injection Detection in LLM Guardrails
    - Cisco: Understanding and Mitigating Unicode Tag Prompt Injection
    - AWS: Defending LLM Applications Against Unicode Character Smuggling
    - GitHub: kristoftabori/unicode_exploration, TrustAI-laboratory/ASCII-Smuggling
    - GitHub: seojoonkim/prompt-guard, 0x6f677548/unicode-injection
    - OWASP: LLM Prompt Injection Prevention Cheat Sheet
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Tag character range (mirrors ASCII 0x00-0x7F at offset 0xE0000)
TAG_BEGIN = 0xE0001   # TAG LANGUAGE TAG (first used tag char)
TAG_SPACE = 0xE0020   # TAG SPACE (first printable tag char)
TAG_END = 0xE007E     # TAG TILDE (last printable tag char)
TAG_CANCEL = 0xE007F  # CANCEL TAG (sequence terminator)

#: Emoji flag sequence: BLACK FLAG (U+1F3F4) + tag chars + CANCEL TAG
FLAG_BASE = 0x1F3F4

#: Variation Selector ranges
VS1_START = 0xFE00    # VS1
VS16_END = 0xFE0F     # VS16  (basic variation selectors)
VS17_START = 0xE0100   # VS17  (supplementary variation selectors)
VS256_END = 0xE01EF    # VS256

#: Emoji presentation selector
EMOJI_VS = 0xFE0F     # VS16 = emoji presentation
TEXT_VS = 0xFE0E       # VS15 = text presentation

#: Threshold: more than this many VS chars without a base is suspicious
VS_DENSITY_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class StegoResult:
    """Result of Unicode steganography detection.

    Attributes:
        has_hidden_text:   True if hidden text was extracted from tag chars.
        hidden_text:       The extracted ASCII text (from tag characters).
        tag_char_count:    Number of tag characters found.
        vs_count:          Number of variation selectors found.
        is_flag_sequence:  True if tag chars form a legitimate flag emoji.
        anomaly_flags:     Flags to add to the Layer0Result.
        cleaned_text:      Input text with tag characters stripped.
    """
    has_hidden_text: bool = False
    hidden_text: str = ""
    tag_char_count: int = 0
    vs_count: int = 0
    is_flag_sequence: bool = False
    anomaly_flags: list[str] = field(default_factory=list)
    cleaned_text: str = ""


# ---------------------------------------------------------------------------
# Tag Character detection and extraction
# ---------------------------------------------------------------------------

def _is_tag_char(cp: int) -> bool:
    """Check if a codepoint is in the Unicode Tags block."""
    return TAG_BEGIN <= cp <= TAG_CANCEL


def _tag_to_ascii(cp: int) -> str:
    """Convert a tag character codepoint to its ASCII equivalent."""
    ascii_cp = cp - 0xE0000
    if 0x20 <= ascii_cp <= 0x7E:
        return chr(ascii_cp)
    return ""


def _is_flag_sequence(text: str, start: int) -> tuple[bool, int]:
    """Check if tag characters at position start form a flag emoji sequence.

    Flag sequences are: U+1F3F4 + tag letters (2-7 lowercase a-z) + U+E007F.
    Example: 🏴󠁧󠁢󠁥󠁮󠁧󠁿 = U+1F3F4 + gbeng + CANCEL TAG

    Returns (is_flag, end_index).
    """
    if start == 0:
        return False, start

    # Check if preceded by BLACK FLAG emoji
    prev_idx = start - 1
    if prev_idx >= 0 and ord(text[prev_idx]) == FLAG_BASE:
        # Scan tag chars for lowercase letter tags only (a-z = E0061-E007A)
        tag_len = 0
        pos = start
        while pos < len(text):
            cp = ord(text[pos])
            if cp == TAG_CANCEL:
                # Valid flag: 2-7 tag letters + cancel
                if 2 <= tag_len <= 7:
                    return True, pos + 1
                break
            ascii_cp = cp - 0xE0000
            if 0x61 <= ascii_cp <= 0x7A:  # lowercase a-z
                tag_len += 1
                pos += 1
            else:
                break
        # Also check 2 chars back for surrogate pair representation
    # Check for surrogate pair (U+1F3F4 = \uD83C\uDFF4 in UTF-16,
    # but in Python str it's a single char)
    if prev_idx >= 1 and ord(text[prev_idx - 1]) == FLAG_BASE:
        # Already handled above
        pass

    return False, start


def extract_tag_characters(text: str) -> StegoResult:
    """Detect and extract hidden text from Unicode Tag Characters.

    Scans the input for tag characters (U+E0001-U+E007F), extracts the
    hidden ASCII content, and returns the cleaned text with tags stripped.

    Legitimate flag emoji sequences (🏴 + tag letters + CANCEL TAG) are
    preserved and not flagged.

    Parameters
    ----------
    text : str
        Input text to scan.

    Returns
    -------
    StegoResult
        Detection results including extracted hidden text and anomaly flags.
    """
    if not text:
        return StegoResult(cleaned_text=text)

    tag_chars_found = 0
    hidden_parts: list[str] = []
    cleaned_parts: list[str] = []
    flags: list[str] = []
    flag_sequence_found = False

    i = 0
    while i < len(text):
        cp = ord(text[i])

        if _is_tag_char(cp):
            # Check if this is part of a flag emoji sequence
            is_flag, flag_end = _is_flag_sequence(text, i)
            if is_flag:
                # Preserve flag sequence in output
                cleaned_parts.append(text[i:flag_end])
                flag_sequence_found = True
                i = flag_end
                continue

            # Non-flag tag character: extract and strip
            tag_chars_found += 1
            ascii_char = _tag_to_ascii(cp)
            if ascii_char:
                hidden_parts.append(ascii_char)
            i += 1
        else:
            cleaned_parts.append(text[i])
            i += 1

    hidden_text = "".join(hidden_parts)
    cleaned_text = "".join(cleaned_parts)

    if tag_chars_found > 0:
        flags.append("unicode_tag_chars_found")
        if hidden_text:
            flags.append("unicode_tag_hidden_text")

    return StegoResult(
        has_hidden_text=bool(hidden_text),
        hidden_text=hidden_text,
        tag_char_count=tag_chars_found,
        is_flag_sequence=flag_sequence_found,
        anomaly_flags=flags,
        cleaned_text=cleaned_text,
    )


# ---------------------------------------------------------------------------
# Variation Selector detection
# ---------------------------------------------------------------------------

def _is_variation_selector(cp: int) -> bool:
    """Check if a codepoint is a Variation Selector."""
    return (VS1_START <= cp <= VS16_END) or (VS17_START <= cp <= VS256_END)


def _is_emoji_vs(cp: int) -> bool:
    """Check if a VS is a standard emoji/text presentation selector."""
    return cp == EMOJI_VS or cp == TEXT_VS


def detect_variation_selectors(text: str) -> StegoResult:
    """Detect suspicious Variation Selector usage that may indicate stego.

    Legitimate VS usage:
    - VS15 (U+FE0E) / VS16 (U+FE0F) for text/emoji presentation
    - CJK ideographic variation sequences (IVS) using VS17-VS256
    - Typically 1 VS per base character

    Suspicious patterns:
    - Multiple consecutive VS characters
    - Supplementary VS (U+E0100-U+E01EF) outside CJK context
    - High density of VS relative to text length

    Parameters
    ----------
    text : str
        Input text to scan.

    Returns
    -------
    StegoResult
        Detection results with anomaly flags.
    """
    if not text:
        return StegoResult(cleaned_text=text)

    vs_count = 0
    supplementary_vs_count = 0
    consecutive_vs = 0
    max_consecutive = 0
    flags: list[str] = []

    for ch in text:
        cp = ord(ch)
        if _is_variation_selector(cp):
            vs_count += 1
            consecutive_vs += 1
            max_consecutive = max(max_consecutive, consecutive_vs)
            if VS17_START <= cp <= VS256_END:
                supplementary_vs_count += 1
        else:
            consecutive_vs = 0

    if vs_count == 0:
        return StegoResult(cleaned_text=text)

    # Flag suspicious patterns
    # Multiple consecutive VS chars (stego encoding)
    if max_consecutive >= 2:
        flags.append("variation_selector_consecutive")

    # High VS density (more than 1 VS per 5 chars of text)
    text_len = len(text)
    if text_len > 0 and vs_count > max(VS_DENSITY_THRESHOLD, text_len // 5):
        flags.append("variation_selector_density")

    # Supplementary VS outside CJK context
    if supplementary_vs_count > 0:
        # Check if text contains CJK characters
        has_cjk = any(
            0x3400 <= ord(ch) <= 0x9FFF or 0xF900 <= ord(ch) <= 0xFAFF
            or 0x20000 <= ord(ch) <= 0x2FA1F
            for ch in text if not _is_variation_selector(ord(ch))
        )
        if not has_cjk:
            flags.append("variation_selector_supplementary_non_cjk")

    return StegoResult(
        has_hidden_text=False,  # VS stego extraction is complex; we flag only
        vs_count=vs_count,
        anomaly_flags=flags,
        cleaned_text=text,  # Don't strip VS (may be legitimate)
    )


# ---------------------------------------------------------------------------
# Combined detection entry point
# ---------------------------------------------------------------------------

def detect_unicode_stego(text: str) -> StegoResult:
    """Run all Unicode steganography detection checks.

    Combines tag character extraction and variation selector detection
    into a single pass.

    Parameters
    ----------
    text : str
        Input text to scan (should be pre-normalized).

    Returns
    -------
    StegoResult
        Combined detection results.
    """
    # Phase 1: Tag character extraction (also cleans the text)
    tag_result = extract_tag_characters(text)

    # Phase 2: Variation selector detection (on cleaned text)
    vs_result = detect_variation_selectors(tag_result.cleaned_text)

    # Merge results
    combined_flags = tag_result.anomaly_flags + vs_result.anomaly_flags

    return StegoResult(
        has_hidden_text=tag_result.has_hidden_text,
        hidden_text=tag_result.hidden_text,
        tag_char_count=tag_result.tag_char_count,
        vs_count=vs_result.vs_count,
        is_flag_sequence=tag_result.is_flag_sequence,
        anomaly_flags=combined_flags,
        cleaned_text=tag_result.cleaned_text,
    )

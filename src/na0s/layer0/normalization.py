import re
import unicodedata

# ftfy fixes mojibake (encoding mix-ups) — e.g. UTF-8 decoded as latin-1.
# Graceful fallback: if not installed, mojibake repair is simply skipped.
try:
    import ftfy

    _HAS_FTFY = True
except ImportError:
    _HAS_FTFY = False

# Unicode whitespace variants that should become plain ASCII space.
# Does NOT include \n, \r, \t — those are handled separately.
_UNICODE_WHITESPACE_RE = re.compile(
    "[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff\x0b\x0c]"
)

# Collapse runs of multiple ASCII spaces into one
_MULTI_SPACE_RE = re.compile(r" {2,}")

# Collapse 3+ consecutive newlines into 2 (preserves paragraph breaks)
_EXCESSIVE_NEWLINES_RE = re.compile(r"\n{3,}")

# Collapse 3+ consecutive tabs into 1
_EXCESSIVE_TABS_RE = re.compile(r"\t{3,}")


# ---------------------------------------------------------------------------
# Post-ftfy integrity validation (guards against ftfy #149, #202)
# ---------------------------------------------------------------------------

# Approximate Unicode script ranges for script-injection detection.
# Characters outside these ranges return "Common" (punctuation, symbols, etc.)
_SCRIPT_RANGES = (
    (0x0000, 0x007F, "Latin"),       # Basic Latin
    (0x0080, 0x024F, "Latin"),       # Latin Extended
    (0x0250, 0x02AF, "Latin"),       # IPA Extensions
    (0x0370, 0x03FF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0500, 0x052F, "Cyrillic"),    # Cyrillic Supplement
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x3400, 0x9FFF, "CJK"),
    (0xAC00, 0xD7AF, "Hangul"),
    (0xF900, 0xFAFF, "CJK"),
    (0x10000, 0x1007F, "LinearB"),
    (0x1F600, 0x1F9FF, "Emoji"),
)


def _char_script(ch):
    """Return the approximate Unicode script for a character."""
    cp = ord(ch)
    for lo, hi, script in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return script
    return "Common"


def _script_inventory(text):
    """Return the set of non-Common scripts present in *text*."""
    return {_char_script(ch) for ch in text} - {"Common"}


def _validate_ftfy_output(original, fixed):
    """Check whether ftfy's correction is safe.

    Returns True if the correction is acceptable, False if ftfy introduced
    suspicious characters.

    Guards against:
    - ftfy #149: Dutch text producing Pallas symbol (U+26B4)
    - ftfy #202: en-dash mojibake producing Cyrillic (fixed in 6.2, but
      we keep the guard as defense-in-depth)

    Key insight: full-text mojibake repair (e.g., Latin garble → CJK) is
    legitimate and changes the entire script.  Isolated wrong corrections
    (e.g., one Pallas symbol or a few Cyrillic chars in Latin text) are
    suspicious.  We distinguish by checking the RATIO of new-script chars.
    """
    new_chars = set(fixed) - set(original)
    if not new_chars:
        return True

    # 1. Symbol injection: reject if new "Other Symbol" (So) chars appear
    #    when the original had none (catches Pallas symbol U+26B4, etc.)
    orig_has_so = any(unicodedata.category(ch) == "So" for ch in original)
    if not orig_has_so:
        for ch in new_chars:
            if unicodedata.category(ch) == "So":
                return False

    # 2. Partial script injection: reject if a SMALL number of chars from
    #    a new script appear (isolated wrong fix), but allow full-script
    #    changes (legitimate mojibake repair like Latin garble → CJK).
    orig_scripts = _script_inventory(original)
    new_script_chars = [
        ch for ch in new_chars
        if _char_script(ch) not in orig_scripts and _char_script(ch) != "Common"
    ]
    if new_script_chars:
        # Count how many chars in the FIXED text belong to the new script(s)
        new_scripts = {_char_script(ch) for ch in new_script_chars}
        new_script_count = sum(
            1 for ch in fixed if _char_script(ch) in new_scripts
        )
        # If less than 50% of the output is in the new script, it's an
        # isolated injection (suspicious).  Full mojibake repair changes
        # most of the text.
        if len(fixed) > 0 and new_script_count / len(fixed) < 0.5:
            return False

    return True


def has_invisible_chars(text):
    """Detect invisible characters, zero-width chars, RTL overrides, surrogates."""
    for char in text:
        cat = unicodedata.category(char)
        if cat == "Cf":  # Format chars (zero-width, RTL override, etc.)
            return True
        if cat == "Cs":  # Lone surrogates — invalid in interchange
            return True
        if cat in ("Cc", "Cn") and char not in "\n\r\t":
            return True
    return False


def strip_invisible_chars(text):
    """Remove invisible/control Unicode characters. Preserves newlines, tabs.

    Also strips lone surrogates (category Cs) — these are invalid in UTF-8
    interchange and crash downstream encoders (hashlib, tiktoken).
    """
    result = []
    for char in text:
        cat = unicodedata.category(char)
        if cat == "Cs":
            continue  # Always strip surrogates
        if cat not in ("Cf", "Cc", "Cn") or char in "\n\r\t ":
            result.append(char)
    return "".join(result)


def _ftfy_fix_with_sentinel(text):
    """Run ftfy.fix_text with a workaround for issue #222 (string-start bug).

    ftfy's badness heuristic (BADNESS_RE) fails to detect certain mojibake
    patterns at position 0 because several patterns require preceding context
    (e.g., a lowercase letter before the garbled capital letter).  When
    mojibake begins at the very first character, that context is absent.

    Workaround: prepend a single ASCII space so the mojibake is no longer
    at position 0, then strip the sentinel after ftfy processes the text.

    See: https://github.com/rspeer/python-ftfy/issues/222
    """
    if not text:
        return text

    sentinel_added = False
    ftfy_input = text

    if not text[0:1].isspace():
        ftfy_input = " " + text
        sentinel_added = True

    fixed = ftfy.fix_text(ftfy_input, fix_character_width=False)

    if sentinel_added:
        if fixed.startswith(" "):
            fixed = fixed[1:]
        else:
            fixed = fixed.lstrip(" ")

    return fixed


def _count_compat_chars(text):
    """Count characters whose NFKC decomposition differs from themselves.

    This per-character check avoids false positives from positional shift
    (e.g. a ligature expanding fi→fi shifts all later positions).
    """
    count = 0
    for ch in text:
        if unicodedata.normalize("NFKC", ch) != ch:
            count += 1
    return count


def normalize_text(text):
    """Run all Layer 0 normalization steps in order.

    Returns (normalized_text, chars_stripped, anomaly_flags).
    """
    flags = []
    original_len = len(text)

    # Step 0: Mojibake repair via ftfy (before NFKC)
    # Fixes encoding errors like UTF-8 decoded as latin-1:
    #   "â€™" → "'"   "Ã©" → "é"   "â€œhelloâ€\x9d" → ""hello""
    # Uses sentinel workaround for ftfy #222 (mojibake at position 0).
    # Post-fix validation guards against ftfy #149/#202 (wrong corrections).
    if _HAS_FTFY:
        fixed = _ftfy_fix_with_sentinel(text)
        if fixed != text:
            if _validate_ftfy_output(text, fixed):
                flags.append("mojibake_repaired")
                text = fixed
            else:
                # ftfy produced a suspicious correction (new scripts or
                # symbols not in original).  Revert and flag for review.
                # See: ftfy #149 (Pallas symbol), #202 (Cyrillic injection)
                flags.append("ftfy_suspicious_correction")

    # Step 1: NFKC normalization
    # Collapses fullwidth chars, ligatures, superscripts, compatibility forms
    compat_count = _count_compat_chars(text)
    text = unicodedata.normalize("NFKC", text)
    # Only flag if >25% of original chars are compatibility forms — ligatures
    # from Word, superscripts in math (x²), smart quotes are all normal.
    # A wall of fullwidth chars (evasion) typically hits 80%+.
    if compat_count > 0 and compat_count / max(original_len, 1) > 0.25:
        flags.append("nfkc_changed")

    # Step 2: Invisible character stripping
    if has_invisible_chars(text):
        before_strip = len(text)
        text = strip_invisible_chars(text)
        invisible_count = before_strip - len(text)
        # Only flag if >2 invisible chars — a single zero-width space from
        # copy-paste is normal; a cluster of them is evasion
        if invisible_count > 2:
            flags.append("invisible_chars_found")

    # Step 3: Whitespace canonicalization
    # Replace Unicode whitespace variants with ASCII space
    cleaned, count = _UNICODE_WHITESPACE_RE.subn(" ", text)
    if count > 0:
        flags.append("unicode_whitespace_normalized")
        text = cleaned

    # Collapse multiple spaces into one, strip leading/trailing
    text = _MULTI_SPACE_RE.sub(" ", text).strip()

    # Collapse excessive newlines and tabs (prevents padding attacks)
    text = _EXCESSIVE_NEWLINES_RE.sub("\n\n", text)
    text = _EXCESSIVE_TABS_RE.sub("\t", text)

    chars_stripped = original_len - len(text)
    return text, chars_stripped, flags

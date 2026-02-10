import re
import unicodedata

# Unicode whitespace variants that should become plain ASCII space.
# Does NOT include \n, \r, \t — those are preserved.
_UNICODE_WHITESPACE_RE = re.compile(
    "[\u00a0\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]"
)

# Collapse runs of multiple ASCII spaces into one
_MULTI_SPACE_RE = re.compile(r" {2,}")


def has_invisible_chars(text):
    """Detect invisible characters, zero-width chars, RTL overrides."""
    for char in text:
        cat = unicodedata.category(char)
        if cat == "Cf":  # Format chars (zero-width, RTL override, etc.)
            return True
        if cat in ("Cc", "Cn") and char not in "\n\r\t":
            return True
    return False


def strip_invisible_chars(text):
    """Remove invisible/control Unicode characters. Preserves newlines, tabs."""
    result = []
    for char in text:
        cat = unicodedata.category(char)
        if cat not in ("Cf", "Cc", "Cn") or char in "\n\r\t ":
            result.append(char)
    return "".join(result)


def normalize_text(text):
    """Run all Layer 0 normalization steps in order.

    Returns (normalized_text, chars_stripped, anomaly_flags).
    """
    flags = []
    original_len = len(text)

    # Step 1: NFKC normalization
    # Collapses fullwidth chars, ligatures, superscripts, compatibility forms
    text = unicodedata.normalize("NFKC", text)
    if len(text) != original_len:
        flags.append("nfkc_changed")

    # Step 2: Invisible character stripping
    if has_invisible_chars(text):
        flags.append("invisible_chars_found")
        text = strip_invisible_chars(text)

    # Step 3: Whitespace canonicalization
    # Replace Unicode whitespace variants with ASCII space
    cleaned, count = _UNICODE_WHITESPACE_RE.subn(" ", text)
    if count > 0:
        flags.append("unicode_whitespace_normalized")
        text = cleaned

    # Collapse multiple spaces into one, strip leading/trailing
    text = _MULTI_SPACE_RE.sub(" ", text).strip()

    chars_stripped = original_len - len(text)
    return text, chars_stripped, flags

import re
import unicodedata

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

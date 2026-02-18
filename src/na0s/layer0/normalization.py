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

# Token splitter: split on whitespace but keep punctuation attached to the
# token for reconstruction.  We use re.split with a capturing group so that
# delimiters (whitespace runs) are preserved for lossless reassembly.
_TOKEN_SPLIT_RE = re.compile(r"(\s+)")


# ---------------------------------------------------------------------------
# Confusable homoglyph mapping (Unicode TR39 / UTS #39)
# ---------------------------------------------------------------------------
# Maps Cyrillic, Greek, and select Armenian characters that are visually
# identical (or near-identical) to Latin characters.  Derived from the
# Unicode Consortium's confusables.txt data file.
#
# DESIGN: Only applied to MIXED-SCRIPT tokens (tokens containing both
# Latin and Cyrillic/Greek/Armenian characters).  Pure non-Latin tokens
# are left untouched to preserve legitimate multilingual text.
#
# WHY NFKC DOESN'T HANDLE THIS: NFKC normalizes compatibility
# decompositions (e.g., fullwidth A -> A, ligature fi -> fi).  Cyrillic
# 'a' (U+0430) is a canonical character, NOT a compatibility form of
# Latin 'a' (U+0061).  They are separate characters in separate scripts
# that happen to look identical.  Unicode explicitly does NOT merge
# cross-script look-alikes in NFC/NFKC because that would destroy
# legitimate Cyrillic/Greek text.

# --- Cyrillic -> Latin confusables ---
_CYRILLIC_TO_LATIN = {
    # Uppercase Cyrillic -> Latin
    "\u0410": "A",   # А -> A
    "\u0412": "B",   # В -> B
    "\u0421": "C",   # С -> C
    "\u0415": "E",   # Е -> E
    "\u041D": "H",   # Н -> H
    "\u0406": "I",   # І -> I  (Ukrainian/Belarusian)
    "\u0408": "J",   # Ј -> J  (Serbian)
    "\u041A": "K",   # К -> K
    "\u041C": "M",   # М -> M
    "\u041E": "O",   # О -> O
    "\u0420": "P",   # Р -> P
    "\u0405": "S",   # Ѕ -> S  (Macedonian)
    "\u0422": "T",   # Т -> T
    "\u0425": "X",   # Х -> X
    "\u04AE": "Y",   # Ү -> Y  (Kazakh/Mongolian)
    # Lowercase Cyrillic -> Latin
    "\u0430": "a",   # а -> a
    "\u0441": "c",   # с -> c
    "\u0435": "e",   # е -> e
    "\u0456": "i",   # і -> i  (Ukrainian і)
    "\u0458": "j",   # ј -> j  (Serbian)
    "\u043E": "o",   # о -> o
    "\u0440": "p",   # р -> p
    "\u0455": "s",   # ѕ -> s  (Macedonian)
    "\u0443": "y",   # у -> y  (Cyrillic у looks like Latin y)
    "\u0445": "x",   # х -> x
    "\u04BB": "h",   # һ -> h  (Bashkir/Kazakh)
    "\u0501": "d",   # ԁ -> d  (Cyrillic Supplement, Komi)
    "\u051B": "q",   # ԛ -> q  (Cyrillic Supplement, Kurdish)
    "\u051D": "w",   # ԝ -> w  (Cyrillic Supplement, Abkhaz)
    # Extended / less common but exploitable
    "\u0454": "e",   # є -> e  (Ukrainian yest, close to epsilon/e)
    "\u0471": "v",   # ѱ -> v  (archaic psi, but rarely used for attack)
    "\u04CF": "l",   # ӏ -> l  (Cyrillic palochka, looks like l or I)
    "\u04C0": "I",   # Ӏ -> I  (Cyrillic palochka uppercase)
}

# --- Greek -> Latin confusables ---
_GREEK_TO_LATIN = {
    # Uppercase Greek -> Latin
    "\u0391": "A",   # Α -> A  (Alpha)
    "\u0392": "B",   # Β -> B  (Beta)
    "\u0395": "E",   # Ε -> E  (Epsilon)
    "\u0396": "Z",   # Ζ -> Z  (Zeta)
    "\u0397": "H",   # Η -> H  (Eta)
    "\u0399": "I",   # Ι -> I  (Iota)
    "\u039A": "K",   # Κ -> K  (Kappa)
    "\u039C": "M",   # Μ -> M  (Mu)
    "\u039D": "N",   # Ν -> N  (Nu)
    "\u039F": "O",   # Ο -> O  (Omicron)
    "\u03A1": "P",   # Ρ -> P  (Rho)
    "\u03A4": "T",   # Τ -> T  (Tau)
    "\u03A5": "Y",   # Υ -> Y  (Upsilon)
    "\u03A7": "X",   # Χ -> X  (Chi)
    # Lowercase Greek -> Latin
    "\u03BF": "o",   # ο -> o  (omicron)
    "\u03B9": "i",   # ι -> i  (iota — in many sans-serif fonts)
    "\u03BA": "k",   # κ -> k  (kappa — close in some fonts)
    "\u03BD": "v",   # ν -> v  (nu — visually identical to v)
    "\u03C1": "p",   # ρ -> p  (rho — descender differs but close)
    "\u03C5": "u",   # υ -> u  (upsilon — close in sans-serif)
    "\u03C7": "x",   # χ -> x  (chi — with descender but close)
}

# --- Armenian -> Latin confusables ---
_ARMENIAN_TO_LATIN = {
    "\u054D": "S",   # Ս -> S
    "\u054F": "T",   # Տ -> T  (close in some fonts)
    "\u0555": "O",   # Օ -> O
    "\u0585": "o",   # օ -> o
    "\u0570": "h",   # հ -> h  (close in some fonts)
    "\u0578": "n",   # ո -> n  (close in some fonts)
    "\u057D": "s",   # ս -> s
    "\u0575": "j",   # յ -> j  (close in some fonts)
}

# Combined mapping — all confusable scripts -> Latin
_CONFUSABLE_TO_LATIN = {}
_CONFUSABLE_TO_LATIN.update(_CYRILLIC_TO_LATIN)
_CONFUSABLE_TO_LATIN.update(_GREEK_TO_LATIN)
_CONFUSABLE_TO_LATIN.update(_ARMENIAN_TO_LATIN)

# Pre-build a frozenset of confusable codepoints for fast O(1) lookup
_CONFUSABLE_CODEPOINTS = frozenset(_CONFUSABLE_TO_LATIN.keys())

# Scripts that contain Latin-confusable characters
_CONFUSABLE_SCRIPTS = frozenset({"Cyrillic", "Greek", "Armenian"})


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


# ---------------------------------------------------------------------------
# Homoglyph normalization (D5.3 — cross-script confusable detection)
# ---------------------------------------------------------------------------

def _has_mixed_scripts_for_homoglyphs(token):
    """Check if a token mixes Latin with Cyrillic/Greek/Armenian characters.

    Only considers alphabetic characters; digits, punctuation, and symbols
    are ignored.  Returns True if the token contains BOTH Latin letters
    AND letters from a confusable script (Cyrillic, Greek, or Armenian).

    This is the gate that prevents legitimate pure-Cyrillic (e.g., Russian)
    or pure-Greek text from being transliterated.
    """
    has_latin = False
    has_confusable = False
    for ch in token:
        if ch.isalpha():
            script = _char_script(ch)
            if script == "Latin":
                has_latin = True
            elif script in _CONFUSABLE_SCRIPTS:
                has_confusable = True
        if has_latin and has_confusable:
            return True
    return False


def normalize_homoglyphs(text):
    """Normalize Cyrillic/Greek/Armenian homoglyphs in mixed-script tokens.

    Only normalizes tokens that MIX Latin with confusable-script characters.
    Pure Cyrillic/Greek/Armenian tokens are left unchanged (legitimate text).

    Uses whitespace-preserving split so that the original spacing (including
    newlines and tabs) is preserved exactly.

    Parameters
    ----------
    text : str
        The input text (should already be NFKC-normalized).

    Returns
    -------
    tuple of (str, int)
        ``(normalized_text, homoglyph_count)`` where *homoglyph_count* is
        the number of confusable characters that were replaced.
    """
    # Split into tokens and whitespace delimiters for lossless reassembly
    parts = _TOKEN_SPLIT_RE.split(text)
    total_replaced = 0

    for i, part in enumerate(parts):
        # Whitespace delimiters (odd indices) are never modified
        if not part or part.isspace():
            continue
        if _has_mixed_scripts_for_homoglyphs(part):
            new_chars = []
            for ch in part:
                replacement = _CONFUSABLE_TO_LATIN.get(ch)
                if replacement is not None:
                    new_chars.append(replacement)
                    total_replaced += 1
                else:
                    new_chars.append(ch)
            parts[i] = "".join(new_chars)

    return "".join(parts), total_replaced


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


def _count_invisible_chars(text):
    """Count invisible/control characters that strip_invisible_chars removes.

    Returns the number of characters that would be stripped (Cf, Cs, Cc, Cn
    excluding newlines, carriage returns, tabs, and spaces).
    """
    count = 0
    for char in text:
        cat = unicodedata.category(char)
        if cat == "Cs":
            count += 1
        elif cat in ("Cf", "Cc", "Cn") and char not in "\n\r\t ":
            count += 1
    return count


def strip_invisible_chars(text):
    """Remove invisible/control Unicode characters. Preserves newlines, tabs.

    Also strips lone surrogates (category Cs) — these are invalid in UTF-8
    interchange and crash downstream encoders (hashlib, tiktoken).

    Word-boundary restoration (two-pass approach):
      Pass 1: Strip all invisible/control characters, producing a clean string.
      Pass 2: Where invisible chars were removed between two groups of 2+
              word-forming characters, insert a single space to restore the
              word boundary that the invisible char was replacing.

    This handles two distinct D5.2 evasion patterns correctly:
      - Per-letter splitting:  "i<ZWSP>g<ZWSP>n<ZWSP>o<ZWSP>r<ZWSP>e" -> "ignore"
        (invisible chars between single characters = intra-word, just strip)
      - Word-boundary hiding: "ignore<ZWSP>all<ZWSP>previous" -> "ignore all previous"
        (invisible chars between multi-char groups = inter-word, insert space)

    The heuristic: if a removed invisible char has >= 2 word-forming characters
    on BOTH sides before the next gap/space/non-word, it was likely a word
    boundary and gets replaced with a space.
    """
    # Build a list of (char, is_visible) pairs to analyze context.
    # First, categorize each character.
    chars_info = []  # list of (char, is_invisible_to_strip)
    for char in text:
        cat = unicodedata.category(char)
        if cat == "Cs":
            chars_info.append((char, True))
        elif cat in ("Cf", "Cc", "Cn") and char not in "\n\r\t ":
            chars_info.append((char, True))
        else:
            chars_info.append((char, False))

    # Now build the result, deciding whether to insert spaces.
    # Strategy: scan segments between invisible-char gaps.
    # A "segment" is a run of visible characters.
    # If two adjacent segments both have length >= 2 (in word chars),
    # insert a space between them; otherwise just concatenate.
    segments = []
    current_segment = []
    had_invisible_between = False

    for char, is_invisible in chars_info:
        if is_invisible:
            if current_segment:
                segments.append(("".join(current_segment), had_invisible_between))
                current_segment = []
                had_invisible_between = False
            had_invisible_between = True
        else:
            current_segment.append(char)

    if current_segment:
        segments.append(("".join(current_segment), had_invisible_between))

    if not segments:
        return ""

    result_parts = [segments[0][0]]
    for i in range(1, len(segments)):
        seg_text, preceded_by_invisible = segments[i]
        if not preceded_by_invisible:
            result_parts.append(seg_text)
            continue

        prev_seg = segments[i - 1][0]
        # Count trailing word chars in previous segment
        prev_word_len = 0
        for ch in reversed(prev_seg):
            if ch.isalpha() or ch.isdigit():
                prev_word_len += 1
            else:
                break

        # Count leading word chars in current segment
        cur_word_len = 0
        for ch in seg_text:
            if ch.isalpha() or ch.isdigit():
                cur_word_len += 1
            else:
                break

        # Insert space only if both sides have 3+ word chars.
        # Groups of 1-2 chars indicate per-letter splitting or intra-word
        # breaks (e.g. soft hyphen in "ig\u00adnore") where we want plain
        # concatenation to reconstruct the word.  Groups of 3+ chars are
        # likely complete words (e.g. "ignore\u200ball") where invisible
        # chars replaced word boundaries.
        if prev_word_len >= 3 and cur_word_len >= 3:
            # Also check the previous segment doesn't already end with space
            if prev_seg and prev_seg[-1] not in (" ", "\n", "\r", "\t"):
                result_parts.append(" ")
        result_parts.append(seg_text)

    return "".join(result_parts)


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

    # Step 1.5: Cross-script homoglyph normalization (D5.3)
    # Cyrillic/Greek/Armenian characters that are visually identical to Latin
    # are normalized to their Latin equivalents, but ONLY in mixed-script
    # tokens.  Pure non-Latin tokens are preserved (legitimate multilingual
    # text).  This closes the D5.3 bypass where NFKC cannot help because
    # these are canonical characters, not compatibility forms.
    text, homoglyph_count = normalize_homoglyphs(text)
    if homoglyph_count > 0:
        flags.append("mixed_script_homoglyphs")

    # Step 2: Invisible character stripping
    if has_invisible_chars(text):
        # Count actual invisible chars before stripping.  Cannot use
        # length difference because strip_invisible_chars() may INSERT
        # spaces at word boundaries, offsetting the count.
        invisible_count = _count_invisible_chars(text)
        text = strip_invisible_chars(text)
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

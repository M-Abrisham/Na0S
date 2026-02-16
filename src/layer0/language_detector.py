"""Language detection for multilingual routing (D6 category).

Detects the primary language of input text and flags non-English or
mixed-language content.  Uses the ``langdetect`` library when available;
gracefully degrades to ``unknown`` when it is not installed.

Technique mapping:
    non_english_input    -> D6   (Multilingual Injection)
    mixed_language_input -> D6.3 (Chinese / mixed-language context)
"""

import logging
import re

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency -- langdetect
# ---------------------------------------------------------------------------
try:
    from langdetect import detect_langs, DetectorFactory
    from langdetect.lang_detect_exception import LangDetectException

    # Make detection deterministic across runs
    DetectorFactory.seed = 0
    _HAS_LANGDETECT = True
except ImportError:
    _HAS_LANGDETECT = False
    _logger.debug("langdetect not installed; language detection disabled")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Minimum character count for reliable detection.  Below this threshold the
# library returns unreliable guesses so we report "unknown" instead.
_MIN_CHARS_FOR_DETECTION = 20

# Confidence threshold -- below this we treat the result as unreliable.
_MIN_CONFIDENCE = 0.5

# Quick heuristic regex: text contains CJK, Arabic, Cyrillic, Devanagari,
# Thai, or other non-Latin script blocks -- used for mixed-language detection.
_NON_LATIN_RE = re.compile(
    "["
    "؀-ۿ"   # Arabic
    "Ѐ-ӿ"   # Cyrillic
    "ऀ-ॿ"   # Devanagari
    "฀-๿"   # Thai
    "぀-ヿ"   # Hiragana + Katakana
    "一-鿿"   # CJK Unified
    "가-힯"   # Hangul Syllables
    "㐀-䶿"   # CJK Extension A
    "𠀀-𪛟"  # CJK Extension B
    "]"
)

_LATIN_LETTER_RE = re.compile(r"[a-zA-Z]")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_language(text):
    """Detect the primary language of *text*.

    Parameters
    ----------
    text : str
        The input text to analyse.  Should be the **sanitized** (post-
        normalization) text so that invisible characters and encoding
        artefacts have already been removed.

    Returns
    -------
    dict
        ``detected_language`` : str
            ISO 639-1 language code (e.g. ``"en"``, ``"zh-cn"``, ``"ar"``),
            or ``"unknown"`` when detection is unreliable.
        ``language_confidence`` : float
            Confidence score 0.0 -- 1.0.
        ``is_non_english`` : bool
            ``True`` when the detected language is not English.
        ``anomaly_flags`` : list[str]
            May contain ``"non_english_input"`` and/or
            ``"mixed_language_input"``.
    """
    result = {
        "detected_language": "unknown",
        "language_confidence": 0.0,
        "is_non_english": False,
        "anomaly_flags": [],
    }

    # --- Guard: empty / whitespace-only text ---
    if not text or not text.strip():
        return result

    # --- Guard: langdetect not available ---
    if not _HAS_LANGDETECT:
        return result

    # --- Guard: text too short for reliable detection ---
    stripped = text.strip()
    if len(stripped) < _MIN_CHARS_FOR_DETECTION:
        # Even for short text, use script heuristic for non-Latin detection
        return _heuristic_detect(stripped)

    # --- Primary detection via langdetect ---
    try:
        langs = detect_langs(stripped)
    except LangDetectException:
        _logger.debug("langdetect raised LangDetectException for input")
        return result

    if not langs:
        return result

    top = langs[0]
    # langdetect returns objects with .lang and .prob attributes
    lang_code = top.lang        # e.g. "en", "zh-cn", "ar"
    confidence = top.prob       # float 0.0 - 1.0

    result["detected_language"] = lang_code
    result["language_confidence"] = round(confidence, 4)

    # --- Determine non-English status ---
    is_english = lang_code.startswith("en")

    if not is_english and confidence >= _MIN_CONFIDENCE:
        result["is_non_english"] = True
        result["anomaly_flags"].append("non_english_input")

    # --- Mixed-language detection ---
    # Two signals: (1) langdetect returns multiple languages with
    # non-trivial probabilities, or (2) script-level heuristic detects
    # both Latin and non-Latin characters.
    if _has_mixed_scripts(stripped):
        if "mixed_language_input" not in result["anomaly_flags"]:
            result["anomaly_flags"].append("mixed_language_input")
        # If text is mixed but top detected language is English,
        # still flag as non-English since it contains non-English segments
        if is_english:
            result["is_non_english"] = True
            if "non_english_input" not in result["anomaly_flags"]:
                result["anomaly_flags"].append("non_english_input")

    # Also check langdetect multi-language output
    if len(langs) >= 2:
        second = langs[1]
        # If two languages both have significant probability, it is mixed
        if second.prob >= 0.2:
            if "mixed_language_input" not in result["anomaly_flags"]:
                result["anomaly_flags"].append("mixed_language_input")

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _heuristic_detect(text):
    """Fallback detection for short text using Unicode script analysis.

    For text shorter than _MIN_CHARS_FOR_DETECTION we do not trust
    langdetect but we can still check for non-Latin scripts which are
    a strong signal of non-English content.
    """
    result = {
        "detected_language": "unknown",
        "language_confidence": 0.0,
        "is_non_english": False,
        "anomaly_flags": [],
    }

    has_non_latin = bool(_NON_LATIN_RE.search(text))
    has_latin = bool(_LATIN_LETTER_RE.search(text))

    if has_non_latin and has_latin:
        # Mixed scripts in short text
        result["is_non_english"] = True
        result["anomaly_flags"].append("non_english_input")
        result["anomaly_flags"].append("mixed_language_input")
    elif has_non_latin and not has_latin:
        # Purely non-Latin short text
        result["is_non_english"] = True
        result["anomaly_flags"].append("non_english_input")
    # else: purely Latin short text -- treat as unknown/English, no flags

    return result


def _has_mixed_scripts(text):
    """Return True if text contains both Latin letters and non-Latin
    script characters.

    This is a strong heuristic for mixed-language content (e.g.
    English words mixed with CJK characters).
    """
    has_non_latin = bool(_NON_LATIN_RE.search(text))
    has_latin = bool(_LATIN_LETTER_RE.search(text))
    return has_non_latin and has_latin

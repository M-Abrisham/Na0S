import chardet

# BOM markers — checked before chardet for deterministic results
_BOM_MAP = [
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]

# Minimum confidence to trust chardet's detection
_MIN_CONFIDENCE = 0.5


def detect_encoding(raw_bytes):
    """Detect the encoding of raw bytes.

    Never assumes UTF-8 — always inspects the actual bytes first.

    Returns (encoding_name, confidence, flags).
    encoding_name is a Python codec name (e.g. "utf-8", "latin-1").
    """
    flags = []

    if not isinstance(raw_bytes, (bytes, bytearray)):
        return "utf-8", 1.0, []

    if not raw_bytes:
        return "utf-8", 1.0, []

    # Step 1: Check for BOM — deterministic, highest priority
    for bom, encoding in _BOM_MAP:
        if raw_bytes.startswith(bom):
            flags.append("bom_detected_{}".format(encoding))
            return encoding, 1.0, flags

    # Step 2: Use chardet for statistical detection
    result = chardet.detect(raw_bytes)
    encoding = result.get("encoding") or "utf-8"
    confidence = result.get("confidence", 0.0)

    # Normalize common aliases
    encoding = encoding.lower().replace("-", "_")
    alias_map = {
        "ascii": "utf-8",        # ASCII is a subset of UTF-8
        "iso_8859_1": "latin-1",
        "windows_1252": "cp1252",
    }
    encoding = alias_map.get(encoding, encoding).replace("_", "-")

    if confidence < _MIN_CONFIDENCE:
        flags.append("low_encoding_confidence_{:.0f}pct".format(confidence * 100))

    return encoding, confidence, flags


def decode_to_str(raw_bytes):
    """Decode raw bytes to a Python string using detected encoding.

    Returns (decoded_string, encoding_used, flags).
    """
    if isinstance(raw_bytes, str):
        return raw_bytes, "utf-8", []

    if not isinstance(raw_bytes, (bytes, bytearray)):
        return str(raw_bytes), "utf-8", ["coerced_to_str"]

    encoding, confidence, flags = detect_encoding(raw_bytes)

    # Strip BOM bytes before decoding
    for bom, bom_enc in _BOM_MAP:
        if raw_bytes.startswith(bom):
            raw_bytes = raw_bytes[len(bom):]
            break

    try:
        decoded = raw_bytes.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        # Fallback: decode as UTF-8 with replacement chars
        flags.append("encoding_fallback_utf8")
        decoded = raw_bytes.decode("utf-8", errors="replace")

    return decoded, encoding, flags

from .result import Layer0Result
from .validation import validate_input
from .encoding import decode_to_str
from .normalization import normalize_text
from .html_extractor import extract_safe_text
from .tokenization import check_tokenization_anomaly


def layer0_sanitize(raw_input):
    """Main Layer 0 entry point. Every input must pass through here first.

    Processing order:
        0. Encoding detection (bytes → str via chardet, never assume UTF-8)
        1. Fail-fast validation (type, empty, size)
        2. Unicode normalization (NFKC + invisible chars + whitespace)
        3. HTML safe extraction (strip tags, detect hidden content)

    Returns a Layer0Result with sanitized text and metadata.
    """
    all_flags = []

    # Step 0: Encoding detection — decode bytes before anything else
    if isinstance(raw_input, (bytes, bytearray)):
        raw_input, encoding_used, enc_flags = decode_to_str(raw_input)
        all_flags.extend(enc_flags)

    # Step 1: Fail-fast validation
    rejection = validate_input(raw_input)
    if rejection is not None:
        rejection.anomaly_flags = all_flags + rejection.anomaly_flags
        return rejection

    original_length = len(raw_input)

    # Step 2: Normalization
    text, chars_stripped, norm_flags = normalize_text(raw_input)
    all_flags.extend(norm_flags)

    # Post-normalization empty check — all-invisible input passes validate_input()
    # but becomes empty after stripping. Reject it here.
    if not text or not text.strip():
        return Layer0Result(
            sanitized_text="",
            original_length=original_length,
            chars_stripped=original_length,
            anomaly_flags=all_flags,
            rejected=True,
            rejection_reason="Input reduced to empty after normalization",
        )

    # Step 3: HTML safe extraction
    text, html_flags = extract_safe_text(text)
    all_flags.extend(html_flags)

    # Step 4: Tokenization anomaly detection + fingerprinting
    tok_flags, token_char_ratio, fingerprint = check_tokenization_anomaly(text)
    all_flags.extend(tok_flags)

    # Calculate total characters removed (normalization + HTML stripping)
    total_stripped = original_length - len(text)

    return Layer0Result(
        sanitized_text=text,
        original_length=original_length,
        chars_stripped=total_stripped,
        anomaly_flags=all_flags,
        token_char_ratio=token_char_ratio,
        fingerprint=fingerprint,
        rejected=False,
        rejection_reason="",
    )

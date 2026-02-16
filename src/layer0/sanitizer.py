import logging
import pathlib

from .result import Layer0Result
from .validation import validate_input
from .encoding import decode_to_str
from .normalization import normalize_text
from .html_extractor import extract_safe_text
from .tokenization import check_tokenization_anomaly
from .content_type import detect_content_type
from .input_loader import load_input, InputLoadError
from .mime_parser import parse_mime_input, _looks_like_mime
from .ocr_extractor import (
    OCRResult,
    detect_image_format,
    extract_text_from_image,
)
from .doc_extractor import (
    DocResult,
    detect_doc_type,
    extract_text_from_document,
)

_logger = logging.getLogger(__name__)


def layer0_sanitize(raw_input):
    """Main Layer 0 entry point. Every input must pass through here first.

    Processing order:
        -1. Input loading (file path, URL, pathlib.Path -> bytes/str)
        0. MIME detection and parsing (email-format inputs)
        0b. Encoding detection (bytes -> str via chardet, never assume UTF-8)
        1. Fail-fast validation (type, empty, size)
        2. Unicode normalization (NFKC + invisible chars + whitespace)
        3. HTML safe extraction (strip tags, detect hidden content)

    Accepts: str, bytes, pathlib.Path, file path string, URL string.
    Returns a Layer0Result with sanitized text and metadata.
    """
    all_flags = []
    source_metadata = {}

    # Step -1: Input loading — resolve file paths, URLs, pathlib.Path
    # Only invoke loader for types that need resolution (Path, URL, file path)
    needs_loading = (
        isinstance(raw_input, pathlib.Path)
        or (
            isinstance(raw_input, str)
            and (
                raw_input.startswith("http://")
                or raw_input.startswith("https://")
            )
        )
    )

    # Also check for file paths (strings that exist on disk),
    # but only for strings that are short enough to plausibly be paths
    # and are not URLs. We check os.path.exists only for strings <= 4096 chars
    # to avoid calling os.path.exists on large text inputs.
    if (
        not needs_loading
        and isinstance(raw_input, str)
        and len(raw_input) <= 4096
        and not raw_input.startswith("http://")
        and not raw_input.startswith("https://")
    ):
        import os
        if os.path.exists(raw_input):
            needs_loading = True

    if needs_loading:
        try:
            raw_input, source_metadata = load_input(raw_input)
            all_flags.append("input_loaded_from_{}".format(
                source_metadata.get("source_type", "unknown")
            ))
        except InputLoadError as exc:
            return Layer0Result(
                rejected=True,
                rejection_reason="Input load failed: {}".format(exc),
                source_metadata=source_metadata,
            )

    # Step 0a: Binary content-type detection on raw bytes — before any
    # decoding so we can inspect true magic bytes.  Executables are
    # rejected immediately; other binary types are flagged for
    # downstream layers (e.g. image OCR, doc parsing).
    if isinstance(raw_input, (bytes, bytearray)):
        ct_result = detect_content_type(raw_input)
        if ct_result.detected_type:
            all_flags.extend(ct_result.flags)
            source_metadata["content_type_detected"] = ct_result.detected_type
            source_metadata["content_type_mime"] = ct_result.mime_type
            source_metadata["content_type_tier"] = ct_result.tier
            if ct_result.reject:
                return Layer0Result(
                    rejected=True,
                    rejection_reason=ct_result.reject_reason,
                    anomaly_flags=all_flags,
                    source_metadata=source_metadata,
                )

    # Step 0: MIME detection — check if loaded bytes look like MIME
    if isinstance(raw_input, (bytes, bytearray)) and _looks_like_mime(raw_input):
        mime_result = parse_mime_input(raw_input)
        all_flags.append("mime_parsed")
        if mime_result.is_multipart:
            all_flags.append("mime_multipart")
        if mime_result.attachments:
            all_flags.append(
                "mime_attachments_count_{}".format(len(mime_result.attachments))
            )
        # Use the body text for sanitization pipeline
        if mime_result.body_text:
            raw_input = mime_result.body_text
            source_metadata["mime_content_type"] = mime_result.content_type
            source_metadata["mime_is_multipart"] = mime_result.is_multipart
            source_metadata["mime_attachment_count"] = len(mime_result.attachments)
            source_metadata["mime_attachments"] = [
                {
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size": att.size,
                }
                for att in mime_result.attachments
            ]

    # Step 0c: Image / document extraction — if raw bytes are a known
    # binary format, extract text before encoding-decoding.  This is an
    # extension point: when extraction libraries are not installed the
    # result is empty and we fall through to the normal bytes->str path.
    if isinstance(raw_input, (bytes, bytearray)):
        raw_input, all_flags, source_metadata = _try_binary_extraction(
            raw_input, all_flags, source_metadata,
        )

    # Step 0d-pre: Raw byte size guard — reject oversized binary payloads
    # BEFORE decoding.  Wide encodings (e.g. UTF-32) can shrink dramatically
    # when re-encoded to UTF-8, so checking the decoded string alone would
    # let an attacker smuggle oversized raw payloads past the byte limit.
    if isinstance(raw_input, (bytes, bytearray)):
        from .validation import MAX_INPUT_BYTES
        raw_byte_len = len(raw_input)
        if raw_byte_len > MAX_INPUT_BYTES:
            all_flags.append("raw_bytes_oversized")
            return Layer0Result(
                rejected=True,
                rejection_reason=(
                    "raw input exceeds {} byte limit (got {} bytes)"
                    .format(MAX_INPUT_BYTES, raw_byte_len)
                ),
                original_length=raw_byte_len,
                anomaly_flags=all_flags,
                source_metadata=source_metadata,
            )

    # Step 0d: Encoding detection — decode bytes before anything else
    if isinstance(raw_input, (bytes, bytearray)):
        raw_input, encoding_used, enc_flags = decode_to_str(raw_input)
        all_flags.extend(enc_flags)

    # Step 1: Fail-fast validation
    rejection = validate_input(raw_input)
    if rejection is not None:
        rejection.anomaly_flags = all_flags + rejection.anomaly_flags
        rejection.source_metadata = source_metadata
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
            source_metadata=source_metadata,
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
        source_metadata=source_metadata,
    )


# ---------------------------------------------------------------------------
# Binary content extraction helpers
# ---------------------------------------------------------------------------

# Map magic-byte doc types to the doc_type string expected by doc_extractor.
_MAGIC_TO_DOCTYPE = {
    "pdf": "pdf",
    "rtf": "rtf",
    "pk_office": None,  # needs further disambiguation
}


def _try_binary_extraction(raw_bytes, flags, metadata):
    """Attempt to extract text from binary image/document bytes.

    If the bytes match a known image or document signature AND the
    corresponding extraction library is installed, replaces the raw bytes
    with the extracted text string.  Otherwise returns the bytes unchanged.

    Parameters
    ----------
    raw_bytes : bytes
        The raw binary input.
    flags : list
        Accumulated anomaly flags (mutated in place via extend).
    metadata : dict
        Source metadata dict (mutated in place).

    Returns
    -------
    tuple of (str | bytes, list, dict)
        ``(possibly_extracted_text_or_original_bytes, flags, metadata)``
    """
    # --- Check for image formats first ---
    img_fmt = detect_image_format(raw_bytes)
    if img_fmt is not None:
        flags.append("image_detected_{}".format(img_fmt))
        metadata["detected_image_format"] = img_fmt
        ocr_result = extract_text_from_image(raw_bytes)
        if ocr_result.warnings:
            for w in ocr_result.warnings:
                _logger.debug("OCR warning: %s", w)
        metadata["ocr_engine"] = ocr_result.engine
        metadata["ocr_confidence"] = ocr_result.confidence
        if ocr_result.text:
            flags.append("ocr_text_extracted")
            return ocr_result.text, flags, metadata
        else:
            flags.append("ocr_no_text")
            return raw_bytes, flags, metadata

    # --- Check for document formats ---
    doc_type_key = detect_doc_type(raw_bytes)
    if doc_type_key is not None:
        # Resolve PK-based office formats via source_metadata hint or
        # by attempting DOCX first (most common).
        dtype = _MAGIC_TO_DOCTYPE.get(doc_type_key)
        if doc_type_key == "pk_office":
            # Use hint from input_loader if available, else try docx
            hint = metadata.get("file_extension", "").lower().lstrip(".")
            if hint in ("xlsx", "pptx", "docx"):
                dtype = hint
            else:
                dtype = "docx"  # default for PK archives

        if dtype:
            flags.append("document_detected_{}".format(dtype))
            metadata["detected_doc_type"] = dtype
            doc_result = extract_text_from_document(raw_bytes, dtype)
            if doc_result.warnings:
                for w in doc_result.warnings:
                    _logger.debug("Doc extraction warning: %s", w)
            metadata["doc_engine"] = doc_result.engine
            metadata["doc_page_count"] = doc_result.page_count
            if doc_result.metadata:
                metadata["doc_metadata"] = doc_result.metadata
            if doc_result.text:
                flags.append("doc_text_extracted")
                return doc_result.text, flags, metadata
            else:
                flags.append("doc_no_text")

    return raw_bytes, flags, metadata

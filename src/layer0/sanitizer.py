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
from .language_detector import detect_language
from .pii_detector import scan_pii
from .mime_parser import parse_mime_input, _looks_like_mime
from .ocr_extractor import (
    OCRResult,
    ImageMetadataResult,
    detect_image_format,
    extract_text_from_image,
    extract_image_metadata,
)
from .doc_extractor import (
    DocResult,
    detect_doc_type,
    detect_pdf_javascript,
    extract_text_from_document,
)
from .timeout import (
    Layer0TimeoutError,
    L0_PIPELINE_TIMEOUT,
    get_step_timeout,
    with_timeout,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MIME family mapping for content-type mismatch detection
# ---------------------------------------------------------------------------
# Maps MIME types to a canonical "family" label.  Two declared/detected types
# are considered a mismatch only when their families differ.
#
# Design decisions:
#   - application/octet-stream is generic ("unknown binary"); servers and
#     file-extension guessers emit it as a catch-all, so it MUST NOT trigger
#     a mismatch.
#   - Minor variations within a family (e.g. image/jpeg vs image/png) are
#     NOT mismatches -- both are images.
#   - text/* is one family; an HTML file declared as text/plain is still
#     "text family".  The HTML extractor handles sub-type nuances.

_MIME_FAMILY_MAP = {
    # --- Text ---
    "text/plain": "text",
    "text/html": "text",
    "text/xml": "text",
    "text/css": "text",
    "text/csv": "text",
    "text/javascript": "text",
    "text/x-shellscript": "text",
    "application/json": "text",
    "application/xml": "text",
    "application/javascript": "text",
    # --- Documents ---
    "application/pdf": "document",
    "application/rtf": "document",
    "application/x-ole-storage": "document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "document",
    "application/vnd.openxmlformats-officedocument": "document",
    "application/vnd.oasis.opendocument": "document",
    "application/msword": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    # --- Images ---
    "image/png": "image",
    "image/jpeg": "image",
    "image/gif": "image",
    "image/bmp": "image",
    "image/tiff": "image",
    "image/webp": "image",
    "image/vnd.adobe.photoshop": "image",
    "image/x-icon": "image",
    "image/svg+xml": "image",
    # --- Audio ---
    "audio/mpeg": "audio",
    "audio/flac": "audio",
    "audio/ogg": "audio",
    "audio/aac": "audio",
    "audio/midi": "audio",
    "audio/wav": "audio",
    "audio/aiff": "audio",
    "audio/x-wav": "audio",
    # --- Video ---
    "video/webm": "video",
    "video/x-flv": "video",
    "video/x-ms-wmv": "video",
    "video/x-msvideo": "video",
    "video/mp4": "video",
    "video/quicktime": "video",
    # --- Archives ---
    "application/zip": "archive",
    "application/gzip": "archive",
    "application/x-7z-compressed": "archive",
    "application/x-rar-compressed": "archive",
    "application/x-bzip2": "archive",
    "application/x-xz": "archive",
    "application/x-lzma": "archive",
    "application/x-tar": "archive",
    "application/java-archive": "archive",
    # --- Executables ---
    "application/x-dosexec": "executable",
    "application/x-elf": "executable",
    "application/x-mach-binary": "executable",
    "application/wasm": "executable",
    "application/x-executable": "executable",
    "application/x-sharedlib": "executable",
}

# Types that are too generic to trigger a mismatch
_GENERIC_TYPES = frozenset([
    "application/octet-stream",
    "",
    None,
])


def _get_mime_family(mime_type):
    """Return the canonical family label for a MIME type.

    Falls back to the top-level type (e.g. ``"image"`` for any
    ``image/*``) when the exact MIME is not in the map.
    Returns ``None`` for generic / unknown types.
    """
    if not mime_type or mime_type in _GENERIC_TYPES:
        return None

    # Strip parameters (e.g. "text/html; charset=utf-8" -> "text/html")
    base = mime_type.split(";")[0].strip().lower()

    if base in _GENERIC_TYPES:
        return None

    # Exact lookup first
    family = _MIME_FAMILY_MAP.get(base)
    if family:
        return family

    # Fallback: use the top-level type as family (e.g. "image" for "image/x-foo")
    top_level = base.split("/")[0] if "/" in base else None
    if top_level in ("text", "image", "audio", "video"):
        return top_level

    return None


def _check_content_type_mismatch(source_metadata, ct_result):
    """Compare declared content type vs magic-byte detected type.

    Parameters
    ----------
    source_metadata : dict
        Metadata from input_loader containing ``"content_type"`` (declared
        MIME from HTTP header or file extension).
    ct_result : ContentTypeResult
        Result from ``detect_content_type()`` with the magic-byte detected
        ``mime_type``.

    Returns
    -------
    list[str]
        Anomaly flags to add (empty list if no mismatch).
    """
    declared_mime = source_metadata.get("content_type")
    detected_mime = ct_result.mime_type if ct_result else None

    # Nothing to compare if either side is missing or generic
    if not declared_mime or not detected_mime:
        return []

    declared_family = _get_mime_family(declared_mime)
    detected_family = _get_mime_family(detected_mime)

    # If either side resolves to None (generic/unknown), no mismatch
    if declared_family is None or detected_family is None:
        return []

    # Same family -> no mismatch
    if declared_family == detected_family:
        return []

    # Genuine mismatch detected
    source_metadata["content_type_mismatch"] = {
        "declared_type": declared_mime,
        "declared_family": declared_family,
        "detected_type": detected_mime,
        "detected_family": detected_family,
    }
    _logger.warning(
        "Content-type mismatch: declared=%s (%s) vs detected=%s (%s)",
        declared_mime, declared_family, detected_mime, detected_family,
    )
    return ["content_type_mismatch"]


def layer0_sanitize(raw_input):
    """Main Layer 0 entry point. Every input must pass through here first.

    Wraps the internal pipeline with a wall-clock timeout
    (``L0_PIPELINE_TIMEOUT`` seconds).  If the entire pipeline exceeds
    this budget, returns a rejected ``Layer0Result``.

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
    try:
        return with_timeout(
            _layer0_sanitize_inner,
            L0_PIPELINE_TIMEOUT,
            raw_input,
            step_name="layer0_pipeline",
        )
    except Layer0TimeoutError:
        _logger.warning(
            "Layer 0 pipeline timed out after %.1fs", L0_PIPELINE_TIMEOUT,
        )
        return Layer0Result(
            rejected=True,
            rejection_reason="Processing timeout: Layer 0 pipeline exceeded {:.0f}s limit".format(
                L0_PIPELINE_TIMEOUT
            ),
            anomaly_flags=["timeout_pipeline"],
        )


def _layer0_sanitize_inner(raw_input):
    """Internal Layer 0 pipeline — called by layer0_sanitize with timeout."""
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

            # Step 0a-mismatch: Compare declared type (HTTP header / file
            # extension) against magic-byte detected type.  Runs BEFORE
            # the reject gate so the flag is present even on rejected inputs.
            mismatch_flags = _check_content_type_mismatch(
                source_metadata, ct_result,
            )
            all_flags.extend(mismatch_flags)

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

    # Step 2: Normalization (with per-step timeout)
    try:
        text, chars_stripped, norm_flags = with_timeout(
            normalize_text,
            get_step_timeout("normalize"),
            raw_input,
            step_name="normalize",
        )
    except Layer0TimeoutError:
        all_flags.append("timeout_normalize")
        return Layer0Result(
            rejected=True,
            rejection_reason="Processing timeout: normalization step",
            original_length=original_length,
            anomaly_flags=all_flags,
            source_metadata=source_metadata,
        )
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

    # Step 3: HTML safe extraction (with per-step timeout)
    try:
        text, html_flags = with_timeout(
            extract_safe_text,
            get_step_timeout("html"),
            text,
            step_name="html",
        )
    except Layer0TimeoutError:
        all_flags.append("timeout_html")
        return Layer0Result(
            rejected=True,
            rejection_reason="Processing timeout: HTML extraction step",
            original_length=original_length,
            anomaly_flags=all_flags,
            source_metadata=source_metadata,
        )
    all_flags.extend(html_flags)

    # Step 4: Tokenization anomaly detection + fingerprinting (with per-step timeout)
    try:
        tok_flags, token_char_ratio, fingerprint = with_timeout(
            check_tokenization_anomaly,
            get_step_timeout("tokenize"),
            text,
            step_name="tokenize",
        )
    except Layer0TimeoutError:
        all_flags.append("timeout_tokenize")
        return Layer0Result(
            rejected=True,
            rejection_reason="Processing timeout: tokenization step",
            original_length=original_length,
            anomaly_flags=all_flags,
            source_metadata=source_metadata,
        )
    all_flags.extend(tok_flags)

    # Calculate total characters removed (normalization + HTML stripping)
    total_stripped = original_length - len(text)

    # Step 5: Language detection for multilingual routing
    lang_result = detect_language(text)
    if lang_result["anomaly_flags"]:
        all_flags.extend(lang_result["anomaly_flags"])
    source_metadata["language"] = {
        "detected": lang_result["detected_language"],
        "confidence": lang_result["language_confidence"],
        "is_non_english": lang_result["is_non_english"],
    }

    # Step 6: PII / secrets pre-screening
    pii_result = scan_pii(text)
    if pii_result.has_pii:
        all_flags.extend(sorted(pii_result.anomaly_flags))
        source_metadata["pii_scan"] = {
            "has_pii": True,
            "pii_types_found": pii_result.pii_types_found,
            "pii_count": pii_result.pii_count,
            "details": pii_result.details,
        }

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

        # --- EXIF/XMP metadata text extraction ---
        meta_result = extract_image_metadata(raw_bytes)
        if meta_result.warnings:
            for w in meta_result.warnings:
                _logger.debug("Image metadata warning: %s", w)
        if meta_result.has_metadata_text:
            flags.append("image_metadata_text")
            metadata["image_metadata_fields"] = meta_result.metadata_fields
            metadata["image_metadata_text"] = meta_result.metadata_text

        # Combine OCR text + metadata text for downstream scanning
        combined_parts = []
        if ocr_result.text:
            flags.append("ocr_text_extracted")
            combined_parts.append(ocr_result.text)
        else:
            flags.append("ocr_no_text")

        if meta_result.has_metadata_text:
            combined_parts.append(meta_result.metadata_text)

        if combined_parts:
            return "\n".join(combined_parts), flags, metadata
        else:
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
                    # Extract anomaly flags emitted by detect_pdf_javascript
                    if w.startswith("flag:"):
                        flags.append(w[5:])  # strip "flag:" prefix
                    else:
                        _logger.debug("Doc extraction warning: %s", w)
            metadata["doc_engine"] = doc_result.engine
            metadata["doc_page_count"] = doc_result.page_count
            if doc_result.metadata:
                metadata["doc_metadata"] = doc_result.metadata

            # Run PDF JavaScript detection directly for PDFs (ensures
            # detection even when text extraction fails or no PDF lib
            # is installed -- the byte scan is independent of parsing).
            if dtype == "pdf":
                js_result = detect_pdf_javascript(raw_bytes)
                if js_result["has_javascript"]:
                    for js_flag in sorted(js_result["anomaly_flags"]):
                        if js_flag not in flags:
                            flags.append(js_flag)
                    metadata["pdf_js_detection"] = js_result

            if doc_result.text:
                flags.append("doc_text_extracted")
                return doc_result.text, flags, metadata
            else:
                flags.append("doc_no_text")

    return raw_bytes, flags, metadata

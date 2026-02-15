"""OCR text extraction from images for Layer 0 pipeline.

Extracts text from image data (PNG, JPEG, GIF, BMP, TIFF, WebP) using
OCR engines.  Engine priority: EasyOCR > pytesseract > none.

ALL imports are optional.  When no OCR library is installed the module
still loads and ``extract_text_from_image`` returns an empty
``OCRResult`` with ``engine="none"`` so the rest of the pipeline
continues without error.
"""

from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency probing
# ---------------------------------------------------------------------------

_HAS_PIL = False
try:
    from PIL import Image  # type: ignore[import-untyped]

    _HAS_PIL = True
except ImportError:
    pass

_HAS_EASYOCR = False
try:
    import easyocr  # type: ignore[import-untyped]

    _HAS_EASYOCR = True
except ImportError:
    pass

_HAS_TESSERACT = False
try:
    import pytesseract  # type: ignore[import-untyped]

    _HAS_TESSERACT = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Maximum allowed image size in bytes (default 10 MB, env-configurable).
MAX_IMAGE_BYTES: int = int(os.getenv("L0_MAX_IMAGE_BYTES", 10 * 1024 * 1024))

#: Supported image magic-byte signatures.
_IMAGE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"II\x2a\x00", "tiff"),  # little-endian TIFF
    (b"MM\x00\x2a", "tiff"),  # big-endian TIFF
    (b"RIFF", "webp"),        # WebP is a RIFF container
]

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class OCRResult:
    """Result of an OCR extraction attempt.

    Attributes:
        text:       Extracted text (empty string if extraction failed).
        confidence: Engine-reported confidence [0.0, 1.0].  0.0 when no
                    extraction was performed.
        engine:     Name of the engine that produced the result
                    (``"easyocr"``, ``"tesseract"``, or ``"none"``).
        language:   Language code used/detected (e.g. ``"en"``).
        warnings:   Non-fatal issues encountered during extraction.
    """

    text: str = ""
    confidence: float = 0.0
    engine: str = "none"
    language: str = ""
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_image_format(data: bytes) -> str | None:
    """Return the image format string if *data* matches a known signature.

    Returns ``None`` if the bytes do not match any known image header.
    """
    for sig, fmt in _IMAGE_SIGNATURES:
        if fmt == "webp":
            # WebP: RIFF....WEBP
            if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
                return "webp"
        elif data[: len(sig)] == sig:
            return fmt
    return None


def extract_text_from_image(
    image_data: bytes,
    *,
    language: str = "en",
    max_bytes: int | None = None,
) -> OCRResult:
    """Extract text from raw image bytes.

    Parameters
    ----------
    image_data:
        Raw bytes of the image file.
    language:
        Language hint for the OCR engine (ISO 639-1, default ``"en"``).
    max_bytes:
        Override for the maximum allowed image size.  ``None`` uses the
        module-level ``MAX_IMAGE_BYTES`` constant.

    Returns
    -------
    OCRResult
        Always returns a result -- never raises.  If no library is
        available or the image cannot be processed, the ``text`` field
        is empty and ``engine`` is ``"none"``.
    """
    effective_max = max_bytes if max_bytes is not None else MAX_IMAGE_BYTES
    result_warnings: list[str] = []

    # --- Guard: size limit ---------------------------------------------------
    if len(image_data) > effective_max:
        return OCRResult(
            text="",
            confidence=0.0,
            engine="none",
            language=language,
            warnings=[
                "Image exceeds size limit ({} bytes > {} bytes)".format(
                    len(image_data), effective_max
                )
            ],
        )

    # --- Guard: PIL is required to decode image bytes ------------------------
    if not _HAS_PIL:
        return OCRResult(
            text="",
            confidence=0.0,
            engine="none",
            language=language,
            warnings=["Pillow (PIL) is not installed -- cannot decode images"],
        )

    # --- Guard: at least one OCR engine must be installed --------------------
    if not _HAS_EASYOCR and not _HAS_TESSERACT:
        return OCRResult(
            text="",
            confidence=0.0,
            engine="none",
            language=language,
            warnings=[
                "No OCR engine installed (install easyocr or pytesseract)"
            ],
        )

    # --- Load image via PIL --------------------------------------------------
    try:
        img = Image.open(io.BytesIO(image_data))
        img.load()  # force decode so corrupt data is caught here
    except Exception as exc:
        return OCRResult(
            text="",
            confidence=0.0,
            engine="none",
            language=language,
            warnings=["Failed to decode image: {}".format(exc)],
        )

    # --- Try EasyOCR first (better accuracy) ---------------------------------
    if _HAS_EASYOCR:
        try:
            reader = easyocr.Reader([language], gpu=False, verbose=False)
            import numpy as np  # type: ignore[import-untyped]

            img_array = np.array(img.convert("RGB"))
            results = reader.readtext(img_array)

            if results:
                texts = [entry[1] for entry in results]
                confidences = [entry[2] for entry in results]
                avg_confidence = sum(confidences) / len(confidences)
                return OCRResult(
                    text="\n".join(texts),
                    confidence=round(avg_confidence, 4),
                    engine="easyocr",
                    language=language,
                    warnings=result_warnings,
                )
            else:
                result_warnings.append("EasyOCR returned no text")
                if not _HAS_TESSERACT:
                    return OCRResult(
                        text="",
                        confidence=0.0,
                        engine="easyocr",
                        language=language,
                        warnings=result_warnings,
                    )
        except Exception as exc:
            logger.warning("EasyOCR failed, trying Tesseract: %s", exc)
            result_warnings.append("EasyOCR error: {}".format(exc))
            if not _HAS_TESSERACT:
                return OCRResult(
                    text="",
                    confidence=0.0,
                    engine="none",
                    language=language,
                    warnings=result_warnings,
                )

    # --- Fall back to pytesseract --------------------------------------------
    if _HAS_TESSERACT:
        try:
            tess_lang = _iso_to_tesseract_lang(language)
            text = pytesseract.image_to_string(img, lang=tess_lang)
            confidence = _tesseract_confidence(img, tess_lang)
            return OCRResult(
                text=text.strip(),
                confidence=confidence,
                engine="tesseract",
                language=language,
                warnings=result_warnings,
            )
        except Exception as exc:
            result_warnings.append("Tesseract error: {}".format(exc))
            return OCRResult(
                text="",
                confidence=0.0,
                engine="none",
                language=language,
                warnings=result_warnings,
            )

    # Should not reach here, but just in case
    return OCRResult(
        text="",
        confidence=0.0,
        engine="none",
        language=language,
        warnings=result_warnings + ["No OCR engine produced output"],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Minimal ISO 639-1 -> Tesseract language mapping
_ISO_TO_TESS: dict[str, str] = {
    "en": "eng",
    "de": "deu",
    "fr": "fra",
    "es": "spa",
    "it": "ita",
    "pt": "por",
    "zh": "chi_sim",
    "ja": "jpn",
    "ko": "kor",
    "ar": "ara",
    "ru": "rus",
    "hi": "hin",
    "nl": "nld",
    "sv": "swe",
    "pl": "pol",
    "tr": "tur",
}


def _iso_to_tesseract_lang(iso_code: str) -> str:
    """Convert ISO 639-1 language code to Tesseract language code."""
    return _ISO_TO_TESS.get(iso_code, iso_code)


def _tesseract_confidence(img, lang: str) -> float:
    """Compute average word-level confidence from Tesseract OSD data.

    Returns 0.0 if detailed data cannot be obtained.
    """
    try:
        data = pytesseract.image_to_data(
            img, lang=lang, output_type=pytesseract.Output.DICT
        )
        confs = [
            int(c)
            for c in data.get("conf", [])
            if str(c).lstrip("-").isdigit() and int(c) >= 0
        ]
        if confs:
            return round(sum(confs) / len(confs) / 100.0, 4)
    except Exception:
        pass
    return 0.0

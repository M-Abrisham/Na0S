"""Binary content-type detection via magic byte signatures.

Provides tiered file-type detection for injection-relevant formats.
No external dependencies — all detection is manual byte comparison.

Tiers:
    CRITICAL — Executables: always reject (MZ, ELF, Mach-O, Java class, WASM, shebang)
    HIGH     — Documents (PDF, RTF, OOXML, OLE2), Archives (ZIP, GZIP, 7z, RAR, BZIP2),
               Images (PNG, JPEG, GIF, BMP, TIFF, WebP, PSD, ICO)
    MEDIUM   — Audio (WAV, MP3, FLAC, OGG, AAC, MIDI, AIFF),
               Video (AVI, WebM/MKV, MP4, FLV, WMV)
"""

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ContentTypeResult:
    """Result of binary content-type detection.

    Attributes:
        detected_type: Short format name (e.g. "pdf", "png", "exe_pe") or "".
        mime_type: Approximate MIME string (e.g. "application/pdf") or "".
        tier: "CRITICAL", "HIGH", "MEDIUM", or "".
        category: Broad category flag such as "embedded_executable".
        flags: List of anomaly flags to propagate
               (e.g. ["embedded_pdf", "embedded_document"]).
        reject: True when the file should be rejected outright.
        reject_reason: Human-readable rejection reason (empty when not rejected).
    """

    detected_type: str = ""
    mime_type: str = ""
    tier: str = ""
    category: str = ""
    flags: list = field(default_factory=list)
    reject: bool = False
    reject_reason: str = ""


# ---------------------------------------------------------------------------
# Signature tables
# ---------------------------------------------------------------------------
# Each entry: (byte_prefix, offset, detected_type, mime, tier, category, sub_flag)
# offset = starting byte position for comparison (usually 0).
# RIFF/FORM containers and PK archives are handled by dedicated helpers.

_SIGNATURES = [
    # ---- CRITICAL: Executables ----
    (b"MZ",                0, "exe_pe",       "application/x-dosexec",     "CRITICAL", "embedded_executable", "embedded_exe"),
    (b"\x7fELF",           0, "exe_elf",      "application/x-elf",         "CRITICAL", "embedded_executable", "embedded_elf"),
    (b"\xfe\xed\xfa\xce",  0, "exe_macho32",  "application/x-mach-binary", "CRITICAL", "embedded_executable", "embedded_macho"),
    (b"\xfe\xed\xfa\xcf",  0, "exe_macho64",  "application/x-mach-binary", "CRITICAL", "embedded_executable", "embedded_macho"),
    (b"\xce\xfa\xed\xfe",  0, "exe_macho32r", "application/x-mach-binary", "CRITICAL", "embedded_executable", "embedded_macho"),
    (b"\xcf\xfa\xed\xfe",  0, "exe_macho64r", "application/x-mach-binary", "CRITICAL", "embedded_executable", "embedded_macho"),
    (b"\xca\xfe\xba\xbe",  0, "java_class",   "application/java",          "CRITICAL", "embedded_executable", "embedded_java_class"),
    (b"\x00asm",           0, "wasm",         "application/wasm",          "CRITICAL", "embedded_executable", "embedded_wasm"),
    (b"#!",                0, "shebang",      "text/x-shellscript",        "CRITICAL", "embedded_executable", "embedded_shebang"),

    # ---- HIGH: Documents ----
    (b"%PDF",              0, "pdf",  "application/pdf", "HIGH", "embedded_document", "embedded_pdf"),
    (b"{\\rtf",            0, "rtf",  "application/rtf", "HIGH", "embedded_document", "embedded_rtf"),
    # OLE2 compound (legacy DOC/XLS/PPT)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole2", "application/x-ole-storage", "HIGH", "embedded_document", "embedded_ole2"),

    # ---- HIGH: Images ----
    (b"\x89PNG\r\n\x1a\n", 0, "png",     "image/png",                 "HIGH", "embedded_image", "embedded_png"),
    (b"\xff\xd8\xff",      0, "jpeg",    "image/jpeg",                "HIGH", "embedded_image", "embedded_jpeg"),
    (b"GIF87a",            0, "gif",     "image/gif",                 "HIGH", "embedded_image", "embedded_gif"),
    (b"GIF89a",            0, "gif",     "image/gif",                 "HIGH", "embedded_image", "embedded_gif"),
    (b"BM",                0, "bmp",     "image/bmp",                 "HIGH", "embedded_image", "embedded_bmp"),
    (b"II*\x00",           0, "tiff_le", "image/tiff",                "HIGH", "embedded_image", "embedded_tiff"),
    (b"MM\x00*",           0, "tiff_be", "image/tiff",                "HIGH", "embedded_image", "embedded_tiff"),
    (b"8BPS",              0, "psd",     "image/vnd.adobe.photoshop", "HIGH", "embedded_image", "embedded_psd"),
    (b"\x00\x00\x01\x00",  0, "ico",     "image/x-icon",              "HIGH", "embedded_image", "embedded_ico"),

    # ---- HIGH: Archives ----
    (b"\x1f\x8b\x08",     0, "gzip",  "application/gzip",             "HIGH", "embedded_archive", "embedded_gzip"),
    (b"7z\xbc\xaf'\x1c",  0, "7z",    "application/x-7z-compressed",  "HIGH", "embedded_archive", "embedded_7z"),
    (b"Rar!\x1a\x07",     0, "rar",   "application/x-rar-compressed", "HIGH", "embedded_archive", "embedded_rar"),
    (b"BZh",               0, "bzip2", "application/x-bzip2",          "HIGH", "embedded_archive", "embedded_bzip2"),

    # ---- MEDIUM: Audio ----
    (b"ID3",               0, "mp3_id3",  "audio/mpeg",  "MEDIUM", "embedded_audio", "embedded_mp3"),
    (b"\xff\xfb",          0, "mp3_sync", "audio/mpeg",  "MEDIUM", "embedded_audio", "embedded_mp3"),
    (b"\xff\xf3",          0, "mp3_sync", "audio/mpeg",  "MEDIUM", "embedded_audio", "embedded_mp3"),
    (b"\xff\xf2",          0, "mp3_sync", "audio/mpeg",  "MEDIUM", "embedded_audio", "embedded_mp3"),
    (b"fLaC",              0, "flac",     "audio/flac",  "MEDIUM", "embedded_audio", "embedded_flac"),
    (b"OggS",              0, "ogg",      "audio/ogg",   "MEDIUM", "embedded_audio", "embedded_ogg"),
    (b"\xff\xf1",          0, "aac",      "audio/aac",   "MEDIUM", "embedded_audio", "embedded_aac"),
    (b"\xff\xf9",          0, "aac",      "audio/aac",   "MEDIUM", "embedded_audio", "embedded_aac"),
    (b"MThd",              0, "midi",     "audio/midi",  "MEDIUM", "embedded_audio", "embedded_midi"),

    # ---- MEDIUM: Video ----
    (b"\x1aE\xdf\xa3",    0, "ebml", "video/webm",      "MEDIUM", "embedded_video", "embedded_webm"),
    (b"FLV\x01",          0, "flv",  "video/x-flv",     "MEDIUM", "embedded_video", "embedded_flv"),
    (b"0&\xb2u",          0, "wmv",  "video/x-ms-wmv",  "MEDIUM", "embedded_video", "embedded_wmv"),
]

# RIFF container: bytes 0-3 = "RIFF", bytes 8-11 = sub-type
_RIFF_SUBTYPES = {
    b"WAVE": ("wav",  "audio/wav",       "MEDIUM", "embedded_audio", "embedded_wav"),
    b"AVI ": ("avi",  "video/x-msvideo", "MEDIUM", "embedded_video", "embedded_avi"),
    b"WEBP": ("webp", "image/webp",      "HIGH",   "embedded_image", "embedded_webp"),
}

# AIFF container: bytes 0-3 = "FORM", bytes 8-11 = "AIFF" or "AIFC"
_FORM_SUBTYPES = {
    b"AIFF": ("aiff", "audio/aiff", "MEDIUM", "embedded_audio", "embedded_aiff"),
    b"AIFC": ("aiff", "audio/aiff", "MEDIUM", "embedded_audio", "embedded_aiff"),
}

# PK (ZIP-based) sub-type detection: look for internal paths in first 2 KB
_PK_HEADER = b"PK\x03\x04"
_PK_OOXML_MARKERS = [
    (b"word/",           "docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    (b"xl/",             "xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    (b"ppt/",            "pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    (b"[Content_Types]", "ooxml", "application/vnd.openxmlformats-officedocument"),
    (b"content.xml",     "odf",   "application/vnd.oasis.opendocument"),
    (b"META-INF/",       "jar",   "application/java-archive"),
]

# MP4 / MOV: "ftyp" box at offset 4
_FTYP_MARKER = b"ftyp"


# ---------------------------------------------------------------------------
# Base64 / Data URI detection (string-level)
# ---------------------------------------------------------------------------

# Matches base64 blobs >= 64 chars (likely binary payload, not short tokens)
_BASE64_BLOB_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
)

# Data URI scheme:  data:[<mediatype>][;base64],<data>
_DATA_URI_RE = re.compile(
    r"data:([a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*"
    r"(?:/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*)?)?"
    r"(?:;[a-zA-Z0-9\-]+=[a-zA-Z0-9\-]+)*"
    r";base64,"
    r"([A-Za-z0-9+/=]{20,})",
    re.ASCII,
)


# ---------------------------------------------------------------------------
# Core detection function (bytes input)
# ---------------------------------------------------------------------------

def detect_content_type(data):
    """Detect the real content type of raw bytes via magic-byte signatures.

    Checks tiers in priority order: CRITICAL > HIGH > MEDIUM.
    Returns a ContentTypeResult; ``result.detected_type`` is the empty
    string when no known binary signature is found (i.e. likely text).

    Args:
        data: bytes or bytearray to inspect.
    """
    if not isinstance(data, (bytes, bytearray)):
        return ContentTypeResult()

    if len(data) < 2:
        return ContentTypeResult()

    # --- RIFF container (needs 12 bytes) ---
    if len(data) >= 12 and data[:4] == b"RIFF":
        sub = data[8:12]
        if sub in _RIFF_SUBTYPES:
            dtype, mime, tier, cat, subflag = _RIFF_SUBTYPES[sub]
            return ContentTypeResult(
                detected_type=dtype, mime_type=mime, tier=tier,
                category=cat, flags=[subflag, cat],
            )
        # Unknown RIFF sub-type -- still flag it
        return ContentTypeResult(
            detected_type="riff_unknown",
            mime_type="application/octet-stream",
            tier="MEDIUM", category="embedded_archive",
            flags=["embedded_riff_unknown", "embedded_archive"],
        )

    # --- FORM container (AIFF) ---
    if len(data) >= 12 and data[:4] == b"FORM":
        sub = data[8:12]
        if sub in _FORM_SUBTYPES:
            dtype, mime, tier, cat, subflag = _FORM_SUBTYPES[sub]
            return ContentTypeResult(
                detected_type=dtype, mime_type=mime, tier=tier,
                category=cat, flags=[subflag, cat],
            )

    # --- PK / ZIP-based (OOXML, ODF, JAR, plain ZIP) ---
    if len(data) >= 4 and data[:4] == _PK_HEADER:
        return _check_pk_archive(data)

    # --- MP4 / MOV: "ftyp" at offset 4 ---
    if len(data) >= 8 and data[4:8] == _FTYP_MARKER:
        return ContentTypeResult(
            detected_type="mp4", mime_type="video/mp4",
            tier="MEDIUM", category="embedded_video",
            flags=["embedded_mp4", "embedded_video"],
        )

    # --- TAR: "ustar" at offset 257 ---
    if len(data) >= 262 and data[257:262] == b"ustar":
        return ContentTypeResult(
            detected_type="tar", mime_type="application/x-tar",
            tier="HIGH", category="embedded_archive",
            flags=["embedded_tar", "embedded_archive"],
        )

    # --- Linear scan of signature table ---
    for sig, offset, dtype, mime, tier, cat, subflag in _SIGNATURES:
        end = offset + len(sig)
        if len(data) >= end and data[offset:end] == sig:
            reject = (tier == "CRITICAL")
            reason = ""
            if reject:
                reason = "Executable binary detected ({})".format(dtype)
            return ContentTypeResult(
                detected_type=dtype, mime_type=mime, tier=tier,
                category=cat, flags=[subflag, cat],
                reject=reject, reject_reason=reason,
            )

    return ContentTypeResult()


def _check_pk_archive(data):
    """Disambiguate PK/ZIP-based formats by checking internal paths."""
    search_window = data[:2048]
    for marker, dtype, mime in _PK_OOXML_MARKERS:
        if marker in search_window:
            subflag = "embedded_{}".format(dtype)
            cat = "embedded_archive" if dtype == "jar" else "embedded_document"
            return ContentTypeResult(
                detected_type=dtype, mime_type=mime,
                tier="HIGH", category=cat,
                flags=[subflag, cat],
            )
    # Plain ZIP (no recognized internal structure)
    return ContentTypeResult(
        detected_type="zip", mime_type="application/zip",
        tier="HIGH", category="embedded_archive",
        flags=["embedded_zip", "embedded_archive"],
    )


# ---------------------------------------------------------------------------
# String-input convenience (for text pipeline)
# ---------------------------------------------------------------------------

def sniff_binary(text):
    """Check if a text string begins with binary magic bytes.

    Encodes the first ~300 characters to bytes and runs detection.
    Also checks for base64-encoded binary blobs and data URIs.

    Returns a list of anomaly flags (empty if plain text).
    """
    flags = []

    # Check raw-byte signatures in the first 300 chars
    head = text[:300]
    raw = head.encode("utf-8", errors="replace")
    result = detect_content_type(raw)
    if result.detected_type:
        flags.extend(result.flags)

    # Check for base64 blobs in the full text
    if _BASE64_BLOB_RE.search(text):
        flags.append("base64_blob_detected")

    # Check for data URIs
    match = _DATA_URI_RE.search(text)
    if match:
        flags.append("data_uri_detected")
        media_type = match.group(1) or ""
        if media_type:
            flags.append("data_uri_type_{}".format(
                media_type.replace("/", "_").lower()
            ))

    return flags

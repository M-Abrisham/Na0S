import re
from html.parser import HTMLParser

from .content_type import sniff_binary
from .resource_guard import check_html_depth, ResourceLimitExceeded

# Quick check: does the string contain anything that looks like an HTML tag?
_HTML_TAG_RE = re.compile(r"<[a-zA-Z/!]")

# --- Magic bytes / content-type sniffing ---
# BOM markers (strip before further checks)
_BOM_PREFIXES = [
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]

# HTML/XML/SVG document signatures (case-insensitive on first bytes)
_HTML_SIGNATURES = [
    b"<!doctype",
    b"<html",
    b"<head",
    b"<body",
    b"<script",
    b"<iframe",
    b"<svg",
    b"<?xml",
]

# Hidden-content CSS patterns in inline styles
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|"
    r"opacity\s*:\s*0(?:\.0*)?\s*[;\"]|"
    r"font-size\s*:\s*0",
    re.IGNORECASE,
)

# Suspicious injection PHRASES inside HTML comments.
# Require multi-word patterns — bare "ignore" or "instruction" match too much
# legitimate content (e.g. "ignore older browsers", "see instructions below").
_COMMENT_KEYWORDS_RE = re.compile(
    r"ignore.{0,15}(?:instruction|previous|above|system|prompt)|"
    r"system.{0,10}prompt|"
    r"reveal.{0,10}(?:prompt|secret|password|key|credential)|"
    r"override.{0,10}(?:instruction|rule|policy|filter)|"
    r"bypass.{0,10}(?:filter|safety|security|guard|check)|"
    r"exfiltrate",
    re.IGNORECASE,
)


def sniff_content_type(text):
    """Detect real content type from magic bytes, not file extensions.

    A ".txt" file could contain HTML -- this function inspects the actual
    bytes to determine the true content type.

    Binary format detection (PDF, RTF, images, archives, executables, etc.)
    is delegated to ``content_type.sniff_binary()``.  This function retains
    HTML/SVG signature detection and BOM handling.

    Returns a list of flags. Empty list means plain text.
    """
    flags = []
    raw = text.encode("utf-8", errors="replace")

    # Strip BOM if present
    for bom, encoding in _BOM_PREFIXES:
        if raw.startswith(bom):
            flags.append("bom_detected_{}".format(encoding))
            raw = raw[len(bom):]
            break

    # Check for HTML/XML/SVG signatures
    lower = raw.lstrip()[:50].lower()
    for sig in _HTML_SIGNATURES:
        if lower.startswith(sig):
            flags.append("magic_bytes_html")
            break

    # Delegate binary format detection to content_type module
    binary_flags = sniff_binary(text)
    flags.extend(binary_flags)

    return flags


class _TextExtractor(HTMLParser):
    """Strips HTML tags and collects visible text + hidden-content flags."""

    def __init__(self):
        super().__init__()
        self._pieces = []
        self._flags = []
        self._skip_depth = 0  # depth inside hidden elements

    def handle_starttag(self, tag, attrs):
        style = dict(attrs).get("style", "")
        if self._skip_depth > 0:
            # Already inside a hidden element — track nested depth
            self._skip_depth += 1
        elif _HIDDEN_STYLE_RE.search(style):
            self._flags.append("hidden_html_content")
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self._pieces.append(data)

    def handle_comment(self, data):
        if _COMMENT_KEYWORDS_RE.search(data):
            self._flags.append("suspicious_html_comment")

    def get_result(self):
        text = " ".join(self._pieces)
        # Collapse whitespace left by tag removal
        text = " ".join(text.split())
        return text, list(set(self._flags))


def extract_safe_text(text):
    """Extract visible text from input.

    File type is detected by magic bytes, not extensions —
    a ".txt" could contain HTML and will be caught here.

    Returns (visible_text, anomaly_flags).
    """
    flags = []

    # Step 1: Magic bytes sniffing — detect real content type
    sniff_flags = sniff_content_type(text)
    flags.extend(sniff_flags)

    # Non-HTML binary content detected — flag and return raw text.
    # Any embedded_* category flag means the content is not parseable HTML.
    _BINARY_CATEGORIES = (
        "embedded_document", "embedded_image", "embedded_audio",
        "embedded_video", "embedded_archive", "embedded_executable",
    )
    if any(f in _BINARY_CATEGORIES for f in sniff_flags):
        return text, flags

    # Step 2: Decide whether to parse as HTML
    has_html_magic = "magic_bytes_html" in sniff_flags
    has_html_tags = bool(_HTML_TAG_RE.search(text))

    if not has_html_magic and not has_html_tags:
        return text, flags

    # Step 2b: HTML depth pre-check — reject deeply nested HTML before
    # feeding it to the parser to prevent stack overflow / excessive
    # recursion.  On violation, flag and return raw text (defense in depth).
    try:
        check_html_depth(text)
    except ResourceLimitExceeded:
        flags.append("html_depth_exceeded")
        return text, flags

    # Step 3: Parse HTML and extract visible text
    parser = _TextExtractor()
    try:
        parser.feed(text)
    except Exception:
        flags.append("html_parse_error")
        return text, flags

    parsed_text, parse_flags = parser.get_result()
    flags.extend(parse_flags)
    return parsed_text, flags

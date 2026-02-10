import re
from html.parser import HTMLParser

# Quick check: does the string contain anything that looks like an HTML tag?
_HTML_TAG_RE = re.compile(r"<[a-zA-Z/!]")

# Hidden-content CSS patterns in inline styles
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|"
    r"opacity\s*:\s*0(?:\.0*)?\s*[;\"]|"
    r"font-size\s*:\s*0",
    re.IGNORECASE,
)

# Injection keywords that are suspicious inside HTML comments
_COMMENT_KEYWORDS_RE = re.compile(
    r"ignore|instruction|system prompt|reveal|override|bypass|exfiltrate",
    re.IGNORECASE,
)


class _TextExtractor(HTMLParser):
    """Strips HTML tags and collects visible text + hidden-content flags."""

    def __init__(self):
        super().__init__()
        self._pieces = []
        self._flags = []
        self._skip_depth = 0  # depth inside hidden elements

    def handle_starttag(self, tag, attrs):
        style = dict(attrs).get("style", "")
        if _HIDDEN_STYLE_RE.search(style):
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
    """Extract visible text from HTML input.

    Returns (visible_text, anomaly_flags).
    If input is not HTML, returns (text, []) unchanged.
    """
    if not _HTML_TAG_RE.search(text):
        return text, []

    parser = _TextExtractor()
    try:
        parser.feed(text)
    except Exception:
        # Malformed HTML — return raw text with a flag
        return text, ["html_parse_error"]

    return parser.get_result()

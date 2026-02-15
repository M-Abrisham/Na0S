"""Unified input loader for Layer 0.

Accepts str, bytes, file paths, and URLs. Returns normalized content
with source metadata for downstream processing.
"""

import os
import stat
import pathlib
import urllib.request
import urllib.error
import mimetypes

# Max file size: 10 MB by default, configurable via env
MAX_FILE_SIZE = int(os.getenv("L0_MAX_FILE_SIZE", 10 * 1024 * 1024))

# URL fetch settings
URL_TIMEOUT = int(os.getenv("L0_URL_TIMEOUT", 10))
MAX_URL_RESPONSE_SIZE = int(os.getenv("L0_MAX_URL_RESPONSE_SIZE", 10 * 1024 * 1024))
HTTPS_ONLY = os.getenv("L0_HTTPS_ONLY", "1") != "0"


class InputLoadError(Exception):
    """Raised when input loading fails due to security or I/O issues."""


def _is_url(source):
    """Check if source string looks like a URL."""
    if not isinstance(source, str):
        return False
    return source.startswith("http://") or source.startswith("https://")


def _is_file_path(source):
    """Check if source string is an existing file path.

    Only returns True for strings that exist on disk. This avoids
    accidentally treating normal text input as a file path.
    """
    if not isinstance(source, str):
        return False
    if _is_url(source):
        return False
    return os.path.exists(source)


def _validate_file_path(filepath):
    """Security checks for file paths.

    Rejects:
    - Directory traversal (.. components in the raw path)
    - Symlinks (the file itself is a symbolic link)
    - Special device files (block/char devices, FIFOs, sockets)
    - Directories
    """
    # Directory traversal: reject if ".." appears in any component
    # of the raw path string before any resolution.
    parts = pathlib.PurePath(filepath).parts
    if ".." in parts:
        raise InputLoadError(
            "Directory traversal detected in path: {}".format(filepath)
        )

    # Symlink check: is the path itself a symlink?
    # We use os.path.islink which checks the final path component,
    # not intermediate directory symlinks (e.g. /var -> /private/var
    # on macOS is fine, but a symlinked file is not).
    if os.path.islink(filepath):
        target = os.path.realpath(filepath)
        raise InputLoadError(
            "Symlink detected: {} -> {}".format(filepath, target)
        )

    resolved = os.path.realpath(filepath)

    # Stat the file to check its type
    try:
        st = os.stat(filepath, follow_symlinks=False)
    except OSError as exc:
        raise InputLoadError("Cannot stat file: {}".format(exc))

    mode = st.st_mode
    if stat.S_ISDIR(mode):
        raise InputLoadError("Path is a directory: {}".format(filepath))
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        raise InputLoadError("Path is a device file: {}".format(filepath))
    if stat.S_ISFIFO(mode):
        raise InputLoadError("Path is a FIFO: {}".format(filepath))
    if stat.S_ISSOCK(mode):
        raise InputLoadError("Path is a socket: {}".format(filepath))

    return resolved


def _load_file(filepath):
    """Read file content with security and size checks.

    Returns (content_bytes, metadata_dict).
    """
    resolved = _validate_file_path(filepath)

    # Size check before reading
    file_size = os.path.getsize(resolved)
    if file_size > MAX_FILE_SIZE:
        raise InputLoadError(
            "File size {} exceeds limit {} bytes".format(file_size, MAX_FILE_SIZE)
        )

    with open(resolved, "rb") as f:
        content = f.read()

    # Detect content type from extension (best effort, stdlib only)
    content_type, _ = mimetypes.guess_type(resolved)

    metadata = {
        "source_type": "file",
        "source_path": filepath,
        "content_type": content_type,
        "file_size": len(content),
    }
    return content, metadata


def _load_url(url):
    """Fetch content from URL with security and size checks.

    Returns (content_bytes, metadata_dict).
    """
    if HTTPS_ONLY and url.startswith("http://"):
        raise InputLoadError(
            "HTTP URLs are not allowed (HTTPS only). "
            "Set L0_HTTPS_ONLY=0 to allow HTTP."
        )

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AI-Prompt-Injection-Detector/1.0"},
        )
        with urllib.request.urlopen(req, timeout=URL_TIMEOUT) as resp:
            content = resp.read(MAX_URL_RESPONSE_SIZE + 1)
            if len(content) > MAX_URL_RESPONSE_SIZE:
                raise InputLoadError(
                    "URL response exceeds {} byte limit".format(
                        MAX_URL_RESPONSE_SIZE
                    )
                )

            content_type = resp.headers.get("Content-Type", None)

            metadata = {
                "source_type": "url",
                "source_path": url,
                "content_type": content_type,
                "file_size": len(content),
            }
            return content, metadata

    except InputLoadError:
        raise
    except urllib.error.HTTPError as exc:
        raise InputLoadError(
            "URL returned HTTP {}: {}".format(exc.code, exc.reason)
        )
    except urllib.error.URLError as exc:
        raise InputLoadError("URL fetch failed: {}".format(exc))
    except OSError as exc:
        raise InputLoadError("Network error: {}".format(exc))


def load_input(source):
    """Unified input loader.

    Accepts:
        - str: plain text (passed through)
        - bytes: raw bytes (passed through)
        - pathlib.Path: file path (read from disk)
        - str that is an existing file path: read from disk
        - str starting with http:// or https://: fetch from URL

    Returns:
        (content, metadata) tuple where:
        - content is str or bytes
        - metadata is a dict with keys: source_type, source_path,
          content_type, file_size
    """
    # pathlib.Path -> always treat as file
    if isinstance(source, pathlib.Path):
        filepath = str(source)
        if not os.path.exists(filepath):
            raise InputLoadError("File not found: {}".format(filepath))
        return _load_file(filepath)

    # bytes -> pass through
    if isinstance(source, (bytes, bytearray)):
        metadata = {
            "source_type": "bytes",
            "source_path": None,
            "content_type": None,
            "file_size": len(source),
        }
        return source, metadata

    # str -> check if URL, then file path, then plain text
    if isinstance(source, str):
        if _is_url(source):
            return _load_url(source)

        if _is_file_path(source):
            return _load_file(source)

        # Plain text pass-through
        metadata = {
            "source_type": "text",
            "source_path": None,
            "content_type": None,
            "file_size": None,
        }
        return source, metadata

    # Unsupported type -- let downstream validation handle it
    metadata = {
        "source_type": "unknown",
        "source_path": None,
        "content_type": None,
        "file_size": None,
    }
    return source, metadata

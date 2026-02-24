"""Hardened YAML loading for Na0S scripts.

Security controls:
- Always uses yaml.safe_load (never yaml.load)
- File size limit (default 10 MB) to prevent billion-laughs DoS
- Path validation (must exist and be a file)
- Explicit encoding (UTF-8-SIG for BOM-safe loading)

Limitation:
  The file-size limit only protects against disk-based YAML bombs.
  In-memory strings passed directly to yaml.safe_load() bypass the
  size guard entirely.  Callers that build YAML from untrusted
  in-memory data must enforce their own size limits before parsing.

References:
- CWE-502: Deserialization of Untrusted Data
- CVE-2017-18342, CVE-2020-1747, CVE-2020-14343 (all yaml.load RCE)
- OWASP Deserialization Cheat Sheet
"""

import os
from pathlib import Path

import yaml

_DEFAULT_MAX_SIZE = 10 * 1024 * 1024  # 10 MB


def safe_load_yaml(path, max_size_bytes=_DEFAULT_MAX_SIZE):
    """Load a YAML file safely with size and type validation.

    Args:
        path: File system path (str or pathlib.Path) to the YAML file.
        max_size_bytes: Maximum allowed file size in bytes.
            Defaults to 10 MB.  Set to 0 to disable the size check.

    Returns:
        The parsed YAML content (typically a dict or list).

    Raises:
        FileNotFoundError: If *path* does not exist or is not a file.
        ValueError: If the file exceeds *max_size_bytes* or contains
            invalid YAML / non-UTF-8 content.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            "YAML file not found: {}".format(path)
        )
    if not path.is_file():
        raise FileNotFoundError(
            "YAML path is not a file: {}".format(path)
        )

    # Size guard — prevent billion-laughs / zip-bomb style DoS
    if max_size_bytes > 0:
        file_size = path.stat().st_size
        if file_size > max_size_bytes:
            raise ValueError(
                "YAML file too large ({:,} bytes, limit {:,}): {}".format(
                    file_size, max_size_bytes, path
                )
            )

    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            return yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(
            "Invalid YAML in {}: {}".format(path, exc)
        ) from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Non-UTF-8 content in {}: {}".format(path, exc)
        ) from exc

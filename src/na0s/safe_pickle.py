"""Safe pickle wrapper — verifies SHA-256 integrity before unpickling.

A tampered .pkl file can execute arbitrary code via ``pickle.loads``.
This module verifies every file against a SHA-256 digest **before**
it is unpickled.

Trust hierarchy (checked in order):

1. **Hardcoded hashes** — ``KNOWN_HASHES`` in ``models/__init__.py``.
   These live inside the Python source, which is signed by pip's wheel
   signature.  An attacker who tampers with a ``.pkl`` cannot update the
   expected hash without also patching the installed Python code.

2. **Sidecar files** — ``<file>.sha256`` on disk (legacy / user-trained
   models).  These are still accepted as a fallback, but they provide
   weaker guarantees because an attacker with write access to the pickle
   can also rewrite the sidecar.

All comparisons use ``hmac.compare_digest()`` for constant-time
equality, preventing timing side-channels.
"""

import hashlib
import hmac
import os
import pickle

from .models import KNOWN_HASHES


def _hash_path(pkl_path):
    return pkl_path + ".sha256"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_expected_hash(path):
    """Return ``(expected_hex_digest, source)`` for *path*.

    *source* is ``"hardcoded"`` when the hash comes from ``KNOWN_HASHES``
    or ``"sidecar"`` when it falls back to the ``.sha256`` file.

    Raises ``FileNotFoundError`` when neither source is available.
    """
    basename = os.path.basename(path)
    if basename in KNOWN_HASHES:
        return KNOWN_HASHES[basename], "hardcoded"

    hash_file = _hash_path(path)
    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            return f.read().strip(), "sidecar"

    raise FileNotFoundError(
        f"No integrity hash available for {path}.  "
        f"Not found in KNOWN_HASHES and sidecar missing: {hash_file}.  "
        f"Re-run training to generate a sidecar, or add the hash to "
        f"models/__init__.py KNOWN_HASHES."
    )


def safe_dump(obj, path):
    """Pickle *obj* to *path* and write a SHA-256 sidecar."""
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    digest = _sha256(path)
    with open(_hash_path(path), "w") as f:
        f.write(digest)


def safe_load(path):
    """Load a pickle only after its SHA-256 digest has been verified.

    The expected hash is resolved via :func:`_resolve_expected_hash`
    (hardcoded first, sidecar fallback).  Comparison is constant-time
    via ``hmac.compare_digest``.

    Raises ``FileNotFoundError`` if no expected hash is available and
    ``ValueError`` if the computed hash does not match.
    """
    expected, source = _resolve_expected_hash(path)
    actual = _sha256(path)
    if not hmac.compare_digest(actual, expected):
        raise ValueError(
            f"Integrity check failed for {path} (hash source: {source}).  "
            f"Expected {expected}, got {actual}.  "
            f"The file may have been tampered with."
        )
    with open(path, "rb") as f:
        return pickle.load(f)

"""Safe pickle wrapper — writes a SHA-256 sidecar on save, verifies before load.

A tampered .pkl file can execute arbitrary code via pickle.  This module
computes a SHA-256 hash of every file it writes and stores it in a
.pkl.sha256 sidecar.  On load the hash is re-computed and compared; a
mismatch raises an error instead of blindly unpickling.
"""

import hashlib
import os
import pickle


def _hash_path(pkl_path):
    return pkl_path + ".sha256"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_dump(obj, path):
    """Pickle *obj* to *path* and write a SHA-256 sidecar."""
    with open(path, "wb") as f:
        pickle.dump(obj, f)
    digest = _sha256(path)
    with open(_hash_path(path), "w") as f:
        f.write(digest)


def safe_load(path):
    """Load a pickle only if its SHA-256 sidecar matches.

    Raises FileNotFoundError if the sidecar is missing and
    ValueError if the hash does not match.
    """
    hash_file = _hash_path(path)
    if not os.path.exists(hash_file):
        raise FileNotFoundError(
            f"Integrity sidecar missing: {hash_file}  "
            f"Re-run training to generate it."
        )
    with open(hash_file, "r") as f:
        expected = f.read().strip()
    actual = _sha256(path)
    if actual != expected:
        raise ValueError(
            f"Integrity check failed for {path}  "
            f"Expected {expected}, got {actual}.  "
            f"The file may have been tampered with."
        )
    with open(path, "rb") as f:
        return pickle.load(f)

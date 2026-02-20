"""Model weight storage and path resolution.

Pre-trained model weights are bundled inside the package at install
time.  Use ``get_model_path(filename)`` to get an absolute path to a
bundled model file.

Hardcoded SHA-256 hashes
~~~~~~~~~~~~~~~~~~~~~~~~
The ``KNOWN_HASHES`` dict maps each bundled ``.pkl`` filename to its
expected SHA-256 hex digest.  Because these hashes live *inside* the
Python source (which is itself signed by pip's wheel signature), an
attacker who tampers with a ``.pkl`` file cannot update the expected
hash without also patching this module.  This eliminates the "security
theater" problem of shipping ``.sha256`` sidecar files next to the very
artefacts they are supposed to protect.

The sidecar files are kept for backward compatibility (e.g. user-trained
models), but ``safe_load()`` will always prefer the hardcoded hash when
one is available.
"""

import importlib.resources

# Authoritative SHA-256 hex digests for every bundled pickle file.
# Update this dict whenever a model is retrained.
KNOWN_HASHES = {
    "model.pkl": "5458775d4a6eff0d194d77d1e914b5ffefc803f265f9485f4ca2e7aada2d830f",
    "tfidf_vectorizer.pkl": "440b41396908baba576c2510a3d17260c67b76c529e326b572107a8067a3ef2b",
}


def get_model_path(filename):
    """Return the absolute path to a bundled model file as a string."""
    return str(importlib.resources.files(__package__) / filename)

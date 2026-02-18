"""Model weight storage and path resolution.

Pre-trained model weights are bundled inside the package at install
time.  Use ``get_model_path(filename)`` to get an absolute path to a
bundled model file.
"""

import importlib.resources


def get_model_path(filename):
    """Return the absolute path to a bundled model file as a string."""
    return str(importlib.resources.files(__package__) / filename)

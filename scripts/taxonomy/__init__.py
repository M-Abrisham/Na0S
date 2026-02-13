"""Taxonomy probe registry — auto-discovers all Probe subclasses."""

import importlib
import inspect
import logging
import pkgutil

from ._base import Probe

logger = logging.getLogger(__name__)

_SKIP_MODULES = frozenset({"_base", "_core", "_tags", "_buffs"})


def _discover_probes():
    """Import every non-private module in this package and collect Probe subclasses."""
    probes = []
    pkg_path = __path__
    for finder, module_name, is_pkg in pkgutil.iter_modules(pkg_path):
        if module_name in _SKIP_MODULES or module_name.startswith("__"):
            continue
        fqn = f"{__name__}.{module_name}"
        try:
            mod = importlib.import_module(fqn)
        except Exception:
            logger.warning("Failed to import probe module '%s'", fqn, exc_info=True)
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, Probe) and obj is not Probe and obj.category_id:
                probes.append(obj)
    # Validate no duplicate category_ids
    seen = {}
    for p in probes:
        if p.category_id in seen:
            raise ValueError(
                f"Duplicate category_id '{p.category_id}': "
                f"{seen[p.category_id].__name__} and {p.__name__}"
            )
        seen[p.category_id] = p
    # Sort by category_id for deterministic ordering
    probes.sort(key=lambda p: p.category_id)
    return probes


ALL_PROBES = _discover_probes()

__all__ = ["Probe", "ALL_PROBES"]

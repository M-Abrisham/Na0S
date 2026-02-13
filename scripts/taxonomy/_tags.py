"""MISP tag loading and aggregation helpers."""

import os
import threading
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_TAGS_PATH = Path(
    os.environ.get("TAGS_MISP_PATH", _PROJECT_ROOT / "data" / "tags.misp.tsv")
)

_tag_cache = None
_tag_lock = threading.Lock()


def load_tags():
    """Load data/tags.misp.tsv into a dict {tag: description} (thread-safe)."""
    global _tag_cache
    if _tag_cache is not None:
        return _tag_cache
    with _tag_lock:
        if _tag_cache is not None:
            return _tag_cache
        result = {}
        with _TAGS_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    result[parts[0]] = parts[1]
        _tag_cache = result
    return _tag_cache


def clear_tag_cache():
    """Reset cached tag data (for tests and live-reload)."""
    global _tag_cache
    with _tag_lock:
        _tag_cache = None


def aggregate_by_taxonomy(probe_results, namespace):
    """Group probe results by a taxonomy namespace.

    Args:
        probe_results: list of dicts from Probe.evaluate()
        namespace: prefix to filter tags, e.g. "owasp-llm", "avid-effect",
                   "risk-cards"

    Returns:
        dict {tag: {"description": str, "total": int, "detected": int,
                     "recall": float, "probes": list}}
    """
    tags = load_tags()
    groups = {}
    for result in probe_results:
        for tag in result.get("tags", []):
            if not tag.startswith(namespace):
                continue
            if tag not in groups:
                groups[tag] = {
                    "description": tags.get(tag, tag),
                    "total": 0,
                    "detected": 0,
                    "probes": [],
                }
            groups[tag]["total"] += result["total"]
            groups[tag]["detected"] += result["detected"]
            groups[tag]["probes"].append(result["probe"])

    for g in groups.values():
        g["recall"] = g["detected"] / g["total"] if g["total"] else 0.0

    return groups

"""MISP tag loading and aggregation helpers."""

import os

_TAGS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "data", "tags.misp.tsv",
)

_tag_cache = None


def load_tags():
    """Load data/tags.misp.tsv into a dict {tag: description}."""
    global _tag_cache
    if _tag_cache is not None:
        return _tag_cache
    _tag_cache = {}
    with open(_TAGS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                _tag_cache[parts[0]] = parts[1]
    return _tag_cache


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

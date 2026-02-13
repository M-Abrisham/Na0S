"""MISP tag loading and aggregation helpers."""

import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_TAGS = str(_PROJECT_ROOT / "data" / "tags.misp.tsv")
_TAGS_PATH = Path(os.environ.get("TAGS_MISP_PATH", _DEFAULT_TAGS))

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
        if not _TAGS_PATH.exists():
            raise FileNotFoundError(
                f"MISP tags file not found: {_TAGS_PATH}. "
                "Set TAGS_MISP_PATH env var or ensure data/tags.misp.tsv exists."
            )
        result = {}
        with _TAGS_PATH.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    tag_key = parts[0]
                    if tag_key in result:
                        logger.warning(
                            "tags.misp.tsv line %d: duplicate tag '%s', "
                            "keeping first occurrence", line_num, tag_key
                        )
                        continue
                    result[tag_key] = parts[1]
                else:
                    logger.warning(
                        "tags.misp.tsv line %d: expected tab-separated "
                        "'tag\\tdescription', got: %s", line_num, line[:80]
                    )
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
                   "risk-cards".  A ":" delimiter is enforced so "owasp"
                   won't accidentally match "owasp-llm:..." tags.

    Returns:
        dict {tag: {"description": str, "total": int, "detected": int,
                     "recall": float, "probes": list}}
    """
    prefix = namespace if namespace.endswith(":") else namespace + ":"
    tags = load_tags()
    groups = {}
    for result in probe_results:
        for tag in result.get("tags", []):
            if not tag.startswith(prefix):
                continue
            if tag not in groups:
                desc = tags.get(tag)
                if desc is None:
                    logger.warning(
                        "Tag '%s' from probe '%s' not found in MISP tags",
                        tag, result.get("probe", "?"),
                    )
                    desc = tag
                groups[tag] = {
                    "description": desc,
                    "total": 0,
                    "detected": 0,
                    "attributed": 0,
                    "probes": [],
                }
            groups[tag]["total"] += result["total"]
            groups[tag]["detected"] += result["detected"]
            groups[tag]["attributed"] += result.get("attributed", 0)
            groups[tag]["probes"].append(result["probe"])

    for g in groups.values():
        g["missed"] = g["total"] - g["detected"]
        g["recall"] = g["detected"] / g["total"] if g["total"] else 0.0
        g["attribution_rate"] = (
            g["attributed"] / g["detected"] if g["detected"] else 0.0
        )

    return groups


def summarize_groups(groups, namespace=None):
    """Compute aggregate stats across tag groups from aggregate_by_taxonomy().

    Returns:
        dict with namespace, tag_count, total, detected, missed, recall.
    """
    total = sum(g["total"] for g in groups.values())
    detected = sum(g["detected"] for g in groups.values())
    attributed = sum(g["attributed"] for g in groups.values())
    return {
        "namespace": namespace,
        "tag_count": len(groups),
        "total": total,
        "detected": detected,
        "attributed": attributed,
        "missed": total - detected,
        "recall": detected / total if total else 0.0,
        "attribution_rate": attributed / detected if detected else 0.0,
    }

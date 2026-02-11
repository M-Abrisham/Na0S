"""Base class for all taxonomy probes."""

import yaml
import os

_TAXONOMY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "data", "taxonomy.yaml",
)

_taxonomy_cache = None


def _load_taxonomy():
    global _taxonomy_cache
    if _taxonomy_cache is None:
        with open(_TAXONOMY_PATH, "r") as f:
            _taxonomy_cache = yaml.safe_load(f)
    return _taxonomy_cache


class Probe:
    """Base class for all taxonomy probes.

    Subclasses must set ``category_id`` and implement ``generate()``.
    Tags, name, severity, and expected_layers are auto-loaded from
    ``data/taxonomy.yaml`` so the YAML file remains the single source of truth.
    """

    category_id = ""  # e.g. "D1", "E", "T"

    def __init__(self):
        tax = _load_taxonomy()
        cat = tax["categories"].get(self.category_id, {})
        self.name = cat.get("name", "")
        self.tags = cat.get("tags", [])
        self.severity = cat.get("severity", "")
        self.expected_layers = cat.get("expected_layers", [])
        self.techniques = cat.get("techniques", {})

    def generate(self):
        """Return list of (text, technique_id) tuples."""
        raise NotImplementedError

    def evaluate(self, classify_fn):
        """Run all samples through the detector.

        Args:
            classify_fn: callable(text) -> (label, prob, hits, l0)
                where label is a string, prob a float, hits a list,
                and l0 is Layer0Result.

        Returns:
            dict with per-probe and per-technique recall.
        """
        samples = self.generate()
        results = {
            "probe": self.category_id,
            "name": self.name,
            "tags": self.tags,
            "total": len(samples),
            "detected": 0,
            "missed": 0,
            "by_technique": {},
            "missed_samples": [],
        }
        for text, tech_id in samples:
            label, prob, hits, l0 = classify_fn(text)
            is_detected = l0.rejected or ("SAFE" not in label.upper())

            if tech_id not in results["by_technique"]:
                results["by_technique"][tech_id] = {"detected": 0, "missed": 0}

            if is_detected:
                results["detected"] += 1
                results["by_technique"][tech_id]["detected"] += 1
            else:
                results["missed"] += 1
                results["by_technique"][tech_id]["missed"] += 1
                results["missed_samples"].append((text[:200], tech_id, prob))

        total = results["total"]
        results["recall"] = results["detected"] / total if total else 0.0
        return results

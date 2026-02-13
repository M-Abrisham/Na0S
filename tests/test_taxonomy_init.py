"""Tests for scripts/taxonomy/__init__.py — auto-discovery sanity checks."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PKG = Path(__file__).resolve().parent.parent / "scripts" / "taxonomy"


class TestAutoDiscovery(unittest.TestCase):

    def test_all_probes_populated(self):
        from scripts.taxonomy import ALL_PROBES
        self.assertGreater(len(ALL_PROBES), 0)

    def test_probe_count_matches_files(self):
        """Every non-helper .py file should contribute exactly one probe."""
        from scripts.taxonomy import ALL_PROBES
        from scripts.taxonomy import _SKIP_MODULES

        probe_files = [
            f.stem for f in TAXONOMY_PKG.glob("*.py")
            if f.stem not in _SKIP_MODULES and not f.stem.startswith("__")
        ]
        self.assertEqual(
            len(ALL_PROBES), len(probe_files),
            f"Expected {len(probe_files)} probes from files {sorted(probe_files)}, "
            f"got {len(ALL_PROBES)}: {[p.__name__ for p in ALL_PROBES]}"
        )

    def test_all_category_ids_exist_in_yaml(self):
        """Every probe's category_id must exist in taxonomy.yaml."""
        from scripts.taxonomy import ALL_PROBES
        from scripts.taxonomy._base import _load_taxonomy

        tax = _load_taxonomy()
        yaml_ids = set(tax["categories"].keys())
        for probe in ALL_PROBES:
            self.assertIn(
                probe.category_id, yaml_ids,
                f"{probe.__name__}.category_id='{probe.category_id}' "
                f"not found in taxonomy.yaml"
            )

    def test_all_category_ids_unique(self):
        from scripts.taxonomy import ALL_PROBES
        ids = [p.category_id for p in ALL_PROBES]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate category_ids: {ids}")

    def test_sorted_by_category_id(self):
        from scripts.taxonomy import ALL_PROBES
        ids = [p.category_id for p in ALL_PROBES]
        self.assertEqual(ids, sorted(ids))

    def test_all_subclass_probe(self):
        from scripts.taxonomy import ALL_PROBES, Probe
        for p in ALL_PROBES:
            self.assertTrue(
                issubclass(p, Probe),
                f"{p.__name__} is not a Probe subclass"
            )

    def test_all_have_generate(self):
        from scripts.taxonomy import ALL_PROBES
        for p in ALL_PROBES:
            self.assertTrue(
                callable(getattr(p, "generate", None)),
                f"{p.__name__} missing generate() method"
            )

    def test_dunder_all_exports(self):
        import scripts.taxonomy as pkg
        self.assertIn("Probe", pkg.__all__)
        self.assertIn("ALL_PROBES", pkg.__all__)
        self.assertEqual(len(pkg.__all__), 2)


if __name__ == "__main__":
    unittest.main()

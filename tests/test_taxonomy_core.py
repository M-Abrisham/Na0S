"""Tests for scripts/taxonomy/_core.py — all 7 issues."""

import logging
import os
import sys
import unittest

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.taxonomy._core import (
    _index_to_combo,
    _validate_templates,
    expand,
)


# ---------------------------------------------------------------------------
# Issue 1 — Deterministic output (seeded RNG)
# ---------------------------------------------------------------------------

class TestDeterministicOutput(unittest.TestCase):

    def test_default_seed_is_deterministic(self):
        """Two calls with default seed produce identical output."""
        subs = {"verb": ["a", "b"], "noun": ["x", "y"]}
        r1 = expand(["{verb} {noun}"], "T1", subs)
        r2 = expand(["{verb} {noun}"], "T1", subs)
        self.assertEqual(r1, r2)

    def test_explicit_seed_is_deterministic(self):
        r1 = expand(["hello {v}"], "T1", {"v": ["a", "b", "c"]}, seed=99)
        r2 = expand(["hello {v}"], "T1", {"v": ["a", "b", "c"]}, seed=99)
        self.assertEqual(r1, r2)

    def test_different_seeds_differ(self):
        subs = {"v": list("abcdefghij")}
        r1 = expand(["{v}"], "T1", subs, seed=1)
        r2 = expand(["{v}"], "T1", subs, seed=2)
        # Same set of values but different shuffle order
        self.assertEqual(set(r1), set(r2))
        self.assertNotEqual(r1, r2)

    def test_none_seed_still_works(self):
        """seed=None produces output (non-deterministic, but shouldn't crash)."""
        result = expand(["static"], "T1", seed=None)
        self.assertEqual(len(result), 1)


# ---------------------------------------------------------------------------
# Issue 2 — limit=0 returns empty list
# ---------------------------------------------------------------------------

class TestLimitZero(unittest.TestCase):

    def test_limit_zero_returns_empty(self):
        result = expand(["a", "b", "c"], "T1", limit=0)
        self.assertEqual(result, [])

    def test_limit_zero_with_subs_returns_empty(self):
        result = expand(["{v}"], "T1", {"v": ["x", "y"]}, limit=0)
        self.assertEqual(result, [])

    def test_limit_none_returns_all(self):
        result = expand(["a", "b", "c"], "T1", limit=None)
        self.assertEqual(len(result), 3)

    def test_limit_one_returns_one(self):
        result = expand(["a", "b", "c"], "T1", limit=1)
        self.assertEqual(len(result), 1)


# ---------------------------------------------------------------------------
# Issue 3 — Template validation (bad placeholders)
# ---------------------------------------------------------------------------

class TestTemplateValidation(unittest.TestCase):

    def test_typo_placeholder_raises_key_error(self):
        with self.assertRaises(KeyError) as ctx:
            expand(["{paylaod}"], "T1", {"payload": ["x"]})
        self.assertIn("paylaod", str(ctx.exception))

    def test_extra_placeholder_raises_key_error(self):
        with self.assertRaises(KeyError):
            expand(["{a} {b} {c}"], "T1", {"a": ["1"], "b": ["2"]})

    def test_valid_placeholders_pass(self):
        result = expand(["{a} {b}"], "T1", {"a": ["x"], "b": ["y"]})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "x y")

    def test_no_placeholders_pass(self):
        result = expand(["static text"], "T1", {"a": ["x"]})
        self.assertEqual(result[0][0], "static text")

    def test_dotted_placeholder_validated(self):
        """Placeholder like {verb.upper} should check 'verb' key exists."""
        with self.assertRaises(KeyError):
            expand(["{verb.upper}"], "T1", {"noun": ["x"]})

    def test_validate_templates_directly(self):
        with self.assertRaises(KeyError):
            _validate_templates(["{missing}"], {"present"})

    def test_validate_templates_passes_when_correct(self):
        # Should not raise
        _validate_templates(["{a} and {b}"], {"a", "b"})


# ---------------------------------------------------------------------------
# Issue 4 — Memory efficiency (lazy Cartesian product)
# ---------------------------------------------------------------------------

class TestLazyExpansion(unittest.TestCase):

    def test_limit_below_product_uses_lazy_path(self):
        """With huge subs but small limit, result stays small."""
        subs = {"v": list(range(1000))}  # 1000 combos
        result = expand(["{v}"], "T1", subs, limit=5)
        self.assertEqual(len(result), 5)

    def test_all_results_unique(self):
        subs = {"a": list("abcde"), "b": list("12345")}
        result = expand(["{a}{b}"], "T1", subs, limit=10)
        texts = [r[0] for r in result]
        self.assertEqual(len(texts), len(set(texts)))

    def test_full_expansion_without_limit(self):
        subs = {"a": ["x", "y"], "b": ["1", "2"]}
        result = expand(["{a}{b}"], "T1", subs)
        self.assertEqual(len(result), 4)  # 2 × 2

    def test_multiple_templates_multiply(self):
        subs = {"v": ["a", "b"]}
        result = expand(["first {v}", "second {v}"], "T1", subs)
        self.assertEqual(len(result), 4)  # 2 templates × 2 combos


# ---------------------------------------------------------------------------
# Issue 5 — Dataset skew (per_template_limit)
# ---------------------------------------------------------------------------

class TestPerTemplateLimit(unittest.TestCase):

    def test_per_template_limit_caps_combos(self):
        subs = {"v": list(range(100))}  # 100 combos per template
        result = expand(["{v}", "prefix {v}"], "T1", subs,
                        per_template_limit=5)
        # 2 templates × 5 capped combos = 10
        self.assertEqual(len(result), 10)

    def test_per_template_limit_with_global_limit(self):
        subs = {"v": list(range(100))}
        result = expand(["{v}", "prefix {v}"], "T1", subs,
                        per_template_limit=10, limit=5)
        self.assertEqual(len(result), 5)

    def test_per_template_limit_no_effect_when_larger(self):
        subs = {"v": ["a", "b"]}  # only 2 combos
        result = expand(["{v}"], "T1", subs, per_template_limit=100)
        self.assertEqual(len(result), 2)  # not capped

    def test_per_template_limit_deterministic(self):
        subs = {"v": list(range(50))}
        r1 = expand(["{v}"], "T1", subs, per_template_limit=10)
        r2 = expand(["{v}"], "T1", subs, per_template_limit=10)
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# Issue 6 — Key ordering stability
# ---------------------------------------------------------------------------

class TestKeyOrdering(unittest.TestCase):

    def test_different_insertion_order_same_result(self):
        """Dict key insertion order should not affect output."""
        subs_a = {"z": ["1"], "a": ["2"], "m": ["3"]}
        subs_b = {"a": ["2"], "m": ["3"], "z": ["1"]}
        r1 = expand(["{a}{m}{z}"], "T1", subs_a)
        r2 = expand(["{a}{m}{z}"], "T1", subs_b)
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# Issue 7 — Logging / sample count reporting
# ---------------------------------------------------------------------------

class TestLogging(unittest.TestCase):

    def test_expand_logs_debug_with_subs(self):
        with self.assertLogs("scripts.taxonomy._core", level="DEBUG") as cm:
            expand(["{v}"], "T1", {"v": ["a", "b"]})
        self.assertTrue(any("expand(T1)" in msg for msg in cm.output))
        self.assertTrue(any("2 combos" in msg for msg in cm.output))

    def test_expand_logs_debug_no_subs(self):
        with self.assertLogs("scripts.taxonomy._core", level="DEBUG") as cm:
            expand(["static"], "T2")
        self.assertTrue(any("expand(T2)" in msg for msg in cm.output))
        self.assertTrue(any("no subs" in msg for msg in cm.output))


# ---------------------------------------------------------------------------
# _index_to_combo unit tests
# ---------------------------------------------------------------------------

class TestIndexToCombo(unittest.TestCase):

    def test_simple_case(self):
        # lengths [3, 4, 2], index 17 → (2, 0, 1)
        self.assertEqual(_index_to_combo(17, [3, 4, 2]), (2, 0, 1))

    def test_index_zero(self):
        self.assertEqual(_index_to_combo(0, [3, 4, 2]), (0, 0, 0))

    def test_single_dimension(self):
        self.assertEqual(_index_to_combo(3, [5]), (3,))

    def test_max_index(self):
        # lengths [2, 3] → total 6, max index 5 → (1, 2)
        self.assertEqual(_index_to_combo(5, [2, 3]), (1, 2))


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_no_subs_returns_raw_templates(self):
        result = expand(["hello", "world"], "T1")
        texts = sorted(r[0] for r in result)
        self.assertEqual(texts, ["hello", "world"])

    def test_all_results_have_correct_technique_id(self):
        result = expand(["{v}"], "T1.1", {"v": ["a", "b", "c"]})
        for text, tech_id in result:
            self.assertEqual(tech_id, "T1.1")

    def test_empty_templates_list(self):
        result = expand([], "T1")
        self.assertEqual(result, [])

    def test_empty_templates_with_subs(self):
        result = expand([], "T1", {"v": ["a"]})
        self.assertEqual(result, [])

    def test_single_value_subs(self):
        result = expand(["{a}"], "T1", {"a": ["only"]})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "only")


if __name__ == "__main__":
    unittest.main()

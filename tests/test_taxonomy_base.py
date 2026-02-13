"""Tests for scripts/taxonomy/_base.py — all 7 issues."""

import os
import sys
import tempfile
import threading
import unittest

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.taxonomy._base import (
    ClassifierOutput,
    DETECTION_LABELS,
    Probe,
    _is_detected_label,
    _load_taxonomy,
    clear_taxonomy_cache,
    recall_at_threshold,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _StubProbe(Probe):
    """Minimal concrete subclass for testing."""
    category_id = "D1"

    def __init__(self, samples=None):
        super().__init__()
        self._samples = samples or []

    def generate(self):
        return self._samples


class _BadReturnProbe(Probe):
    """Returns wrong type from generate()."""
    category_id = "D1"

    def __init__(self, bad_value):
        super().__init__()
        self._bad = bad_value

    def generate(self):
        return self._bad


def _make_classify_fn(label="MALICIOUS", confidence=0.9, hits=None,
                      rejected=False, anomaly_flags=None):
    """Return a classify_fn that always returns the given ClassifierOutput."""
    output = ClassifierOutput(
        label=label,
        confidence=confidence,
        hits=hits or [],
        rejected=rejected,
        anomaly_flags=anomaly_flags or [],
    )
    return lambda text: output


def _make_legacy_classify_fn(label="MALICIOUS", prob=0.9, hits=None, l0=None):
    """Return a classify_fn that returns the legacy 4-tuple."""
    return lambda text: (label, prob, hits or [], l0)


# ---------------------------------------------------------------------------
# Issue 1 — YAML load error handling
# ---------------------------------------------------------------------------

class TestYAMLLoadErrorHandling(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()

    def test_missing_file_raises_file_not_found(self):
        import scripts.taxonomy._base as mod
        orig = mod._TAXONOMY_PATH
        try:
            mod._TAXONOMY_PATH = mod.Path("/nonexistent/taxonomy.yaml")
            clear_taxonomy_cache()
            with self.assertRaises(FileNotFoundError):
                _load_taxonomy()
        finally:
            mod._TAXONOMY_PATH = orig

    def test_malformed_yaml_raises_value_error(self):
        import scripts.taxonomy._base as mod
        orig = mod._TAXONOMY_PATH
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(": :\n  bad: [unterminated")
            tmp = f.name
        try:
            mod._TAXONOMY_PATH = mod.Path(tmp)
            clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                _load_taxonomy()
            self.assertIn("Cannot read taxonomy YAML", str(ctx.exception))
        finally:
            mod._TAXONOMY_PATH = orig
            os.unlink(tmp)

    def test_missing_categories_key_raises_value_error(self):
        import scripts.taxonomy._base as mod
        orig = mod._TAXONOMY_PATH
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: '1.0'\nsome_other_key: {}\n")
            tmp = f.name
        try:
            mod._TAXONOMY_PATH = mod.Path(tmp)
            clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                _load_taxonomy()
            self.assertIn("missing 'categories' key", str(ctx.exception))
        finally:
            mod._TAXONOMY_PATH = orig
            os.unlink(tmp)

    def test_valid_yaml_loads_successfully(self):
        clear_taxonomy_cache()
        data = _load_taxonomy()
        self.assertIn("categories", data)
        self.assertIn("D1", data["categories"])


# ---------------------------------------------------------------------------
# Issue 2 — Silent category_id fallback
# ---------------------------------------------------------------------------

class TestCategoryIdValidation(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()

    def test_empty_category_id_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            Probe()
        self.assertIn("must set category_id", str(ctx.exception))

    def test_wrong_category_id_raises_key_error(self):
        class BadProbe(Probe):
            category_id = "NONEXISTENT_99"
            def generate(self):
                return []
        with self.assertRaises(KeyError) as ctx:
            BadProbe()
        self.assertIn("NONEXISTENT_99", str(ctx.exception))
        self.assertIn("Available:", str(ctx.exception))

    def test_valid_category_id_loads_fields(self):
        probe = _StubProbe()
        self.assertEqual(probe.name, "Instruction Override")
        self.assertEqual(probe.severity, "critical")
        self.assertIn("D1.1", probe.techniques)


# ---------------------------------------------------------------------------
# Issue 3 — Detection label matching (exact words, no substring)
# ---------------------------------------------------------------------------

class TestDetectionLabels(unittest.TestCase):

    def test_malicious_detected(self):
        self.assertTrue(_is_detected_label("MALICIOUS"))

    def test_blocked_detected(self):
        self.assertTrue(_is_detected_label("BLOCKED"))

    def test_safe_not_detected(self):
        self.assertFalse(_is_detected_label("SAFE"))

    def test_not_malicious_not_detected(self):
        """Substring 'MALICIOUS' inside 'NOT_MALICIOUS' must NOT match."""
        self.assertFalse(_is_detected_label("NOT_MALICIOUS"))

    def test_emoji_prefix_stripped(self):
        self.assertTrue(_is_detected_label("🚨 MALICIOUS"))

    def test_case_insensitive(self):
        self.assertTrue(_is_detected_label("malicious"))
        self.assertTrue(_is_detected_label("Blocked"))

    def test_empty_string(self):
        self.assertFalse(_is_detected_label(""))

    def test_frozenset_is_immutable(self):
        with self.assertRaises(AttributeError):
            DETECTION_LABELS.add("NEW")


# ---------------------------------------------------------------------------
# Issue 4 — Metadata in results
# ---------------------------------------------------------------------------

class TestMetadataInResults(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()

    def test_evaluate_includes_meta(self):
        probe = _StubProbe([("test input", "D1.1")])
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.95,
                                     hits=["override"])
        result = probe.evaluate(classify, confidence_threshold=0.5)
        self.assertIn("meta", result)
        meta = result["meta"]
        self.assertIn("timestamp", meta)
        self.assertEqual(meta["confidence_threshold"], 0.5)
        self.assertIn("taxonomy_version", meta)

    def test_severity_in_results(self):
        probe = _StubProbe([("test input", "D1.1")])
        classify = _make_classify_fn()
        result = probe.evaluate(classify)
        self.assertEqual(result["severity"], "critical")


# ---------------------------------------------------------------------------
# Issue 5 — _TAXONOMY_PATH env var override
# ---------------------------------------------------------------------------

class TestTaxonomyPathOverride(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()
        os.environ.pop("TAXONOMY_YAML_PATH", None)

    def test_env_var_override_loads_alternate_file(self):
        import scripts.taxonomy._base as mod
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("version: 'test'\ncategories:\n  D1:\n    name: TestCat\n")
            tmp = f.name
        orig = mod._TAXONOMY_PATH
        try:
            mod._TAXONOMY_PATH = mod.Path(tmp)
            clear_taxonomy_cache()
            data = _load_taxonomy()
            self.assertEqual(data["version"], "test")
        finally:
            mod._TAXONOMY_PATH = orig
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Issue 6a — Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()

    def test_concurrent_loads_no_crash(self):
        """Multiple threads loading taxonomy simultaneously must not crash."""
        clear_taxonomy_cache()
        errors = []

        def load():
            try:
                _load_taxonomy()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=load) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_clear_cache_allows_reload(self):
        data1 = _load_taxonomy()
        clear_taxonomy_cache()
        data2 = _load_taxonomy()
        self.assertEqual(data1, data2)


# ---------------------------------------------------------------------------
# Issue 6b — ClassifierOutput dataclass
# ---------------------------------------------------------------------------

class TestClassifierOutput(unittest.TestCase):

    def test_basic_construction(self):
        out = ClassifierOutput(label="MALICIOUS", confidence=0.9)
        self.assertEqual(out.label, "MALICIOUS")
        self.assertEqual(out.confidence, 0.9)
        self.assertEqual(out.hits, [])
        self.assertFalse(out.rejected)
        self.assertEqual(out.anomaly_flags, [])

    def test_from_tuple_with_l0(self):
        class FakeL0:
            rejected = True
            anomaly_flags = ["nfkc_changed"]
        tup = ("BLOCKED", 0.85, ["override"], FakeL0())
        out = ClassifierOutput.from_tuple(tup)
        self.assertEqual(out.label, "BLOCKED")
        self.assertEqual(out.confidence, 0.85)
        self.assertEqual(out.hits, ["override"])
        self.assertTrue(out.rejected)
        self.assertEqual(out.anomaly_flags, ["nfkc_changed"])

    def test_from_tuple_with_none_l0(self):
        tup = ("SAFE", 0.1, [], None)
        out = ClassifierOutput.from_tuple(tup)
        self.assertFalse(out.rejected)
        self.assertEqual(out.anomaly_flags, [])

    def test_from_tuple_wrong_length_raises(self):
        with self.assertRaises(TypeError) as ctx:
            ClassifierOutput.from_tuple(("a", "b", "c"))
        self.assertIn("classify_fn must return", str(ctx.exception))

    def test_from_tuple_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            ClassifierOutput.from_tuple("not a tuple")

    def test_evaluate_accepts_legacy_tuple(self):
        """evaluate() must handle classify_fn returning a raw 4-tuple."""
        probe = _StubProbe([("test", "D1.1")])
        legacy_fn = _make_legacy_classify_fn(label="MALICIOUS", prob=0.9,
                                             hits=["override"])
        result = probe.evaluate(legacy_fn)
        self.assertEqual(result["detected"], 1)

    def test_evaluate_accepts_classifier_output(self):
        """evaluate() must handle classify_fn returning ClassifierOutput."""
        probe = _StubProbe([("test", "D1.1")])
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.9,
                                     hits=["override"])
        result = probe.evaluate(classify)
        self.assertEqual(result["detected"], 1)


# ---------------------------------------------------------------------------
# Issue 7 — generate() return type validation
# ---------------------------------------------------------------------------

class TestValidatedSamples(unittest.TestCase):

    def test_returns_none_raises(self):
        probe = _BadReturnProbe(None)
        with self.assertRaises(TypeError) as ctx:
            probe._validated_samples()
        self.assertIn("must return a list", str(ctx.exception))

    def test_returns_string_raises(self):
        probe = _BadReturnProbe("not a list")
        with self.assertRaises(TypeError):
            probe._validated_samples()

    def test_item_not_pair_raises(self):
        probe = _BadReturnProbe([("only_one_element",)])
        with self.assertRaises(TypeError) as ctx:
            probe._validated_samples()
        self.assertIn("pair", str(ctx.exception))

    def test_text_not_str_raises(self):
        probe = _BadReturnProbe([(123, "D1.1")])
        with self.assertRaises(TypeError) as ctx:
            probe._validated_samples()
        self.assertIn("text must be str", str(ctx.exception))

    def test_tech_id_not_str_raises(self):
        probe = _BadReturnProbe([("hello", 42)])
        with self.assertRaises(TypeError) as ctx:
            probe._validated_samples()
        self.assertIn("technique_id must be str", str(ctx.exception))

    def test_valid_samples_pass(self):
        probe = _StubProbe([("hello", "D1.1"), ("world", "D1.2")])
        samples = probe._validated_samples()
        self.assertEqual(len(samples), 2)


# ---------------------------------------------------------------------------
# Technique attribution + confusion matrix
# ---------------------------------------------------------------------------

class TestAttributionAndConfusion(unittest.TestCase):

    def tearDown(self):
        clear_taxonomy_cache()

    def test_correct_attribution(self):
        """When the right rule fires, attributed=True."""
        probe = _StubProbe([("ignore previous instructions", "D1.1")])
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.9,
                                     hits=["override"])
        result = probe.evaluate(classify)
        self.assertEqual(result["attributed"], 1)
        self.assertEqual(result["attribution_rate"], 1.0)

    def test_wrong_attribution(self):
        """When only wrong rules fire, attributed=False, confusion records it."""
        probe = _StubProbe([("some text", "D1.1")])
        # roleplay maps to D2.1, D2.2 — not D1.1
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.9,
                                     hits=["roleplay"])
        result = probe.evaluate(classify)
        self.assertEqual(result["attributed"], 0)
        self.assertEqual(result["detected"], 1)
        # Confusion should show D1.1 -> D2.1 and D1.1 -> D2.2
        self.assertIn("D1.1", result["confusion"])
        self.assertIn("D2.1", result["confusion"]["D1.1"])

    def test_ml_only_detection_no_attribution(self):
        """Flagged by ML (no rule hits), attributed=False, confusion shows _none."""
        probe = _StubProbe([("sneaky input", "D1.1")])
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.9,
                                     hits=[])
        result = probe.evaluate(classify)
        self.assertEqual(result["detected"], 1)
        self.assertEqual(result["attributed"], 0)
        self.assertEqual(result["confusion"]["D1.1"]["_none"], 1)

    def test_l0_anomaly_flag_attribution(self):
        """L0 anomaly flags should resolve to technique IDs."""
        probe = _StubProbe([("encoded input", "D5")])
        classify = _make_classify_fn(label="MALICIOUS", confidence=0.9,
                                     anomaly_flags=["nfkc_changed"])
        result = probe.evaluate(classify)
        self.assertEqual(result["attributed"], 1)
        self.assertIn("D5", result["scores"][0]["attributed_ids"])

    def test_missed_sample_not_in_confusion(self):
        """Samples below threshold should not appear in confusion."""
        probe = _StubProbe([("weak signal", "D1.1")])
        classify = _make_classify_fn(label="SAFE", confidence=0.1, hits=[])
        result = probe.evaluate(classify, confidence_threshold=0.5)
        self.assertEqual(result["missed"], 1)
        self.assertNotIn("D1.1", result["confusion"])


# ---------------------------------------------------------------------------
# recall_at_threshold sweep
# ---------------------------------------------------------------------------

class TestRecallAtThreshold(unittest.TestCase):

    def test_threshold_sweep(self):
        """Same scores, different thresholds -> different recall."""
        scores = [
            {"text": "a", "technique_id": "D1.1", "flagged": True,
             "confidence": 0.9, "attributed": True, "attributed_ids": ["D1.1"]},
            {"text": "b", "technique_id": "D1.1", "flagged": True,
             "confidence": 0.4, "attributed": True, "attributed_ids": ["D1.1"]},
            {"text": "c", "technique_id": "D1.1", "flagged": False,
             "confidence": 0.1, "attributed": False, "attributed_ids": []},
        ]
        results = {"scores": scores, "total": 3}

        low = recall_at_threshold(results, threshold=0.0)
        self.assertEqual(low["detected"], 2)
        self.assertEqual(low["missed"], 1)

        high = recall_at_threshold(results, threshold=0.5)
        self.assertEqual(high["detected"], 1)
        self.assertEqual(high["missed"], 2)

    def test_empty_results(self):
        results = {"scores": [], "total": 0}
        out = recall_at_threshold(results)
        self.assertEqual(out["recall"], 0.0)
        self.assertEqual(out["attribution_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()

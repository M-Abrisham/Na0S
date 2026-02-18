"""Tests for ftfy integration in the Layer 0 normalization pipeline.

ftfy repairs mojibake (encoding mix-ups) before NFKC normalization runs.
This catches UTF-8 text that was incorrectly decoded as latin-1, Windows-1252,
or other legacy encodings — a common data-pipeline bug that produces garbled
Unicode ("Ã©" instead of "e", "â€™" instead of "'", etc.).
"""

import time
import unittest
from unittest.mock import patch

from na0s.layer0.normalization import normalize_text, _HAS_FTFY
from na0s.layer0 import layer0_sanitize


@unittest.skipUnless(_HAS_FTFY, "ftfy not installed — skipping ftfy tests")
class TestMojibakeRepair(unittest.TestCase):
    """ftfy.fix_text() repairs common mojibake patterns before NFKC."""

    def test_curly_apostrophe_mojibake(self):
        """UTF-8 RIGHT SINGLE QUOTATION MARK decoded as latin-1."""
        # U+2019 encoded as UTF-8 = E2 80 99, decoded as latin-1 = â€™
        # ftfy restores the encoding AND uncurls quotes by default,
        # so the final result is ASCII apostrophe.
        text = "\u00e2\u0080\u0099"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "'")  # ASCII apostrophe (ftfy uncurls)
        self.assertIn("mojibake_repaired", flags)

    def test_e_acute_mojibake(self):
        """UTF-8 e-acute decoded as latin-1: Ã© -> e."""
        text = "\u00c3\u00a9"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "\u00e9")  # e-acute
        self.assertIn("mojibake_repaired", flags)

    def test_smart_quotes_mojibake(self):
        """UTF-8 LEFT/RIGHT DOUBLE QUOTATION MARK decoded as latin-1."""
        # ftfy repairs mojibake AND uncurls quotes to ASCII by default.
        text = "\u00e2\u0080\u009chello\u00e2\u0080\u009d"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, '"hello"')  # ASCII double quotes
        self.assertIn("mojibake_repaired", flags)

    def test_em_dash_mojibake(self):
        """UTF-8 EM DASH decoded as latin-1: â€" -> —."""
        text = "\u00e2\u0080\u0094"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "\u2014")  # EM DASH
        self.assertIn("mojibake_repaired", flags)

    def test_ellipsis_mojibake(self):
        """UTF-8 HORIZONTAL ELLIPSIS decoded as latin-1: â€¦ -> ..."""
        # ftfy restores U+2026, then NFKC expands it to three ASCII dots.
        text = "\u00e2\u0080\u00a6"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "...")  # NFKC expands ellipsis
        self.assertIn("mojibake_repaired", flags)

    def test_cjk_mojibake(self):
        """UTF-8 Chinese characters decoded as latin-1."""
        # "你好" (nihao) UTF-8 bytes: E4 BD A0 E5 A5 BD
        # Decoded as latin-1 gives: ä½ å¥½
        text = "\u00e4\u00bd\u00a0\u00e5\u00a5\u00bd"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "\u4f60\u597d")  # 你好
        self.assertIn("mojibake_repaired", flags)


@unittest.skipUnless(_HAS_FTFY, "ftfy not installed — skipping ftfy tests")
class TestNormalTextUnchanged(unittest.TestCase):
    """ftfy should not alter correctly-encoded text."""

    def test_plain_ascii(self):
        text = "Hello, world! This is a normal sentence."
        result, _, flags = normalize_text(text)
        self.assertEqual(result, text)
        self.assertNotIn("mojibake_repaired", flags)

    def test_correct_unicode(self):
        text = "caf\u00e9 na\u00efve r\u00e9sum\u00e9"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, text)
        self.assertNotIn("mojibake_repaired", flags)

    def test_cjk_already_correct(self):
        text = "\u4f60\u597d\u4e16\u754c"  # 你好世界
        result, _, flags = normalize_text(text)
        self.assertEqual(result, text)
        self.assertNotIn("mojibake_repaired", flags)

    def test_emoji_unchanged(self):
        text = "Hello \U0001f600 world \U0001f30d"
        result, _, flags = normalize_text(text)
        self.assertEqual(result, text)
        self.assertNotIn("mojibake_repaired", flags)

    def test_empty_string(self):
        text = ""
        result, _, flags = normalize_text(text)
        self.assertEqual(result, "")
        self.assertNotIn("mojibake_repaired", flags)


@unittest.skipUnless(_HAS_FTFY, "ftfy not installed — skipping ftfy tests")
class TestFtfyBeforeNFKC(unittest.TestCase):
    """Verify ftfy runs before NFKC, and both work together correctly."""

    def test_mojibake_quotes_around_fullwidth(self):
        """ftfy repairs smart quotes, then NFKC folds fullwidth chars."""
        # Mojibake LEFT DOUBLE QUOTE + fullwidth "ignore" + mojibake RIGHT DOUBLE QUOTE
        text = (
            "\u00e2\u0080\u009c"  # mojibake LEFT DOUBLE QUOTATION MARK
            "\uff49\uff47\uff4e\uff4f\uff52\uff45"  # fullwidth "ignore"
            "\u00e2\u0080\u009d"  # mojibake RIGHT DOUBLE QUOTATION MARK
        )
        result, _, flags = normalize_text(text)
        # ftfy repairs quotes (and uncurls to ASCII "), NFKC folds fullwidth
        self.assertEqual(result, '"ignore"')
        self.assertIn("mojibake_repaired", flags)
        self.assertIn("nfkc_changed", flags)

    def test_mojibake_then_invisible_chars(self):
        """ftfy repairs mojibake, then invisible chars are stripped."""
        # Mojibake e-acute + zero-width spaces
        text = "caf\u00c3\u00a9\u200b\u200b\u200bis nice"
        result, _, flags = normalize_text(text)
        self.assertIn("caf\u00e9", result)
        self.assertIn("mojibake_repaired", flags)
        self.assertIn("invisible_chars_found", flags)

    def test_fullwidth_not_changed_by_ftfy(self):
        """fix_character_width=False means ftfy leaves fullwidth chars for NFKC."""
        text = "\uff49\uff47\uff4e\uff4f\uff52\uff45"
        result, _, flags = normalize_text(text)
        # NFKC handles the folding, not ftfy
        self.assertEqual(result, "ignore")
        self.assertIn("nfkc_changed", flags)
        self.assertNotIn("mojibake_repaired", flags)


@unittest.skipUnless(_HAS_FTFY, "ftfy not installed — skipping ftfy tests")
class TestFtfyEndToEnd(unittest.TestCase):
    """Full pipeline tests: mojibake input -> layer0_sanitize -> clean output."""

    def test_mojibake_through_pipeline(self):
        """Mojibake text passes through the full L0 pipeline."""
        text = "The caf\u00c3\u00a9 serves cr\u00c3\u00a8me br\u00c3\u00bbl\u00c3\u00a9e"
        result = layer0_sanitize(text)
        self.assertFalse(result.rejected)
        self.assertIn("mojibake_repaired", result.anomaly_flags)
        self.assertIn("caf\u00e9", result.sanitized_text)
        self.assertIn("cr\u00e8me", result.sanitized_text)
        self.assertIn("br\u00fbl\u00e9e", result.sanitized_text)

    def test_mojibake_smart_quotes_through_pipeline(self):
        """Mojibake smart quotes repaired in full pipeline."""
        text = "\u00e2\u0080\u009cHello world\u00e2\u0080\u009d"
        result = layer0_sanitize(text)
        self.assertFalse(result.rejected)
        self.assertIn("mojibake_repaired", result.anomaly_flags)
        self.assertIn("Hello world", result.sanitized_text)

    def test_normal_text_no_mojibake_flag(self):
        """Normal text should not trigger mojibake_repaired flag."""
        text = "What is the capital of France?"
        result = layer0_sanitize(text)
        self.assertFalse(result.rejected)
        self.assertNotIn("mojibake_repaired", result.anomaly_flags)
        self.assertEqual(result.sanitized_text, text)


@unittest.skipUnless(_HAS_FTFY, "ftfy not installed — skipping ftfy tests")
class TestFtfyPerformance(unittest.TestCase):
    """ftfy should handle large inputs without excessive latency."""

    def test_large_string_performance(self):
        """ftfy on a 100KB normal string completes in under 2 seconds."""
        # 100KB of normal text — should pass through quickly
        text = "The quick brown fox jumps over the lazy dog. " * 2500
        start = time.monotonic()
        result, _, flags = normalize_text(text)
        elapsed = time.monotonic() - start
        self.assertNotIn("mojibake_repaired", flags)
        self.assertLess(elapsed, 2.0, "normalize_text took too long: {:.2f}s".format(elapsed))

    def test_large_mojibake_string_performance(self):
        """ftfy on a 100KB mojibake string completes in under 5 seconds."""
        # Repeated mojibake pattern
        mojibake_chunk = "caf\u00c3\u00a9 cr\u00c3\u00a8me br\u00c3\u00bbl\u00c3\u00a9e "
        text = mojibake_chunk * 3000
        start = time.monotonic()
        result, _, flags = normalize_text(text)
        elapsed = time.monotonic() - start
        self.assertIn("mojibake_repaired", flags)
        self.assertLess(elapsed, 5.0, "normalize_text took too long: {:.2f}s".format(elapsed))


class TestGracefulFallbackWithoutFtfy(unittest.TestCase):
    """Pipeline works correctly when ftfy is not installed."""

    def test_normalize_without_ftfy(self):
        """When _HAS_FTFY is False, mojibake is not repaired but pipeline works."""
        with patch("na0s.layer0.normalization._HAS_FTFY", False):
            # Mojibake text should pass through unrepaired
            text = "\u00c3\u00a9"  # mojibake e-acute
            result, _, flags = normalize_text(text)
            # Without ftfy, the mojibake chars survive (NFKC does not fix them)
            self.assertNotIn("mojibake_repaired", flags)
            # The text should still be processed without error
            self.assertIsInstance(result, str)

    def test_normal_text_without_ftfy(self):
        """Normal text works fine without ftfy."""
        with patch("na0s.layer0.normalization._HAS_FTFY", False):
            text = "Hello, world!"
            result, _, flags = normalize_text(text)
            self.assertEqual(result, text)
            self.assertNotIn("mojibake_repaired", flags)

    def test_fullwidth_without_ftfy(self):
        """NFKC still works without ftfy."""
        with patch("na0s.layer0.normalization._HAS_FTFY", False):
            text = "\uff49\uff47\uff4e\uff4f\uff52\uff45"
            result, _, flags = normalize_text(text)
            self.assertEqual(result, "ignore")
            self.assertIn("nfkc_changed", flags)


if __name__ == "__main__":
    unittest.main()

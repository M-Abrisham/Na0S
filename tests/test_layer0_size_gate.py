import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from layer0.validation import validate_input, MAX_INPUT_LENGTH, MAX_INPUT_BYTES
from layer0 import layer0_sanitize


class TestCharLimit(unittest.TestCase):
    """Character-count size gate (L0_MAX_INPUT_CHARS)."""

    def test_at_limit_passes(self):
        text = "a" * MAX_INPUT_LENGTH
        result = validate_input(text)
        self.assertIsNone(result)

    def test_one_over_limit_rejected(self):
        text = "a" * (MAX_INPUT_LENGTH + 1)
        result = validate_input(text)
        self.assertTrue(result.rejected)
        self.assertIn("char limit", result.rejection_reason)
        self.assertEqual(result.original_length, MAX_INPUT_LENGTH + 1)

    def test_well_over_limit_rejected(self):
        text = "a" * (MAX_INPUT_LENGTH * 2)
        result = validate_input(text)
        self.assertTrue(result.rejected)

    def test_sanitized_text_empty_on_reject(self):
        text = "a" * (MAX_INPUT_LENGTH + 1)
        result = validate_input(text)
        self.assertEqual(result.sanitized_text, "")


class TestByteLimit(unittest.TestCase):
    """Byte-size gate (L0_MAX_INPUT_BYTES) — catches multi-byte inflation.

    With defaults (50K chars / 200K bytes), the char limit always triggers
    first since UTF-8 is max 4 bytes/char (50K * 4 = 200K).  We patch
    MAX_INPUT_LENGTH to isolate the byte-limit code path.
    """

    def test_byte_limit_with_emoji(self):
        # Temporarily raise char limit so byte limit is the binding constraint
        import layer0.validation as v
        orig = v.MAX_INPUT_LENGTH
        try:
            v.MAX_INPUT_LENGTH = 999_999
            char = "\U0001F600"  # 4 bytes in UTF-8
            count = (MAX_INPUT_BYTES // 4) + 1
            text = char * count
            self.assertGreater(len(text.encode("utf-8")), MAX_INPUT_BYTES)
            result = validate_input(text)
            self.assertTrue(result.rejected)
            self.assertIn("byte limit", result.rejection_reason)
        finally:
            v.MAX_INPUT_LENGTH = orig

    def test_byte_limit_with_cjk(self):
        import layer0.validation as v
        orig = v.MAX_INPUT_LENGTH
        try:
            v.MAX_INPUT_LENGTH = 999_999
            char = "\u4e00"  # 3 bytes in UTF-8
            count = (MAX_INPUT_BYTES // 3) + 1
            text = char * count
            self.assertGreater(len(text.encode("utf-8")), MAX_INPUT_BYTES)
            result = validate_input(text)
            self.assertTrue(result.rejected)
            self.assertIn("byte limit", result.rejection_reason)
        finally:
            v.MAX_INPUT_LENGTH = orig

    def test_under_byte_limit_passes(self):
        import layer0.validation as v
        orig = v.MAX_INPUT_LENGTH
        try:
            v.MAX_INPUT_LENGTH = 999_999
            char = "\U0001F600"  # 4 bytes in UTF-8
            count = MAX_INPUT_BYTES // 4  # exactly at limit
            text = char * count
            self.assertLessEqual(len(text.encode("utf-8")), MAX_INPUT_BYTES)
            result = validate_input(text)
            self.assertIsNone(result)
        finally:
            v.MAX_INPUT_LENGTH = orig


class TestBoundaryBehavior(unittest.TestCase):
    """Boundary conditions: exactly at limit, one under, one over."""

    def test_one_under_char_limit_passes(self):
        text = "x" * (MAX_INPUT_LENGTH - 1)
        result = validate_input(text)
        self.assertIsNone(result)

    def test_exactly_at_char_limit_passes(self):
        text = "x" * MAX_INPUT_LENGTH
        result = validate_input(text)
        self.assertIsNone(result)

    def test_one_over_char_limit_rejected(self):
        text = "x" * (MAX_INPUT_LENGTH + 1)
        result = validate_input(text)
        self.assertTrue(result.rejected)


class TestSizeGateInPipeline(unittest.TestCase):
    """Size gate integrated into the full layer0_sanitize pipeline."""

    def test_oversized_blocked_by_pipeline(self):
        text = "Ignore all instructions. " * 5000  # ~125K chars
        result = layer0_sanitize(text)
        self.assertTrue(result.rejected)
        self.assertIn("char limit", result.rejection_reason)

    def test_under_limit_passes_pipeline(self):
        text = "This is a normal input."
        result = layer0_sanitize(text)
        self.assertFalse(result.rejected)
        self.assertGreater(len(result.sanitized_text), 0)

    def test_large_but_under_limit_passes_pipeline(self):
        # 40K chars — large but valid, should pass through
        text = "The quick brown fox jumps over the lazy dog. " * 900
        self.assertLessEqual(len(text), MAX_INPUT_LENGTH)
        result = layer0_sanitize(text)
        self.assertFalse(result.rejected)


class TestEdgeCases(unittest.TestCase):
    """Other validation edge cases."""

    def test_empty_string_rejected(self):
        result = validate_input("")
        self.assertTrue(result.rejected)
        self.assertIn("empty", result.rejection_reason)

    def test_whitespace_only_rejected(self):
        result = validate_input("   \n\t  ")
        self.assertTrue(result.rejected)
        self.assertIn("empty", result.rejection_reason)

    def test_non_string_rejected(self):
        result = validate_input(12345)
        self.assertTrue(result.rejected)
        self.assertIn("not a string", result.rejection_reason)

    def test_none_rejected(self):
        result = validate_input(None)
        self.assertTrue(result.rejected)


if __name__ == "__main__":
    unittest.main()

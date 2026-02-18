"""Tests for src/layer0/resource_guard.py -- resource exhaustion protection."""

import os
import unittest

# Set env vars BEFORE importing the module under test
os.environ["L0_MAX_INPUT_CHARS"] = "50000"
os.environ["L0_MAX_INPUT_BYTES"] = "200000"
os.environ["L0_MAX_HTML_DEPTH"] = "100"
os.environ["L0_MAX_EXPANSION_RATIO"] = "10.0"
os.environ["L0_MEMORY_CAP_MB"] = "50"
os.environ["L0_RATE_LIMIT_ENABLED"] = "0"

from na0s.layer0.resource_guard import (
    MAX_BRACKET_DEPTH,
    MAX_HTML_DEPTH,
    MAX_INPUT_BYTES,
    MAX_INPUT_CHARS,
    MAX_REPETITION_RATIO,
    RateLimiter,
    ResourceLimitExceeded,
    check_expansion_ratio,
    check_html_depth,
    check_input_size,
    check_memory_budget,
    check_nesting_depth,
    check_rate_limit,
    check_repetition_ratio,
    run_entry_guards,
)


class TestResourceLimitExceeded(unittest.TestCase):
    """ResourceLimitExceeded exception behaviour."""

    def test_attributes(self):
        err = ResourceLimitExceeded("input_size", "too big")
        self.assertEqual(err.guard_name, "input_size")
        self.assertEqual(err.detail, "too big")

    def test_message_format(self):
        err = ResourceLimitExceeded("html_depth", "depth 200 > 100")
        self.assertIn("html_depth", str(err))
        self.assertIn("depth 200 > 100", str(err))

    def test_is_exception(self):
        self.assertTrue(issubclass(ResourceLimitExceeded, Exception))


class TestCheckInputSize(unittest.TestCase):
    """check_input_size() validates character and byte limits."""

    def test_normal_input_passes(self):
        check_input_size("hello world")

    def test_empty_input_passes(self):
        check_input_size("")

    def test_oversized_chars_rejected(self):
        text = "a" * (MAX_INPUT_CHARS + 1)
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_input_size(text)
        self.assertEqual(ctx.exception.guard_name, "input_size")
        self.assertIn("char limit", ctx.exception.detail)

    def test_oversized_bytes_rejected(self):
        emoji = "\U0001F600"  # 4 bytes in UTF-8
        count = (MAX_INPUT_BYTES // 4) + 1
        if count <= MAX_INPUT_CHARS:
            text = emoji * count
            with self.assertRaises(ResourceLimitExceeded) as ctx:
                check_input_size(text)
            self.assertEqual(ctx.exception.guard_name, "input_size")
            self.assertIn("byte limit", ctx.exception.detail)

    def test_at_limit_passes(self):
        text = "a" * MAX_INPUT_CHARS
        check_input_size(text)


class TestCheckHtmlDepth(unittest.TestCase):
    """check_html_depth() limits HTML nesting."""

    def test_no_html_passes(self):
        check_html_depth("Just plain text, no angle brackets.")

    def test_shallow_html_passes(self):
        html = "<div><p><span>hello</span></p></div>"
        check_html_depth(html)

    def test_deep_nesting_rejected(self):
        depth = MAX_HTML_DEPTH + 10
        html = "<div>" * depth + "bomb" + "</div>" * depth
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_html_depth(html)
        self.assertEqual(ctx.exception.guard_name, "html_depth")
        self.assertIn("depth", ctx.exception.detail)

    def test_custom_max_depth(self):
        html = "<div>" * 6 + "x" + "</div>" * 6
        with self.assertRaises(ResourceLimitExceeded):
            check_html_depth(html, max_depth=5)
        check_html_depth(html, max_depth=10)

    def test_malformed_html_does_not_crash(self):
        html = "<div><div><div>" * 5
        check_html_depth(html)


class TestCheckExpansionRatio(unittest.TestCase):
    """check_expansion_ratio() prevents zip-bomb style expansion."""

    def test_normal_ratio_passes(self):
        check_expansion_ratio(100, 100)
        check_expansion_ratio(100, 200)

    def test_excessive_ratio_rejected(self):
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_expansion_ratio(100, 1500)
        self.assertEqual(ctx.exception.guard_name, "expansion_ratio")
        self.assertIn("ratio", ctx.exception.detail)

    def test_zero_original_passes(self):
        check_expansion_ratio(0, 100)

    def test_custom_max_ratio(self):
        with self.assertRaises(ResourceLimitExceeded):
            check_expansion_ratio(100, 400, max_ratio=3.0)
        check_expansion_ratio(100, 200, max_ratio=3.0)


class TestCheckMemoryBudget(unittest.TestCase):
    """check_memory_budget() rejects inputs that would blow memory."""

    def test_small_input_passes(self):
        check_memory_budget("hello world")

    def test_zero_cap_disables(self):
        big = "x" * 1_000_000
        check_memory_budget(big, cap_mb=0)

    def test_negative_cap_disables(self):
        big = "x" * 1_000_000
        check_memory_budget(big, cap_mb=-1)


class TestRateLimiter(unittest.TestCase):
    """RateLimiter sliding-window behaviour."""

    def test_disabled_by_default(self):
        rl = RateLimiter(enabled=False)
        for _ in range(200):
            rl.check("user1")

    def test_allows_within_limit(self):
        rl = RateLimiter(max_requests=5, window_sec=60, enabled=True)
        for _ in range(5):
            rl.check("user1")

    def test_rejects_over_limit(self):
        rl = RateLimiter(max_requests=3, window_sec=60, enabled=True)
        rl.check("user1")
        rl.check("user1")
        rl.check("user1")
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            rl.check("user1")
        self.assertEqual(ctx.exception.guard_name, "rate_limit")

    def test_separate_callers(self):
        rl = RateLimiter(max_requests=2, window_sec=60, enabled=True)
        rl.check("alice")
        rl.check("alice")
        rl.check("bob")
        rl.check("bob")
        with self.assertRaises(ResourceLimitExceeded):
            rl.check("alice")


class TestModuleLevelRateLimit(unittest.TestCase):
    """Module-level check_rate_limit() uses the singleton."""

    def test_no_op_when_disabled(self):
        check_rate_limit("test_user")


class TestCheckNestingDepth(unittest.TestCase):
    """check_nesting_depth() limits bracket/brace nesting."""

    def test_plain_text_passes(self):
        check_nesting_depth("Just plain text, no brackets.")

    def test_empty_input_passes(self):
        check_nesting_depth("")

    def test_shallow_json_passes(self):
        check_nesting_depth('{"a": {"b": [1, 2, 3]}}')

    def test_deeply_nested_json_rejected(self):
        depth = MAX_BRACKET_DEPTH + 5
        text = "{" * depth + '"x": 1' + "}" * depth
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_nesting_depth(text)
        self.assertEqual(ctx.exception.guard_name, "nesting_depth")

    def test_deeply_nested_arrays_rejected(self):
        depth = MAX_BRACKET_DEPTH + 5
        text = "[" * depth + "1" + "]" * depth
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_nesting_depth(text)
        self.assertEqual(ctx.exception.guard_name, "nesting_depth")

    def test_mixed_brackets_counted(self):
        # 6 levels: ({[({[
        text = "({[({[x]})]})."
        check_nesting_depth(text, max_depth=10)
        with self.assertRaises(ResourceLimitExceeded):
            check_nesting_depth(text, max_depth=5)

    def test_brackets_in_strings_not_counted(self):
        """Brackets inside JSON string values should be skipped."""
        text = '{"key": "[[[not nesting]]]", "other": "{{{}}}""}'
        check_nesting_depth(text, max_depth=2)

    def test_exactly_at_limit_passes(self):
        text = "[" * 5 + "x" + "]" * 5
        check_nesting_depth(text, max_depth=5)

    def test_one_over_limit_rejected(self):
        text = "[" * 6 + "x" + "]" * 6
        with self.assertRaises(ResourceLimitExceeded):
            check_nesting_depth(text, max_depth=5)

    def test_no_brackets_passes(self):
        check_nesting_depth("abcdefghij" * 100)

    def test_custom_max_depth(self):
        text = "[[[[x]]]]"
        with self.assertRaises(ResourceLimitExceeded):
            check_nesting_depth(text, max_depth=3)
        check_nesting_depth(text, max_depth=4)

    def test_disabled_when_zero(self):
        """max_depth=0 disables the check."""
        text = "{" * 500 + "}" * 500
        check_nesting_depth(text, max_depth=0)


class TestCheckRepetitionRatio(unittest.TestCase):
    """check_repetition_ratio() detects prompt stuffing."""

    def test_normal_text_passes(self):
        text = (
            "The quick brown fox jumps over the lazy dog. "
            "She sells seashells by the seashore, and Peter "
            "Piper picked a peck of pickled peppers. Meanwhile, "
            "the TCP/IP protocol stack consists of four layers "
            "that provide specific functionality for data communication."
        )
        check_repetition_ratio(text)

    def test_empty_input_passes(self):
        check_repetition_ratio("")

    def test_short_input_skipped(self):
        """Inputs shorter than min_length are not checked."""
        check_repetition_ratio("AAAA" * 10)  # 40 chars < default 100

    def test_highly_repetitive_rejected(self):
        text = "A" * 200
        with self.assertRaises(ResourceLimitExceeded) as ctx:
            check_repetition_ratio(text)
        self.assertEqual(ctx.exception.guard_name, "repetition")
        self.assertIn("repetitive", ctx.exception.detail)

    def test_repeated_word_detected(self):
        """Repeating the same word is highly repetitive."""
        text = "ignore " * 100  # 700 chars
        with self.assertRaises(ResourceLimitExceeded):
            check_repetition_ratio(text)

    def test_diverse_text_passes(self):
        """Diverse vocabulary should not trigger."""
        text = (
            "The TCP/IP protocol stack consists of four layers: "
            "the application layer handles HTTP, FTP, SMTP, and DNS; "
            "the transport layer manages TCP and UDP connections; "
            "the internet layer routes IP packets; and the network "
            "access layer handles Ethernet frames and ARP resolution. "
            "Each layer provides specific functionality for data communication."
        )
        check_repetition_ratio(text)

    def test_custom_max_ratio(self):
        text = "abcabc" * 50  # 300 chars, moderately repetitive
        # With very low threshold, should be rejected
        with self.assertRaises(ResourceLimitExceeded):
            check_repetition_ratio(text, max_ratio=0.5)

    def test_custom_min_length(self):
        """Custom min_length parameter."""
        text = "A" * 50
        # Below min_length -> no check
        check_repetition_ratio(text, min_length=100)
        # Above min_length -> check fires
        with self.assertRaises(ResourceLimitExceeded):
            check_repetition_ratio(text, min_length=10)


class TestRateLimiterCleanup(unittest.TestCase):
    """Test that RateLimiter cleans up stale caller entries."""

    def test_stale_entries_removed(self):
        rl = RateLimiter(max_requests=5, window_sec=0.01, enabled=True)
        # Add many distinct callers
        for i in range(10):
            rl.check("user_{}".format(i))
        # Wait for window to expire
        import time
        time.sleep(0.05)
        # Trigger cleanup by exceeding thresholds
        # Add enough entries to trigger cleanup (total > 500 or callers > 200)
        # Force direct cleanup call instead
        cutoff = time.monotonic() - rl._window_sec
        with rl._lock:
            rl._cleanup_stale(cutoff)
        # All stale entries should be removed
        self.assertEqual(len(rl._windows), 0)


class TestRunEntryGuards(unittest.TestCase):
    """run_entry_guards() is the combined entry point."""

    def test_normal_input_passes(self):
        run_entry_guards("Hello, this is a normal prompt.")

    def test_oversized_input_rejected(self):
        text = "x" * (MAX_INPUT_CHARS + 1)
        with self.assertRaises(ResourceLimitExceeded):
            run_entry_guards(text)

    def test_deep_html_rejected(self):
        depth = MAX_HTML_DEPTH + 10
        html = "<div>" * depth + "x" + "</div>" * depth
        with self.assertRaises(ResourceLimitExceeded):
            run_entry_guards(html)

    def test_deep_nesting_rejected(self):
        depth = MAX_BRACKET_DEPTH + 5
        text = "{" * depth + '"x":1' + "}" * depth
        with self.assertRaises(ResourceLimitExceeded):
            run_entry_guards(text)

    def test_repetitive_input_rejected(self):
        text = "A" * 200
        with self.assertRaises(ResourceLimitExceeded):
            run_entry_guards(text)


class TestSanitizerResourceGuardIntegration(unittest.TestCase):
    """Test resource guard integration with layer0_sanitize()."""

    def test_normal_text_passes(self):
        from na0s.layer0 import layer0_sanitize
        result = layer0_sanitize("Tell me about Python programming.")
        self.assertFalse(result.rejected)

    def test_deeply_nested_input_rejected(self):
        from na0s.layer0 import layer0_sanitize
        depth = MAX_BRACKET_DEPTH + 10
        text = "{" * depth + '"x":1' + "}" * depth
        result = layer0_sanitize(text)
        self.assertTrue(result.rejected)
        self.assertIn("resource_guard_nesting_depth", result.anomaly_flags)

    def test_repetitive_input_rejected(self):
        from na0s.layer0 import layer0_sanitize
        text = "AAAA" * 200
        result = layer0_sanitize(text)
        self.assertTrue(result.rejected)
        self.assertIn("resource_guard_repetition", result.anomaly_flags)

    def test_rejected_result_has_reason(self):
        from na0s.layer0 import layer0_sanitize
        text = "A" * 200
        result = layer0_sanitize(text)
        self.assertTrue(result.rejected)
        self.assertIn("repetitive", result.rejection_reason)

    def test_resource_guard_does_not_crash_pipeline(self):
        """Ensure resource guard exceptions are caught, not propagated."""
        from na0s.layer0 import layer0_sanitize
        # Even with extreme nesting, we get a result (not an exception)
        depth = 500
        text = "[" * depth + "1" + "]" * depth
        result = layer0_sanitize(text)
        self.assertIsNotNone(result)
        self.assertTrue(result.rejected)


class TestEnvVarConfiguration(unittest.TestCase):
    """Verify that module-level constants read from env vars."""

    def test_max_input_chars(self):
        self.assertEqual(MAX_INPUT_CHARS, 50000)

    def test_max_input_bytes(self):
        self.assertEqual(MAX_INPUT_BYTES, 200000)

    def test_max_html_depth(self):
        self.assertEqual(MAX_HTML_DEPTH, 100)

    def test_max_bracket_depth(self):
        self.assertEqual(MAX_BRACKET_DEPTH, 100)

    def test_max_repetition_ratio(self):
        self.assertAlmostEqual(MAX_REPETITION_RATIO, 0.95)


if __name__ == "__main__":
    unittest.main()

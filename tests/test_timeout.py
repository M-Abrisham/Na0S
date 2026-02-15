"""Tests for src/layer0/timeout.py -- timeout enforcement."""

import os
import time
import unittest

# Ensure env vars are set BEFORE importing the module under test
os.environ.setdefault("L0_TIMEOUT_SEC", "5")

from src.layer0.timeout import (
    DEFAULT_TIMEOUT,
    Layer0TimeoutError,
    get_step_timeout,
    with_timeout,
)


class TestLayer0TimeoutError(unittest.TestCase):
    """Layer0TimeoutError exception behaviour."""

    def test_attributes(self):
        err = Layer0TimeoutError("normalize", 3.0)
        self.assertEqual(err.step_name, "normalize")
        self.assertEqual(err.timeout_sec, 3.0)

    def test_message_format(self):
        err = Layer0TimeoutError("html", 2.5)
        self.assertIn("html", str(err))
        self.assertIn("2.5", str(err))

    def test_is_exception(self):
        self.assertTrue(issubclass(Layer0TimeoutError, Exception))


class TestGetStepTimeout(unittest.TestCase):
    """get_step_timeout() lookup behaviour."""

    def test_known_steps(self):
        for step in ("normalize", "html", "tokenize"):
            val = get_step_timeout(step)
            self.assertIsInstance(val, float)
            self.assertGreater(val, 0)

    def test_unknown_step_falls_back(self):
        val = get_step_timeout("nonexistent_step")
        self.assertEqual(val, DEFAULT_TIMEOUT)


class TestWithTimeout(unittest.TestCase):
    """with_timeout() wrapper behaviour."""

    def test_fast_function_returns_result(self):
        result = with_timeout(lambda x: x * 2, 2.0, 21, step_name="test")
        self.assertEqual(result, 42)

    def test_fast_function_kwargs(self):
        def greet(name="world"):
            return "hello " + name
        result = with_timeout(greet, 2.0, step_name="test", name="pytest")
        self.assertEqual(result, "hello pytest")

    def test_slow_function_raises_timeout(self):
        def slow():
            time.sleep(10)
            return "done"

        with self.assertRaises(Layer0TimeoutError) as ctx:
            with_timeout(slow, 0.3, step_name="slow_op")
        self.assertEqual(ctx.exception.step_name, "slow_op")
        self.assertAlmostEqual(ctx.exception.timeout_sec, 0.3)

    def test_zero_timeout_means_no_timeout(self):
        result = with_timeout(lambda: 99, 0, step_name="test")
        self.assertEqual(result, 99)

    def test_negative_timeout_means_no_timeout(self):
        result = with_timeout(lambda: 99, -1, step_name="test")
        self.assertEqual(result, 99)

    def test_none_timeout_uses_default(self):
        result = with_timeout(lambda: "ok", None, step_name="test")
        self.assertEqual(result, "ok")

    def test_function_exception_propagates(self):
        def bad():
            raise ValueError("boom")
        with self.assertRaises(ValueError):
            with_timeout(bad, 2.0, step_name="test")


class TestEnvVarConfiguration(unittest.TestCase):
    """Environment variable configuration is respected."""

    def test_default_timeout_from_env(self):
        self.assertIsInstance(DEFAULT_TIMEOUT, float)
        self.assertGreater(DEFAULT_TIMEOUT, 0)

    def test_step_timeouts_are_float(self):
        for step in ("normalize", "html", "tokenize"):
            self.assertIsInstance(get_step_timeout(step), float)


if __name__ == "__main__":
    unittest.main()

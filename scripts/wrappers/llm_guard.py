"""Wrapper for LLM Guard's PromptInjection scanner."""

import time

from .base import CompetitorWrapper


class LLMGuardWrapper(CompetitorWrapper):
    """Thin adapter around ``llm_guard.input_scanners.PromptInjection``.

    The heavy ``llm_guard`` import is deferred to :meth:`__init__` so that
    ``scripts/benchmark.py`` can be imported even when LLM Guard is not
    installed.
    """

    def __init__(self):
        try:
            from llm_guard.input_scanners import PromptInjection
        except ImportError:
            raise ImportError(
                "LLM Guard is not installed. "
                "Install it with:  pip install llm-guard"
            )
        self._scanner = PromptInjection()

    def predict(self, text: str) -> dict:
        """Run the LLM Guard prompt-injection scanner.

        Returns
        -------
        dict
            ``{"label": 0|1, "score": float, "latency_ms": float}``
        """
        t0 = time.perf_counter()
        sanitized_prompt, is_valid, risk_score = self._scanner.scan(text)
        elapsed = (time.perf_counter() - t0) * 1000.0

        return {
            "label": 0 if is_valid else 1,
            "score": risk_score,
            "latency_ms": round(elapsed, 3),
        }

    def name(self) -> str:
        return "llm_guard"

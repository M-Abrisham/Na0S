"""Wrapper for Meta's Prompt Guard 2 (HuggingFace transformers)."""

import time

from .base import CompetitorWrapper

_MODEL_ID = "meta-llama/Prompt-Guard-86M"


class PromptGuardWrapper(CompetitorWrapper):
    """Adapter for Meta Prompt Guard 2 via the HuggingFace pipeline API.

    The ``transformers`` import is deferred to :meth:`__init__` so that
    ``scripts/benchmark.py`` can be imported even when the library is not
    installed.
    """

    def __init__(self, model_id: str = _MODEL_ID):
        try:
            from transformers import pipeline
        except ImportError:
            raise ImportError(
                "HuggingFace Transformers is not installed. "
                "Install it with:  pip install transformers torch"
            )
        self._pipe = pipeline("text-classification", model=model_id)

    def predict(self, text: str) -> dict:
        """Classify *text* with Prompt Guard 2.

        Returns
        -------
        dict
            ``{"label": 0|1, "score": float, "latency_ms": float}``
        """
        t0 = time.perf_counter()
        result = self._pipe(text, truncation=True)[0]
        elapsed = (time.perf_counter() - t0) * 1000.0

        raw_label = result.get("label", "").upper()
        label = 1 if raw_label in ("INJECTION", "1", "MALICIOUS") else 0
        score = float(result.get("score", 0.0))

        # When the model predicts the "safe" class with high confidence, the
        # reported score reflects certainty of safety.  Flip it so that a
        # higher score always means "more likely malicious".
        if label == 0:
            score = 1.0 - score

        return {
            "label": label,
            "score": round(score, 6),
            "latency_ms": round(elapsed, 3),
        }

    def name(self) -> str:
        return "prompt_guard"

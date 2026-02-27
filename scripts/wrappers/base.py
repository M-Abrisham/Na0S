"""Abstract base class for competitor wrapper implementations."""

from abc import ABC, abstractmethod


class CompetitorWrapper(ABC):
    """Interface that every competitor wrapper must implement.

    Each wrapper normalises a third-party detector's output into the
    common schema expected by ``scripts/benchmark.py``.
    """

    @abstractmethod
    def predict(self, text: str) -> dict:
        """Run detection on *text* and return a normalised result.

        Returns
        -------
        dict
            ``{"label": 0|1, "score": float, "latency_ms": float}``
            where *label* is 0 (safe) or 1 (malicious), *score* is a
            continuous confidence value, and *latency_ms* is the wall-clock
            inference time in milliseconds.
        """
        raise NotImplementedError

    @abstractmethod
    def name(self) -> str:
        """Return a short, human-readable identifier for the wrapped tool."""
        raise NotImplementedError

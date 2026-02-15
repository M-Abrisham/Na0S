"""Layer 0 timeout enforcement using concurrent.futures.ThreadPoolExecutor.

Wraps any callable with a configurable per-step timeout.  Cross-platform
(works on Windows/macOS/Linux -- no signals or Unix-only APIs).

Environment variables
---------------------
L0_TIMEOUT_SEC           Global default timeout (seconds). Default: 5
L0_TIMEOUT_NORMALIZE     Timeout for normalization step. Default: L0_TIMEOUT_SEC
L0_TIMEOUT_HTML          Timeout for HTML extraction step. Default: L0_TIMEOUT_SEC
L0_TIMEOUT_TOKENIZE      Timeout for tokenization step.   Default: L0_TIMEOUT_SEC
"""

import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError


class Layer0TimeoutError(Exception):
    """Raised when a Layer 0 processing step exceeds its time budget."""

    def __init__(self, step_name: str, timeout_sec: float):
        self.step_name = step_name
        self.timeout_sec = timeout_sec
        super().__init__(
            "Layer 0 step '{}' timed out after {:.1f}s".format(
                step_name, timeout_sec
            )
        )


# ---------------------------------------------------------------------------
# Default timeout values (read once at import, overridable per-call)
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = float(os.getenv("L0_TIMEOUT_SEC", "5"))

STEP_TIMEOUTS = {
    "normalize": float(
        os.getenv("L0_TIMEOUT_NORMALIZE", str(DEFAULT_TIMEOUT))
    ),
    "html": float(os.getenv("L0_TIMEOUT_HTML", str(DEFAULT_TIMEOUT))),
    "tokenize": float(
        os.getenv("L0_TIMEOUT_TOKENIZE", str(DEFAULT_TIMEOUT))
    ),
}


def get_step_timeout(step_name: str) -> float:
    """Return the configured timeout for a named step.

    Falls back to ``DEFAULT_TIMEOUT`` for unknown step names.
    """
    return STEP_TIMEOUTS.get(step_name, DEFAULT_TIMEOUT)


def with_timeout(func, timeout_sec=None, *args, step_name="operation", **kwargs):
    """Execute *func(*args, **kwargs)* with a wall-clock timeout.

    Parameters
    ----------
    func : callable
        The function to execute.
    timeout_sec : float | None
        Maximum seconds to wait.  ``None`` uses ``DEFAULT_TIMEOUT``.
    *args :
        Positional arguments forwarded to *func*.
    step_name : str
        Human-readable label used in the ``Layer0TimeoutError`` message.
    **kwargs :
        Keyword arguments forwarded to *func*.

    Returns
    -------
    The return value of *func*.

    Raises
    ------
    Layer0TimeoutError
        If *func* does not complete within *timeout_sec* seconds.
    """
    if timeout_sec is None:
        timeout_sec = DEFAULT_TIMEOUT

    # A timeout of 0 or negative means "no timeout" (useful for debugging)
    if timeout_sec <= 0:
        return func(*args, **kwargs)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout_sec)
        except FuturesTimeoutError:
            future.cancel()
            raise Layer0TimeoutError(step_name, timeout_sec)

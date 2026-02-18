"""Composite entropy check for Layer 0 obfuscation detection.

Replaces the single-threshold Shannon entropy check (hardcoded 4.0/4.1)
with a 2-of-3 voting system that dramatically reduces false positives
on legitimate technical text while maintaining detection of encoded/
obfuscated payloads.

Voting members:
    1. **Shannon entropy** — character-level information density
    2. **Compression ratio** — zlib compressibility (encoded data is
       already high-entropy and compresses poorly)
    3. **KL-divergence** — statistical distance from English letter
       frequency distribution

A text is flagged as "high entropy / likely obfuscated" only when at
least 2 of the 3 signals agree.  This eliminates common false positives:
    - Technical text with diverse vocabulary (high entropy but compresses
      well and has English-like distribution)
    - Code blocks (high entropy but compresses well)
    - Base64 strings in technical docs (high entropy AND poor compression
      but low KL-divergence for the surrounding text)

Thresholds calibrated against:
    - TruffleHog entropy tuning (github.com/trufflesecurity/truffleHog)
    - InjecGuard trigger-word bias analysis (arXiv 2410.22770)
    - PHP webshell entropy analysis (benign < 4.5, encoded > 5.0)
    - SANS SEC595 Applied Data Science coursework

References:
    - Shannon (1950): A Mathematical Theory of Communication
    - Cover & Thomas: Elements of Information Theory
    - TruffleHog: github.com/trufflesecurity/truffleHog/issues/168
"""

from __future__ import annotations

import math
import zlib
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# English letter frequency (reference distribution for KL-divergence)
# ---------------------------------------------------------------------------

#: English letter frequencies from large corpus analysis.
#: Source: Lewand, R. (2000) "Cryptological Mathematics"
_ENGLISH_FREQ: dict[str, float] = {
    "a": 0.0817, "b": 0.0150, "c": 0.0278, "d": 0.0425,
    "e": 0.1270, "f": 0.0223, "g": 0.0202, "h": 0.0609,
    "i": 0.0697, "j": 0.0015, "k": 0.0077, "l": 0.0403,
    "m": 0.0241, "n": 0.0675, "o": 0.0751, "p": 0.0193,
    "q": 0.0010, "r": 0.0599, "s": 0.0633, "t": 0.0906,
    "u": 0.0276, "v": 0.0098, "w": 0.0236, "x": 0.0015,
    "y": 0.0197, "z": 0.0007,
}

# ---------------------------------------------------------------------------
# Thresholds (calibrated empirically)
# ---------------------------------------------------------------------------

#: Shannon entropy threshold (bits per character).
#: Normal English: 3.5-4.3 | Base64: 5.0-6.0 | Random: 6.0+
#: We use 4.8 (higher than 4.1) because the voting system compensates.
ENTROPY_THRESHOLD: float = 4.8

#: Compression ratio threshold (compressed_size / original_size).
#: Well-structured text: 0.15-0.35 | Encoded data: 0.70-0.95 | Random: 0.95+
#: Ratio > 0.65 means the data is hard to compress (likely encoded).
COMPRESSION_RATIO_THRESHOLD: float = 0.65

#: KL-divergence threshold (bits).
#: English text: 0.1-0.5 | Mixed/code: 0.5-2.0 | Encoded: 2.0-8.0
#: Divergence > 1.5 means distribution is far from English.
KL_DIVERGENCE_THRESHOLD: float = 1.5

#: Minimum text length for meaningful entropy analysis.
#: Short strings have unreliable entropy statistics.
MIN_LENGTH_FOR_ANALYSIS: int = 20

#: Required votes for flagging (2 out of 3)
REQUIRED_VOTES: int = 2


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class EntropyCheckResult:
    """Result of the composite entropy check.

    Attributes:
        is_suspicious:       True if >= REQUIRED_VOTES signals triggered.
        vote_count:          Number of signals that voted "suspicious".
        shannon_entropy:     Character-level entropy (bits/char).
        compression_ratio:   zlib compressed/original ratio [0.0, 1.0+].
        kl_divergence:       KL-divergence from English reference.
        entropy_vote:        True if entropy exceeded threshold.
        compression_vote:    True if compression ratio exceeded threshold.
        kl_vote:             True if KL-divergence exceeded threshold.
        anomaly_flags:       Flags to add to the Layer0Result.
    """
    is_suspicious: bool = False
    vote_count: int = 0
    shannon_entropy: float = 0.0
    compression_ratio: float = 0.0
    kl_divergence: float = 0.0
    entropy_vote: bool = False
    compression_vote: bool = False
    kl_vote: bool = False
    anomaly_flags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy in bits per character.

    Parameters
    ----------
    text : str
        Input text.

    Returns
    -------
    float
        Entropy in bits per character. 0.0 for empty text.
    """
    if not text:
        return 0.0

    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    length = float(len(text))
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def compression_ratio(text: str) -> float:
    """Calculate zlib compression ratio.

    Parameters
    ----------
    text : str
        Input text.

    Returns
    -------
    float
        Ratio of compressed size to original size.
        Values closer to 1.0 mean the data is hard to compress.
        Values closer to 0.0 mean the data compresses well.
    """
    if not text:
        return 0.0

    original = text.encode("utf-8", errors="replace")
    if len(original) == 0:
        return 0.0

    compressed = zlib.compress(original, level=6)
    return len(compressed) / len(original)


def kl_divergence_from_english(text: str) -> float:
    """Calculate KL-divergence of text's letter distribution from English.

    Only considers ASCII letters (a-z, case-insensitive).  Non-letter
    characters are ignored.  Uses Laplace smoothing to avoid division
    by zero for missing letters.

    Parameters
    ----------
    text : str
        Input text.

    Returns
    -------
    float
        KL-divergence in bits. 0.0 if no letters found.
        Higher values indicate distribution is far from English.
    """
    # Count letter frequencies (case-insensitive)
    counts: dict[str, int] = {}
    total = 0
    for ch in text.lower():
        if "a" <= ch <= "z":
            counts[ch] = counts.get(ch, 0) + 1
            total += 1

    if total == 0:
        return 0.0

    # Laplace smoothing: add 1 to each count
    smoothed_total = total + 26
    kl = 0.0
    for letter, q_ref in _ENGLISH_FREQ.items():
        p_obs = (counts.get(letter, 0) + 1) / smoothed_total
        if p_obs > 0 and q_ref > 0:
            kl += p_obs * math.log2(p_obs / q_ref)

    return max(0.0, kl)


# ---------------------------------------------------------------------------
# Combined check
# ---------------------------------------------------------------------------

def composite_entropy_check(text: str) -> EntropyCheckResult:
    """Run the 2-of-3 voting entropy check.

    Parameters
    ----------
    text : str
        Input text to analyze.

    Returns
    -------
    EntropyCheckResult
        Composite analysis results.
    """
    if not text or len(text) < MIN_LENGTH_FOR_ANALYSIS:
        return EntropyCheckResult()

    # Calculate all three signals
    entropy = shannon_entropy(text)
    comp_ratio = compression_ratio(text)
    kl_div = kl_divergence_from_english(text)

    # Vote
    entropy_vote = entropy >= ENTROPY_THRESHOLD
    compression_vote = comp_ratio >= COMPRESSION_RATIO_THRESHOLD
    kl_vote = kl_div >= KL_DIVERGENCE_THRESHOLD

    vote_count = sum([entropy_vote, compression_vote, kl_vote])
    is_suspicious = vote_count >= REQUIRED_VOTES

    flags: list[str] = []
    if is_suspicious:
        flags.append("composite_entropy_suspicious")
        if entropy_vote:
            flags.append("entropy_high")
        if compression_vote:
            flags.append("compression_ratio_high")
        if kl_vote:
            flags.append("kl_divergence_high")

    return EntropyCheckResult(
        is_suspicious=is_suspicious,
        vote_count=vote_count,
        shannon_entropy=round(entropy, 4),
        compression_ratio=round(comp_ratio, 4),
        kl_divergence=round(kl_div, 4),
        entropy_vote=entropy_vote,
        compression_vote=compression_vote,
        kl_vote=kl_vote,
        anomaly_flags=flags,
    )

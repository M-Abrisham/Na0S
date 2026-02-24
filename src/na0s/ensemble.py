"""Ensemble combiner for Layer 4 (TF-IDF) and Layer 5 (Embeddings).

Combines calibrated probabilities from both models via weighted average.
TF-IDF catches keyword patterns; embeddings catch semantic similarity.
Together they produce a more robust detection signal than either alone.

Design decisions:
  - Weighted average of P(malicious) from both models (simplest, most robust).
  - Graceful degradation: if embedding model is unavailable, falls back to
    TF-IDF only (no error, just a log message).
  - Configurable weights via parameters or NA0S_ENSEMBLE_TFIDF_WEIGHT env var.
  - Returns a ScanResult for compatibility with the rest of the pipeline.
"""

import logging
import os

from .scan_result import ScanResult
from .predict import scan as tfidf_scan

# Layer 5: Embedding-based classifier -- optional import
try:
    from .predict_embedding import (
        classify_prompt_embedding,
        load_models as _load_embedding_models,
    )
    _HAS_EMBEDDING = True
except ImportError:
    _HAS_EMBEDDING = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default weights (configurable via env var or parameter)
# ---------------------------------------------------------------------------
_DEFAULT_TFIDF_WEIGHT = 0.5
_DEFAULT_EMBEDDING_WEIGHT = 0.5

# Read from environment if set.
# NA0S_ENSEMBLE_TFIDF_WEIGHT sets the TF-IDF weight; embedding weight
# is the complement (1.0 - tfidf_weight).
_ENV_TFIDF_WEIGHT = os.environ.get("NA0S_ENSEMBLE_TFIDF_WEIGHT")
if _ENV_TFIDF_WEIGHT is not None:
    try:
        _DEFAULT_TFIDF_WEIGHT = float(_ENV_TFIDF_WEIGHT)
        _DEFAULT_EMBEDDING_WEIGHT = 1.0 - _DEFAULT_TFIDF_WEIGHT
    except (ValueError, TypeError):
        pass  # Keep defaults if env var is invalid

# Decision threshold -- same as predict.py for consistency
_DECISION_THRESHOLD = 0.55


def ensemble_scan(
    text,
    tfidf_weight=None,
    embedding_weight=None,
    vectorizer=None,
    model=None,
    embedding_model=None,
    embedding_classifier=None,
):
    """Combine Layer 4 (TF-IDF) and Layer 5 (Embeddings) into a single scan.

    Parameters
    ----------
    text : str
        The prompt text to scan.
    tfidf_weight : float or None
        Weight for the TF-IDF model's P(malicious).  Defaults to 0.5 or
        the value from ``NA0S_ENSEMBLE_TFIDF_WEIGHT`` env var.
    embedding_weight : float or None
        Weight for the embedding model's P(malicious).  Defaults to
        ``1.0 - tfidf_weight``.
    vectorizer, model : sklearn objects or None
        Pre-loaded TF-IDF vectorizer and classifier.  Loaded lazily if None.
    embedding_model : SentenceTransformer or None
        Pre-loaded embedding model.  Loaded lazily if None.
    embedding_classifier : sklearn model or None
        Pre-loaded embedding classifier.  Loaded lazily if None.

    Returns
    -------
    ScanResult
        Unified scan result with combined score from both models.
    """
    # Resolve weights
    w_tfidf = tfidf_weight if tfidf_weight is not None else _DEFAULT_TFIDF_WEIGHT
    w_embed = embedding_weight if embedding_weight is not None else _DEFAULT_EMBEDDING_WEIGHT

    # If only one weight was explicitly passed, compute the other as complement
    if tfidf_weight is not None and embedding_weight is None:
        w_embed = 1.0 - w_tfidf
    elif embedding_weight is not None and tfidf_weight is None:
        w_tfidf = 1.0 - w_embed

    # Clamp weights to [0, 1] and re-normalize
    w_tfidf = max(0.0, min(1.0, w_tfidf))
    w_embed = max(0.0, min(1.0, w_embed))
    total_weight = w_tfidf + w_embed
    if total_weight > 0:
        w_tfidf /= total_weight
        w_embed /= total_weight
    else:
        w_tfidf = 0.5
        w_embed = 0.5

    # ------------------------------------------------------------------
    # Layer 4: TF-IDF scan (always available)
    # ------------------------------------------------------------------
    tfidf_result = tfidf_scan(text, vectorizer=vectorizer, model=model)

    # If Layer 0 blocked the input, return immediately
    if tfidf_result.rejected:
        return tfidf_result

    # ------------------------------------------------------------------
    # Layer 5: Embedding scan (optional, graceful degradation)
    # ------------------------------------------------------------------
    embedding_available = False
    emb_p_malicious = 0.0
    emb_hits = []

    if _HAS_EMBEDDING:
        try:
            if embedding_model is None or embedding_classifier is None:
                embedding_model, embedding_classifier = _load_embedding_models()

            emb_label, emb_confidence, emb_hits_raw, _emb_l0 = classify_prompt_embedding(
                text,
                embedding_model=embedding_model,
                classifier=embedding_classifier,
            )

            emb_p_malicious = emb_confidence
            emb_hits = emb_hits_raw if emb_hits_raw else []
            embedding_available = True
            logger.debug(
                "Ensemble: embedding P(malicious)=%.4f, label=%s",
                emb_p_malicious, emb_label,
            )
        except Exception as exc:
            logger.warning(
                "Ensemble: embedding model unavailable, falling back to "
                "TF-IDF only: %s", exc,
            )

    # ------------------------------------------------------------------
    # Combine scores
    # ------------------------------------------------------------------
    tfidf_risk = tfidf_result.risk_score

    if embedding_available:
        combined_risk = (w_tfidf * tfidf_risk) + (w_embed * emb_p_malicious)
        contributor_tag = "ensemble:tfidf+embedding"
        logger.info(
            "Ensemble: tfidf=%.4f (w=%.2f) + embedding=%.4f (w=%.2f) = %.4f",
            tfidf_risk, w_tfidf, emb_p_malicious, w_embed, combined_risk,
        )
    else:
        combined_risk = tfidf_risk
        contributor_tag = "ensemble:tfidf_only"
        logger.info(
            "Ensemble: tfidf_only=%.4f (embedding unavailable)", tfidf_risk,
        )

    combined_risk = round(max(0.0, min(1.0, combined_risk)), 4)

    # ------------------------------------------------------------------
    # Decision: apply threshold
    # ------------------------------------------------------------------
    is_malicious = combined_risk >= _DECISION_THRESHOLD

    # Merge rule_hits from both models
    merged_hits = list(tfidf_result.rule_hits)
    for h in emb_hits:
        if h not in merged_hits:
            merged_hits.append(h)
    merged_hits.append(contributor_tag)

    # ------------------------------------------------------------------
    # Build ScanResult
    # ------------------------------------------------------------------
    return ScanResult(
        sanitized_text=tfidf_result.sanitized_text,
        is_malicious=is_malicious,
        risk_score=combined_risk,
        label="malicious" if is_malicious else "safe",
        technique_tags=list(tfidf_result.technique_tags),
        rule_hits=merged_hits,
        ml_confidence=combined_risk,
        ml_label=tfidf_result.ml_label,
        anomaly_flags=list(tfidf_result.anomaly_flags),
    )

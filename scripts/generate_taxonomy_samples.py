"""
Generate training samples for all taxonomy categories.

Each category lives in its own file under scripts/taxonomy/.
This orchestrator imports them, deduplicates, computes per-sample
metadata, and writes the CSV.

Output: data/raw/taxonomy_samples.csv
Schema: text, label, technique_id, category,
        length_chars, length_bytes, token_count,
        compression_ratio, has_reset_claim, has_override_language
"""

import csv
import hashlib
import os
import random
import re
import sys
import zlib

# Ensure scripts/ is on the path so `taxonomy` is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from taxonomy import ALL_PROBES

# D and I have numbered sub-categories that ARE the category (D1, I1).
# All others use the single letter (E, A, O, T, R, P, M, S, C).
_MULTI_SUB_LETTERS = {"D", "I"}

# ── Metadata helpers ────────────────────────────────────────────────
# Computed centrally so generators stay simple (return (text, tech_id)).

_encoder = None  # lazy-loaded tiktoken encoder


def _get_encoder():
    global _encoder
    if _encoder is None:
        import tiktoken
        _encoder = tiktoken.get_encoding("cl100k_base")
    return _encoder


_RESET_RE = re.compile(
    r"(?i)"
    r"(new session|context (clear|flush|rotat|refresh|boundary|reset|displace|evict))"
    r"|session boundary|context.{0,20}(expired|ended|dropped|full|rotated)"
    r"|system reset|context limit reached|earliest messages"
    r"|system prompt.{0,20}(evict|displace|gone|expired|scroll)"
)

_OVERRIDE_RE = re.compile(
    r"(?i)"
    r"(ignore|disregard|forget|bypass|override|disable).{0,30}"
    r"(instruct|restrict|safe|filter|guideline|rule|previous|prior)"
    r"|no.{0,10}(restrict|safe|filter|guideline)"
    r"|unrestrict|comply with (all|every)"
)


def _compute_metadata(text):
    """Return dict of computed metadata fields for a single sample."""
    text_bytes = text.encode("utf-8")
    length_chars = len(text)
    length_bytes = len(text_bytes)

    enc = _get_encoder()
    token_count = len(enc.encode(text))

    # compression_ratio: lower = more repetitive (0.0-1.0 range)
    if length_bytes > 0:
        compressed = zlib.compress(text_bytes, 6)
        compression_ratio = round(len(compressed) / length_bytes, 4)
    else:
        compression_ratio = 1.0

    has_reset = 1 if _RESET_RE.search(text) else 0
    has_override = 1 if _OVERRIDE_RE.search(text) else 0

    return {
        "length_chars": length_chars,
        "length_bytes": length_bytes,
        "token_count": token_count,
        "compression_ratio": compression_ratio,
        "has_reset_claim": has_reset,
        "has_override_language": has_override,
    }


# ── CSV schema ──────────────────────────────────────────────────────

_FIELDNAMES = [
    "text", "label", "technique_id", "category",
    "difficulty", "difficulty_score", "evasion_type",
    "length_chars", "length_bytes", "token_count",
    "compression_ratio", "has_reset_claim", "has_override_language",
]


_BENIGN_SUFFIX = "_benign"


def _technique_to_category(technique_id):
    # Strip benign suffix before parsing: "D1.1_benign" -> "D1.1" -> "D1"
    clean = technique_id.removesuffix(_BENIGN_SUFFIX)
    sub = clean.split(".")[0]  # e.g. "D1", "O1", "T2"
    letter = sub[0]
    return sub if letter in _MULTI_SUB_LETTERS else letter


def main(seed=42):
    all_samples = []

    print("Generating taxonomy training samples (seed={})...".format(seed))
    print("=" * 60)

    for i, ProbeClass in enumerate(ALL_PROBES):
        probe = ProbeClass()
        cat_name = "{} \u2014 {}".format(probe.category_id, probe.name)
        # Each generator gets its own deterministic seed so adding/removing
        # a category doesn't shift output for all subsequent ones.
        random.seed(seed + i)
        samples = probe.generate()
        # Deduplicate within category (hash-based to avoid storing large strings)
        seen = set()
        unique = []
        for item in samples:
            text, tech_id = item[0], item[1]
            meta = item[2] if len(item) == 3 else {}
            h = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if h not in seen:
                seen.add(h)
                unique.append((text, tech_id, meta))
        all_samples.extend(unique)
        print("  {:<40s} {:>4d} samples".format(cat_name, len(unique)))

    print("=" * 60)
    print("Total: {} samples".format(len(all_samples)))

    # Write CSV with metadata
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    out_path = os.path.join(project_root, "data", "raw", "taxonomy_samples.csv")

    print("\nComputing per-sample metadata...")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        writer.writeheader()
        for text, technique_id, meta in all_samples:
            is_benign = technique_id.endswith(_BENIGN_SUFFIX)
            row = {
                "text": text,
                "label": 0 if is_benign else 1,
                "technique_id": technique_id,
                "category": _technique_to_category(technique_id),
                "difficulty": meta.get("difficulty", ""),
                "difficulty_score": meta.get("difficulty_score", ""),
                "evasion_type": meta.get("evasion_type", ""),
            }
            row.update(_compute_metadata(text))
            writer.writerow(row)

    print("Written to: {}".format(out_path))
    return out_path


if __name__ == "__main__":
    main()

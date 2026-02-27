#!/usr/bin/env python3
"""Download and convert benchmark datasets to standard JSONL format.

Downloads three datasets and converts them to the JSONL schema expected by
``scripts/benchmark.py``::

    {"text": "...", "label": 0|1, "source": "...", "category": "..."}

Datasets
--------
1. deepset/prompt-injections  -- labelled prompt-injection dataset (HuggingFace)
2. tatsu-lab/alpaca            -- benign instruction-following (GitHub JSON)
3. databricks/databricks-dolly-15k -- benign instruction-following (HuggingFace)

Usage
-----
    python scripts/download_datasets.py
    python scripts/download_datasets.py --output-dir /tmp/bench --force
"""

import argparse
import json
import os
import random
import sys

try:
    import requests
except ImportError:
    requests = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEEPSET_PARQUET_URL = (
    "https://huggingface.co/api/datasets/deepset/prompt-injections/parquet/default/train"
)
ALPACA_JSON_URL = (
    "https://raw.githubusercontent.com/tatsu-lab/stanford_alpaca/main/alpaca_data.json"
)
DOLLY_PARQUET_URL = (
    "https://huggingface.co/api/datasets/databricks/databricks-dolly-15k/parquet/default/train"
)

RANDOM_SEED = 42
DEFAULT_SAMPLE_SIZE = 2000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_requests():
    """Raise a clear error if the ``requests`` library is not installed."""
    if requests is None:
        print(
            "ERROR: the 'requests' package is required. "
            "Install it with:  pip install requests",
            file=sys.stderr,
        )
        sys.exit(1)


def _http_get_json(url):
    """GET *url* and return the parsed JSON body."""
    _ensure_requests()
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _http_get_bytes(url):
    """GET *url* and return raw bytes."""
    _ensure_requests()
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    return resp.content


def _read_parquet_bytes(raw_bytes):
    """Read Parquet bytes into a list of dicts.

    Tries ``pyarrow`` first, then falls back to ``pandas``.
    """
    import io

    try:
        import pyarrow.parquet as pq

        table = pq.read_table(io.BytesIO(raw_bytes))
        return table.to_pylist()
    except ImportError:
        pass

    try:
        import pandas as pd

        df = pd.read_parquet(io.BytesIO(raw_bytes))
        return df.to_dict(orient="records")
    except ImportError:
        pass

    raise ImportError(
        "Reading Parquet files requires either 'pyarrow' or 'pandas' "
        "(with a Parquet engine).  Install one of them:\n"
        "  pip install pyarrow   # or\n"
        "  pip install pandas pyarrow"
    )


def _write_jsonl(records, path):
    """Write a list of dicts as JSONL to *path*."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Dataset conversion functions
# ---------------------------------------------------------------------------

def convert_deepset(output_path, force=False):
    """Download and convert the deepset/prompt-injections dataset.

    The HuggingFace API returns a list of Parquet file URLs.  We download
    each shard, concatenate, and convert to JSONL.

    Returns the number of records written.
    """
    if os.path.exists(output_path) and not force:
        print(f"  [skip] {output_path} already exists (use --force to re-download)")
        return 0

    print("  Fetching parquet URLs from HuggingFace API ...")
    parquet_urls = _http_get_json(DEEPSET_PARQUET_URL)

    if not isinstance(parquet_urls, list) or len(parquet_urls) == 0:
        raise RuntimeError(
            f"Unexpected API response from {DEEPSET_PARQUET_URL}: {parquet_urls!r}"
        )

    all_rows = []
    for i, purl in enumerate(parquet_urls):
        print(f"  Downloading shard {i + 1}/{len(parquet_urls)} ...")
        raw = _http_get_bytes(purl)
        all_rows.extend(_read_parquet_bytes(raw))

    records = []
    for row in all_rows:
        text = row.get("text") or row.get("prompt") or ""
        text = str(text).strip()
        if not text:
            continue
        label = int(row.get("label", 0))
        records.append({
            "text": text,
            "label": label,
            "source": "deepset",
            "category": "malicious" if label == 1 else "benign",
        })

    _write_jsonl(records, output_path)
    print(f"  Wrote {len(records)} records to {output_path}")
    return len(records)


def convert_alpaca(output_path, force=False, sample_size=DEFAULT_SAMPLE_SIZE):
    """Download and convert the tatsu-lab/alpaca dataset.

    All samples are benign (label=0).  We sample *sample_size* random entries
    for a manageable benchmark size.

    Returns the number of records written.
    """
    if os.path.exists(output_path) and not force:
        print(f"  [skip] {output_path} already exists (use --force to re-download)")
        return 0

    print(f"  Downloading alpaca_data.json from GitHub ...")
    data = _http_get_json(ALPACA_JSON_URL)

    if not isinstance(data, list):
        raise RuntimeError(
            f"Expected a JSON array from {ALPACA_JSON_URL}, got {type(data).__name__}"
        )

    # Build text from instruction (+ optional input)
    entries = []
    for item in data:
        instruction = str(item.get("instruction", "")).strip()
        inp = str(item.get("input", "")).strip()
        if not instruction:
            continue
        text = f"{instruction}\n{inp}".strip() if inp else instruction
        entries.append(text)

    # Reproducible random sample
    rng = random.Random(RANDOM_SEED)
    if len(entries) > sample_size:
        entries = rng.sample(entries, sample_size)

    records = [
        {"text": t, "label": 0, "source": "alpaca", "category": "instructional"}
        for t in entries
    ]

    _write_jsonl(records, output_path)
    print(f"  Wrote {len(records)} records to {output_path}")
    return len(records)


def convert_dolly(output_path, force=False, sample_size=DEFAULT_SAMPLE_SIZE):
    """Download and convert the databricks/databricks-dolly-15k dataset.

    All samples are benign (label=0).  We sample *sample_size* random entries.

    Returns the number of records written.
    """
    if os.path.exists(output_path) and not force:
        print(f"  [skip] {output_path} already exists (use --force to re-download)")
        return 0

    print("  Fetching parquet URLs from HuggingFace API ...")
    parquet_urls = _http_get_json(DOLLY_PARQUET_URL)

    if not isinstance(parquet_urls, list) or len(parquet_urls) == 0:
        raise RuntimeError(
            f"Unexpected API response from {DOLLY_PARQUET_URL}: {parquet_urls!r}"
        )

    all_rows = []
    for i, purl in enumerate(parquet_urls):
        print(f"  Downloading shard {i + 1}/{len(parquet_urls)} ...")
        raw = _http_get_bytes(purl)
        all_rows.extend(_read_parquet_bytes(raw))

    # Build text from instruction (+ optional context)
    entries = []
    for row in all_rows:
        instruction = str(row.get("instruction", "")).strip()
        context = str(row.get("context", "")).strip()
        if not instruction:
            continue
        text = f"{instruction}\n{context}".strip() if context else instruction
        entries.append(text)

    # Reproducible random sample
    rng = random.Random(RANDOM_SEED)
    if len(entries) > sample_size:
        entries = rng.sample(entries, sample_size)

    records = [
        {"text": t, "label": 0, "source": "dolly", "category": "instructional"}
        for t in entries
    ]

    _write_jsonl(records, output_path)
    print(f"  Wrote {len(records)} records to {output_path}")
    return len(records)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        description="Download and convert benchmark datasets to JSONL format.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/benchmark",
        help="Directory for output JSONL files (default: data/benchmark/).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if output files already exist.",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    output_dir = args.output_dir

    datasets = [
        ("deepset/prompt-injections", convert_deepset,
         os.path.join(output_dir, "deepset_pi.jsonl")),
        ("tatsu-lab/alpaca", convert_alpaca,
         os.path.join(output_dir, "benign_alpaca.jsonl")),
        ("databricks/dolly-15k", convert_dolly,
         os.path.join(output_dir, "benign_dolly.jsonl")),
    ]

    total = 0
    errors = 0

    for name, converter, path in datasets:
        print(f"\n[{name}]")
        try:
            n = converter(path, force=args.force)
            total += n
        except Exception as exc:
            print(f"  ERROR: {exc}", file=sys.stderr)
            errors += 1

    print(f"\nDone. {total} total records written, {errors} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

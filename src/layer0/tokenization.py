import hashlib
import json
import os
import re
import time

import tiktoken

_ENCODER = tiktoken.get_encoding("cl100k_base")

# --- Ratio thresholds ---
GLOBAL_RATIO_THRESHOLD = 0.50
WINDOW_SIZE = 50
WINDOW_RATIO_THRESHOLD = 0.70

# Strip everything except lowercase alphanumeric + spaces for normalized hash
_NORMALIZE_RE = re.compile(r"[^a-z0-9 ]")


def _compute_fingerprint(text):
    """Build a multi-layer structural fingerprint.

    Produces four hashes:
        content_hash:    SHA-256 of exact text (exact match)
        normalized_hash: SHA-256 of lowercased, punctuation-stripped text
                         (catches case/whitespace/punctuation mutations)
        token_hash:      SHA-256 of the BPE token-id sequence
                         (catches identical token patterns)
    Plus numeric features: token_count, char_count, ratio.
    """
    tokens = _ENCODER.encode(text)
    token_bytes = ",".join(str(t) for t in tokens).encode("utf-8")

    # Normalized form: lowercase, strip punctuation, collapse whitespace
    norm = _NORMALIZE_RE.sub("", text.lower())
    norm = " ".join(norm.split())

    return {
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "normalized_hash": hashlib.sha256(norm.encode("utf-8")).hexdigest(),
        "token_hash": hashlib.sha256(token_bytes).hexdigest(),
        "token_count": len(tokens),
        "char_count": len(text),
        "ratio": round(len(tokens) / max(len(text), 1), 4),
    }


class FingerprintStore:
    """Persistent store of known-malicious input fingerprints.

    Stores three hash indices for different matching strategies:
        content_hashes    — exact text match
        normalized_hashes — case/punctuation-insensitive match
        token_hashes      — BPE token-sequence match

    Each entry tracks hit_count and last_seen for monitoring.
    """

    _DEFAULT_PATH = os.path.join(
        os.path.dirname(__file__), "..", "..", "data", "fingerprints.json"
    )

    def __init__(self, store_path=None):
        self._path = os.path.normpath(
            store_path or os.getenv("L0_FINGERPRINT_STORE", self._DEFAULT_PATH)
        )
        self._store = self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return {
                "content_hashes": {},
                "normalized_hashes": {},
                "token_hashes": {},
            }
        with open(self._path, "r") as f:
            data = json.load(f)
        # Migrate older stores that lack normalized_hashes
        if "normalized_hashes" not in data:
            data["normalized_hashes"] = {}
        return data

    def _save(self):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._store, f, indent=2)

    def register(self, text, label="malicious"):
        """Add a confirmed-malicious input to the store.

        Stores all three hashes so future lookups can match by
        exact text, normalized form, or token sequence.
        Returns the fingerprint dict.
        """
        fp = _compute_fingerprint(text)
        now = time.time()
        entry = {
            "label": label,
            "ratio": fp["ratio"],
            "preview": text[:80],
            "hit_count": 0,
            "first_seen": now,
            "last_seen": now,
        }

        for key in ("content_hashes", "normalized_hashes", "token_hashes"):
            hash_field = key.replace("_hashes", "_hash")
            hash_val = fp[hash_field]
            if hash_val in self._store[key]:
                # Already registered — don't reset counters
                continue
            self._store[key][hash_val] = dict(entry)

        self._save()
        return fp

    def check(self, fingerprint):
        """Look up a fingerprint against all three indices.

        Returns a list of match flags. Increments hit_count and
        updates last_seen on every match.
        """
        flags = []
        now = time.time()
        hit = False

        checks = [
            ("content_hash", "content_hashes", "known_malicious_exact"),
            ("normalized_hash", "normalized_hashes", "known_malicious_normalized"),
            ("token_hash", "token_hashes", "known_malicious_token_pattern"),
        ]

        for hash_field, store_key, flag_name in checks:
            hash_val = fingerprint.get(hash_field, "")
            if hash_val in self._store.get(store_key, {}):
                flags.append(flag_name)
                self._store[store_key][hash_val]["hit_count"] = (
                    self._store[store_key][hash_val].get("hit_count", 0) + 1
                )
                self._store[store_key][hash_val]["last_seen"] = now
                hit = True

        if hit:
            self._save()

        return flags

    def stats(self):
        """Return summary stats for monitoring."""
        return {
            "exact_entries": len(self._store["content_hashes"]),
            "normalized_entries": len(self._store["normalized_hashes"]),
            "token_entries": len(self._store["token_hashes"]),
            "total_hits": sum(
                e.get("hit_count", 0)
                for section in self._store.values()
                for e in section.values()
            ),
        }


# --- Module-level instance (used by sanitizer) ---
_default_store = None


def _get_default_store():
    global _default_store
    if _default_store is None:
        _default_store = FingerprintStore()
    return _default_store


def register_malicious(text, label="malicious"):
    """Module-level convenience — registers into the default store."""
    return _get_default_store().register(text, label)


# --- Main detection entry point ---

def check_tokenization_anomaly(text):
    """Fingerprint the input and check for anomalies.

    Four checks:
        1. Known-malicious store lookup (exact + normalized + token)
        2. Global token:char ratio spike
        3. Sliding window for localized adversarial suffixes

    Returns (anomaly_flags, token_char_ratio, fingerprint_dict).
    """
    flags = []

    if len(text) < 10:
        return flags, 0.0, {}

    fp = _compute_fingerprint(text)
    store = _get_default_store()

    # Check 1: known-malicious store lookup
    store_flags = store.check(fp)
    flags.extend(store_flags)

    # Check 2: global ratio
    if fp["ratio"] >= GLOBAL_RATIO_THRESHOLD:
        flags.append("tokenization_spike")

    # Check 3: sliding window for localized anomalies
    char_count = fp["char_count"]
    if char_count > WINDOW_SIZE:
        for start in range(0, char_count - WINDOW_SIZE + 1, WINDOW_SIZE):
            window = text[start : start + WINDOW_SIZE]
            w_tokens = len(_ENCODER.encode(window))
            w_ratio = w_tokens / len(window)
            if w_ratio >= WINDOW_RATIO_THRESHOLD:
                flags.append("tokenization_spike_local")
                break

    return flags, fp["ratio"], fp

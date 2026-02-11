"""Shared helpers for taxonomy sample generators."""

import itertools
import random


def expand(templates, technique_id, subs=None, limit=None):
    """Generate all combos of templates x subs, shuffle, optionally cap."""
    results = []
    if subs is None:
        for t in templates:
            results.append((t, technique_id))
    else:
        keys = list(subs.keys())
        combos = list(itertools.product(*(subs[k] for k in keys)))
        random.shuffle(combos)
        for t in templates:
            for combo in combos:
                mapping = dict(zip(keys, combo))
                try:
                    results.append((t.format(**mapping), technique_id))
                except (KeyError, IndexError):
                    continue
    random.shuffle(results)
    if limit:
        results = results[:limit]
    return results

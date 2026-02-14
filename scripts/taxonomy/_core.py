"""Shared helpers for taxonomy sample generators."""

import logging
import random
import string

logger = logging.getLogger(__name__)

_DEFAULT_SEED = 42
_FORMATTER = string.Formatter()


def _validate_templates(templates, subs_keys):
    """Raise KeyError if any template placeholder is missing from subs."""
    for i, t in enumerate(templates):
        for _, field_name, _, _ in _FORMATTER.parse(t):
            if field_name is None:
                continue
            # Handle dotted/indexed access like {verb.upper} or {items[0]}
            key = field_name.split(".")[0].split("[")[0]
            if key and key not in subs_keys:
                raise KeyError(
                    "Template [{}] has placeholder {{{!s}}} but subs "
                    "only has keys: {}".format(i, field_name, subs_keys)
                )


def _index_to_combo(index, lengths):
    """Convert a flat index to substitution indices via mixed-radix decomposition.

    E.g. with lengths [3, 4, 2], index 17 → (2, 0, 1):
      17 % 2 = 1, 17 // 2 = 8
       8 % 4 = 0,  8 // 4 = 2
       2 % 3 = 2
    """
    indices = []
    for length in reversed(lengths):
        indices.append(index % length)
        index //= length
    return tuple(reversed(indices))


def expand(templates, technique_id, subs=None, limit=None, seed=_DEFAULT_SEED,
           per_template_limit=None, metadata=None):
    """Generate all combos of templates x subs, shuffle, optionally cap.

    When limit is set and the full Cartesian product is larger, samples
    random indices directly instead of materializing the entire product.
    This keeps memory at O(limit) regardless of subs cardinality.

    Args:
        templates: list of format-string templates.
        technique_id: technique ID to pair with each generated sample.
        subs: optional dict {placeholder: [values]} for template expansion.
        limit: max samples to return (None = all).
        seed: RNG seed for deterministic output.  Default 42 ensures
              reproducible runs across regression tests and model
              comparisons.  Pass None for true randomness.
        per_template_limit: max combos per template.  Prevents high-
              cardinality subs from producing disproportionately many
              samples for one technique — critical for balanced
              fine-tuning datasets.
        metadata: optional dict of per-sample metadata (e.g.
              {"difficulty": "basic"}).  When provided, returns 3-tuples
              (text, technique_id, metadata) instead of 2-tuples.

    Raises:
        KeyError: if a template placeholder is not present in subs.
    """
    rng = random.Random(seed)
    results = []
    _m = metadata  # short alias for tuple construction

    def _item(text):
        return (text, technique_id, _m) if _m is not None else (text, technique_id)

    if subs is None:
        for t in templates:
            results.append(_item(t))
    else:
        keys = set(subs.keys())
        _validate_templates(templates, keys)
        key_list = sorted(keys)
        lengths = [len(subs[k]) for k in key_list]
        total_combos = 1
        for length in lengths:
            total_combos *= length

        # Cap combos per template for dataset balance
        usable_combos = total_combos
        combo_pool = None
        if per_template_limit is not None and per_template_limit < total_combos:
            usable_combos = per_template_limit
            combo_pool = rng.sample(range(total_combos), usable_combos)

        effective_total = usable_combos * len(templates)

        if limit is not None and limit < effective_total:
            # Lazy path — sample random indices, convert to combos on the fly
            indices = rng.sample(range(effective_total), limit)
            for idx in indices:
                t_idx = idx // usable_combos
                c_pos = idx % usable_combos
                c_idx = combo_pool[c_pos] if combo_pool is not None else c_pos
                combo_indices = _index_to_combo(c_idx, lengths)
                mapping = {k: subs[k][ci] for k, ci in zip(key_list, combo_indices)}
                results.append(_item(templates[t_idx].format(**mapping)))
        else:
            # Materialize from the (possibly capped) combo pool
            pool = combo_pool if combo_pool is not None else range(total_combos)
            for t in templates:
                for c_idx in pool:
                    combo_indices = _index_to_combo(c_idx, lengths)
                    mapping = {k: subs[k][ci] for k, ci in zip(key_list, combo_indices)}
                    results.append(_item(t.format(**mapping)))
    rng.shuffle(results)
    if limit is not None:
        results = results[:limit]
    logger.debug(
        "expand(%s): %d templates × %s combos → %d samples",
        technique_id,
        len(templates),
        total_combos if subs else "no subs",
        len(results),
    )
    return results

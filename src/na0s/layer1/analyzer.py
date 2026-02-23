"""Layer 1 analyzer — orchestrator for regex-based rule matching.

Public API:
  rule_score(text)          → list[str]     (backward-compatible names)
  rule_score_detailed(text) → list[RuleHit] (enriched with severity + technique_ids)

Pre-processing pipeline:
  1. Fold Unicode angle bracket homoglyphs to ASCII
  2. Strip combining marks (Zalgo defense)
  3. Decode plus-signs as spaces (URL-encoded evasion)

Single-pass evaluation with context-aware suppression and paranoia filtering.
"""

from ..layer0.safe_regex import safe_search, RegexTimeoutError
from .result import RuleHit
from .rules_registry import RULES
from .unicode_defense import _fold_angle_homoglyphs, _strip_combining_marks
from .context import _has_contextual_framing, _is_legitimate_roleplay, _CONTEXT_SUPPRESSIBLE
from . import paranoia as _paranoia_mod


def rule_score(text):
    """Return list of matched rule names (backward-compatible).

    Context-aware: suppresses override/system_prompt/roleplay rule hits
    when the text is in educational, question, quoting, code, or narrative
    framing.  ML and structural features still provide independent signals.

    Paranoia-aware: skips rules whose paranoia_level exceeds the current
    module-level _PARANOIA_LEVEL setting.

    Internally delegates to rule_score_detailed() for single-pass evaluation.
    """
    return [hit.name for hit in rule_score_detailed(text)]


def rule_score_detailed(text):
    """Return list of RuleHit objects with technique_ids and severity.

    Context-aware: same suppression logic as rule_score().
    Paranoia-aware: skips rules whose paranoia_level > _PARANOIA_LEVEL.
    Homoglyph-aware: folds Unicode angle brackets to ASCII before matching.
    Zalgo-resilient: strips combining marks (diacritics) to catch attacks
    hidden under stacked combining characters (U+0300-U+036F).
    Plus-sign-aware: decodes '+' as spaces for URL-encoded evasion.
    """
    # Fold Unicode angle bracket look-alikes BEFORE matching.
    # This prevents bypass via ＜system＞, 〈system〉, etc.
    folded = _fold_angle_homoglyphs(text)

    # Build alternate views for evasion-resilient matching.
    # Each view is tried in order; the first match wins.
    alt_views = []

    # Strip combining marks (Zalgo defense) — create a second view of
    # the text with all diacritics removed.  If it differs from the
    # folded version, we also try matching rules against it.  This
    # catches attacks like "ì́̂̃ḡ̅n̆̇ö̉r̊̋ě̍ all previous instructions"
    # where combining marks prevent regex matching.
    stripped = _strip_combining_marks(folded)
    if stripped != folded:
        alt_views.append(stripped)

    # Plus-sign space decoding — if the text contains 3+ plus signs
    # with no spaces (typical of URL-encoded form data), create a view
    # with '+' replaced by ' '.  This catches "Ignore+all+previous+
    # instructions" evasion (application/x-www-form-urlencoded format).
    if folded.count("+") >= 3 and " " not in folded:
        plus_decoded = folded.replace("+", " ")
        if plus_decoded != folded:
            alt_views.append(plus_decoded)

    has_context = _has_contextual_framing(folded)
    # Also check context on alternate views to catch framing in decoded text.
    if not has_context:
        for view in alt_views:
            if _has_contextual_framing(view):
                has_context = True
                break
    hits = []
    current_pl = _paranoia_mod.get_paranoia_level()
    for rule in RULES:
        # Paranoia filtering: skip rules above the configured threshold
        if rule.paranoia_level > current_pl:
            continue
        try:
            matched = safe_search(rule._compiled, folded, timeout_ms=100)
        except RegexTimeoutError:
            # Timeout is treated as a match -- adversarial input that
            # causes backtracking is inherently suspicious.
            matched = True
        # If no match on the primary text, try alternate views (Zalgo-
        # cleaned, plus-decoded) that may reveal the hidden attack pattern.
        if not matched:
            for view in alt_views:
                try:
                    matched = safe_search(rule._compiled, view, timeout_ms=100)
                except RegexTimeoutError:
                    matched = True
                if matched:
                    break
        if not matched:
            continue
        if has_context and rule.name in _CONTEXT_SUPPRESSIBLE:
            continue
        if rule.name == "roleplay" and _is_legitimate_roleplay(folded):
            continue
        hits.append(RuleHit(
            name=rule.name,
            technique_ids=rule.technique_ids,
            severity=rule.severity,
        ))
    return hits

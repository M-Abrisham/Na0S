"""Layer 1: Regex-based signature rule engine for prompt injection detection.

62 pre-compiled rules covering 30+ technique IDs with:
- 4-level paranoia system (PL1-PL4, env-configurable via RULES_PARANOIA_LEVEL)
- Context-aware suppression (25 suppressible rules)
- Unicode evasion defenses (homoglyph folding, Zalgo stripping)
- ReDoS-safe patterns (all validated with safe_compile)

Public API:
  rule_score(text)          → list[str]
  rule_score_detailed(text) → list[RuleHit]
"""

from .result import Rule, RuleHit, SEVERITY_WEIGHTS
from .paranoia import get_paranoia_level, set_paranoia_level
from .rules_registry import RULES, ROLE_ASSIGNMENT_PATTERN, PERSONA_OVERRIDE_PATTERNS
from .analyzer import rule_score, rule_score_detailed

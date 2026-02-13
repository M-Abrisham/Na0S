import re
from dataclasses import dataclass, field


@dataclass
class Rule:
    name: str
    pattern: str
    technique_ids: list = field(default_factory=list)
    severity: str = "medium"
    description: str = ""
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class RuleHit:
    name: str
    technique_ids: list = field(default_factory=list)
    severity: str = "medium"


RULES = [
    Rule("override",
         r"ignore (all|any|previous) (instructions|rules)",
         technique_ids=["D1.1"],
         severity="critical",
         description="Explicit instruction override attempt"),
    Rule("system_prompt",
         r"(reveal|show|print).{0,40}(system prompt|developer message)",
         technique_ids=["E1.1", "E1.2"],
         severity="high",
         description="System prompt extraction attempt"),
    Rule("roleplay",
         r"\byou are now\b|\bpretend to be\b|\bact as\b",
         technique_ids=["D2.1", "D2.2"],
         severity="medium",
         description="Persona/roleplay hijack attempt"),
    Rule("secrecy",
         r"don't tell (the user|anyone)|keep this secret",
         technique_ids=["E1.4"],
         severity="medium",
         description="Secrecy instruction injection"),
    Rule("exfiltration",
         r"\b(upload|send|exfiltrate|forward)\b.{0,60}\b(to|http|https|email)\b",
         technique_ids=["E1.1"],
         severity="high",
         description="Data exfiltration attempt"),
]


def rule_score(text):
    """Return list of matched rule names (backward-compatible)."""
    hits = []
    for rule in RULES:
        if rule._compiled.search(text):
            hits.append(rule.name)
    return hits


def rule_score_detailed(text):
    """Return list of RuleHit objects with technique_ids and severity."""
    hits = []
    for rule in RULES:
        if rule._compiled.search(text):
            hits.append(RuleHit(
                name=rule.name,
                technique_ids=rule.technique_ids,
                severity=rule.severity,
            ))
    return hits

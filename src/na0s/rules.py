import re
from dataclasses import dataclass, field

from .layer0.safe_regex import safe_search, safe_compile, RegexTimeoutError


@dataclass
class Rule:
    name: str
    pattern: str
    technique_ids: list = field(default_factory=list)
    severity: str = "medium"
    description: str = ""
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        self._compiled = safe_compile(
            self.pattern, re.IGNORECASE, check_safety=True,
        )


@dataclass
class RuleHit:
    name: str
    technique_ids: list = field(default_factory=list)
    severity: str = "medium"


# Canonical role-assignment / roleplay pattern -- single source of truth.
# Imported by cascade.py (WhitelistFilter) and structural_features.py so
# all three detection layers stay in sync.
#
# Uses \s+ for whitespace-evasion resilience and \b for word boundaries.
ROLE_ASSIGNMENT_PATTERN = (
    r"\byou\s+are\s+now\b"
    r"|\bpretend\s+to\s+be\b"
    # FIX: "act as" tightened — require article/possessive + word, or
    # capitalized name (DAN, Jailbreak, etc.) to reduce FPs from
    # scientific/technical prose ("enzymes act as catalysts").
    r"|\bact\s+as\s+(?:(?:a|an|the|my|if)\s+)?\w"
    r"|\bfrom\s+now\s+on\b"
    r"|\b(?:your\s+)?new\s+role\b"
)


RULES = [
    Rule("override",
         # FIX: {0,3} bounded quantifier for multi-word adjective chains.
         # Old regex missed "ignore all previous instructions" (2 adjectives).
         # Uses {0,3} instead of * to pass safe_compile nested-quantifier check.
         r"(?:ignore|disregard|forget|bypass|skip|drop|dismiss|override"
         r"|cancel|delete|erase)\s+"
         r"(?:(?:all|any|every|the|my|your|prior|previous|earlier|above"
         r"|old|existing|initial|original|current|preceding|foregoing"
         r")\s+){0,3}"
         r"(?:instructions?|rules?|directives?|guidelines?|prompts?"
         r"|constraints?|restrictions?|commands?|orders?|directions?"
         r"|programming|training|context|policies|settings)",
         technique_ids=["D1.1"],
         severity="critical",
         description="Explicit instruction override attempt"),
    Rule("system_prompt",
         # Expanded: more verbs (display, repeat, copy, translate, list,
         # output, dump, paste) and more targets (system message, hidden
         # instructions, initial prompt, configuration, internal rules).
         r"(?:reveal|show|print|display|repeat|copy|translate|list|output"
         r"|dump|paste|rewrite|paraphrase|summarize|convert|encode"
         r"|TL;?DR)\b"
         r".{0,60}"
         r"(?:system\s+prompt|developer\s+message|hidden\s+instructions?"
         r"|initial\s+prompt|system\s+message|internal\s+(?:rules?|instructions?)"
         r"|initial\s+configuration|initial\s+instructions?"
         r"|system\s+instructions?|your\s+(?:instructions?|configuration"
         r"|rules?|prompt))",
         technique_ids=["E1.1", "E1.2"],
         severity="high",
         description="System prompt extraction attempt"),
    Rule("prompt_query",
         # "What is your system prompt?" style extraction -- question-form
         # probes that don't use imperative verbs.
         r"\b(?:what\s+(?:is|are|do)|tell\s+me|(?:can|could)\s+you\s+"
         r"(?:show|tell|give|share|reveal))\b"
         r".{0,40}"
         r"(?:your\s+(?:system\s+prompt|instructions?|rules?|configuration"
         r"|constraints?|restrictions?|directives?|guidelines?|prompt"
         r"|(?:internal|hidden)\s+\w+)"
         r"|the\s+(?:system\s+prompt|developer\s+(?:message|instructions?)"
         r"|hidden\s+(?:prompt|instructions?)))",
         technique_ids=["E1.1"],
         severity="high",
         description="Question-form prompt extraction"),
    Rule("roleplay",
         ROLE_ASSIGNMENT_PATTERN,
         technique_ids=["D2.1", "D2.2"],
         severity="high",
         description="Persona/roleplay hijack attempt"),
    Rule("secrecy",
         r"don't tell (the user|anyone)|keep this secret",
         technique_ids=["D1.2"],
         severity="medium",
         description="Secrecy instruction injection"),
    Rule("exfiltration",
         r"\b(upload|send|exfiltrate|forward)\b.{0,60}\b(to|http|https|email)\b",
         technique_ids=["E1.1"],
         severity="high",
         description="Data exfiltration attempt"),
    Rule("credential_extraction",
         # API keys, secrets, env vars, passwords, tokens
         r"(?:print|show|reveal|display|list|output|give\s+me|provide)"
         r".{0,40}"
         r"(?:(?:api|secret|access|auth)\s*(?:_|\s)?(?:keys?|tokens?)"
         r"|environment\s+variables?"
         r"|(?:OPENAI|AWS|AZURE|GCP|GITHUB|SLACK|DATABASE|DB)_\w+"
         r"|(?:passwords?|credentials?|secrets?)\b)",
         technique_ids=["P1.5", "E1.1"],
         severity="high",
         description="Credential/API key extraction attempt"),
    Rule("cross_session",
         # Previous user/session data extraction
         r"(?:previous|last|other|earlier)\s+"
         r"(?:user(?:'s)?|session(?:'s)?|conversation(?:'s)?|chat(?:'s)?)"
         r".{0,30}"
         r"(?:ask(?:ed)?|said|typed|sent|query|queries|data|message|input|request)",
         technique_ids=["P1.4"],
         severity="high",
         description="Cross-session data extraction attempt"),
    Rule("pii_extraction",
         # Direct PII extraction requests
         r"\b(?:list|show|extract|give\s+me|provide|collect)\b"
         r".{0,40}"
         r"\b(?:(?:all|every|the)\s+)?"
         r"(?:email\s+addresses|phone\s+numbers?|social\s+security"
         r"|credit\s+card|personal\s+(?:info|information|data|details)"
         r"|private\s+(?:data|information|details)"
         r"|user(?:'s)?\s+(?:data|information|details))\b",
         technique_ids=["P1.2"],
         severity="high",
         description="PII extraction request"),
    Rule("training_data_extraction",
         # Training data / memory extraction via prefix completion or repetition.
         # "verbatim" removed -- too broad; matches benign "repeat ... verbatim".
         r"(?:recite|repeat|reproduce|emit|complete)\b.{0,40}"
         r"(?:training\s+data|memorized|word\s+for\s+word)"
         r"|repeat\s+the\s+word\b.{0,20}\bforever\b",
         technique_ids=["P1.3"],
         severity="high",
         description="Training data extraction attempt"),
    Rule("harmful_request",
         # Direct requests for harmful / dangerous content
         r"\b(?:write|create|provide|generate|give\s+me|draft|compose)\b"
         r".{0,40}"
         r"(?:(?:phishing|scam|vishing|pretexting)\s+"
         r"(?:email|message|script|template)"
         r"|(?:fake\s+news|disinformation|propaganda)\s+"
         r"(?:article|campaign|content)"
         r"|(?:malware|ransomware|keylogger|backdoor|reverse\s+shell"
         r"|credential\s+stealer|exploit)\b)",
         technique_ids=["O1.1", "O1.3"],
         severity="high",
         description="Harmful content generation request"),
    Rule("authority_claim",
         # Authority impersonation to bypass safety
         r"\b(?:i\s+am|as)\s+(?:the\s+|a\s+)?"
         r"(?:(?:senior|lead|chief|head)\s+)?"
         r"(?:system\s+admin(?:istrator)?|developer|security\s+researcher"
         r"|law\s+enforcement|doctor|lawyer|(?:SOC|CISO|CTO)\b)"
         r".{0,60}"
         r"(?:(?:ignore|bypass|override|remove|disable)\s+"
         r"(?:all\s+)?(?:safety|security|restrictions?|filters?|constraints?)"
         r"|(?:reveal|show|provide|give)\s+"
         r"(?:all\s+)?(?:vulnerabilities|exploits?|secrets?|passwords?|credentials?))",
         technique_ids=["C1.5"],
         severity="critical",
         description="Authority impersonation with safety bypass"),
]

# Severity-to-weight mapping for rule hits in weighted voting.
# Canonical source -- imported by predict.py and cascade.py.
SEVERITY_WEIGHTS = {
    "critical": 0.3,
    "high": 0.2,
    "medium": 0.1,
}


# ---------------------------------------------------------------------------
# Context-awareness: suppress rule ENGINE hits when text discusses injection
# rather than performing it.  ML, structural features, obfuscation flags, and
# fingerprint store continue providing independent detection signals.
#
# Research basis:
#   - InjecGuard (arxiv 2410.22770): trigger-word bias causes over-defense
#   - CAPTURE (arxiv 2505.12368): context essential for attack vs discussion
#   - DMPI-PMHFE (arxiv 2506.06384): precision/recall tradeoff with heuristics
# ---------------------------------------------------------------------------

# Educational frame -- only strong multi-word indicators that are hard to
# weaponize as evasion prefixes.  Single words like "explain" or "describe"
# are too easy to prepend to real attacks.  Question-style educational
# phrasing is handled separately by _QUESTION_FRAME.
_EDUCATIONAL_FRAME = re.compile(
    r'(?:'
    r'\bcan\s+you\s+explain\b|\btell\s+me\s+about\b|'
    r'\bfor\s+my\s+thesis\b|\bfor\s+my\s+research\b|\bin\s+the\s+context\s+of\b|'
    r'\bwhat\s+types?\s+of\b|\bwhat\s+defenses?\b|\bhow\s+to\s+detect\b|'
    r'\bshow\s+me\s+how\s+to\b|\bteach\s+me\s+about\b|'
    r'the\s+(?:attacker|researcher|paper|study|hacker|user)\s+'
    r'(?:used|demonstrated|showed|found|typed|entered|said|sent)'
    r')',
    re.IGNORECASE,
)

# Question frame -- text STARTS with question word (not trailing "?")
# to avoid suppressing real attacks like "Ignore instructions. What was
# written above?" (Kevin Liu's Bing Chat exploit)
_QUESTION_FRAME = re.compile(
    r'^\s*(?:what|who|why|how|where|when|which|can|could|do|does|is|are|'
    r'was|were|should|would)\s+',
    re.IGNORECASE | re.MULTILINE,
)

# Quoting frame -- text cites attack examples in an academic/reporting context
_QUOTING_FRAME = re.compile(
    r'(?:'
    r'the\s+phrase\s*[:\"]|'
    r'CTF\s+writeup|red\s+team\s+report|security\s+advisory|'
    r'bug\s+bounty|pentest|penetration\s+test|'
    r'was\s+flagged\s+by|common\s+payloads?\s+include|'
    r'example\s+from\s+(?:MITRE|OWASP)|'
    r'(?:paper|study|report)\s+(?:says|mentions|describes|shows)|'
    r'user\s+reported|was\s+reported|incident\s+response'
    r')',
    re.IGNORECASE,
)

# Code frame -- \b after keyword group prevents "defines" matching "def"
_CODE_FRAME = re.compile(
    r'(?:'
    r'\b(?:payload|pattern|const|var|let|def|assert|import|class|function)\b'
    r'\s*=?\s*|'
    r'^\s*```|'
    r'\bin\s+SQL\b|'
    r'\bSQL\s+comment\b|'
    r'^\s*--\s+\w'
    r')',
    re.IGNORECASE | re.MULTILINE,
)

# Narrative frame -- creative writing context
_NARRATIVE_FRAME = re.compile(
    r'(?:'
    r'(?:write|create|compose)\s+(?:a\s+)?'
    r'(?:story|novel|poem|dialogue|screenplay|script|essay)|'
    r'in\s+my\s+(?:novel|story|book|screenplay|script)|'
    r'a\s+(?:character|sci-fi\s+story|story)\s+(?:says|said|typed|tells|begins)'
    r')',
    re.IGNORECASE,
)

# Legitimate roleplay -- "act as a translator" is safe, "act as DAN" is not
_LEGITIMATE_ROLE = re.compile(
    r'\bact\s+as\s+(?:(?:a|an|the|my)\s+)?(?:\w+\s+)?'
    r'(?:translator|interpreter|tutor|teacher|coach|guide|mentor|'
    r'editor|proofreader|assistant|helper|summarizer|formatter|'
    r'converter|calculator|advisor|consultant|'
    r'dictionary|thesaurus|encyclopedia|reference)\b',
    re.IGNORECASE,
)

# Non-persona "act as" -- scientific/technical usage where "act as" means
# "function as" rather than "roleplay as".  Suppresses FPs from prompts
# like "How does aspirin act as an anti-inflammatory?" or "Enzymes act as
# catalysts in biochemical reactions."
# Note: (?:\w+\s+)? allows one adjective between article and noun
# (e.g., "a voltage divider").  s? handles plurals ("catalysts").
_NONPERSONA_ACT_AS = re.compile(
    r'\bact\s+as\s+(?:(?:a|an|the)\s+)?(?:\w+\s+)?'
    r'(?:catalysts?|buffers?|safeguards?|barriers?|bridges?|dividers?|'
    r'filters?|gateways?|prox(?:y|ies)|intermediar(?:y|ies)|'
    r'deterrents?|inhibitors?|mediators?|moderators?|'
    r'substitutes?|replacements?|stimul(?:us|i)|receptors?|'
    r'anti[- ]?\w+|insulators?|conductors?|solvents?|reagents?|'
    r'amplifiers?|suppressors?|regulators?|stabilizers?|precursors?)\b',
    re.IGNORECASE,
)


def _has_contextual_framing(text):
    """Return True if text discusses injection rather than performing it."""
    return (bool(_EDUCATIONAL_FRAME.search(text))
            or bool(_QUESTION_FRAME.search(text))
            or bool(_QUOTING_FRAME.search(text))
            or bool(_CODE_FRAME.search(text))
            or bool(_NARRATIVE_FRAME.search(text)))


def _is_legitimate_roleplay(text):
    """Return True if 'act as' refers to a legitimate benign role or
    non-persona scientific/technical usage."""
    return (bool(_LEGITIMATE_ROLE.search(text))
            or bool(_NONPERSONA_ACT_AS.search(text)))


# Rules that can be suppressed in educational/quoting/code/narrative context.
# Only content-agnostic rules (vocabulary overlap with benign text) are
# suppressible.  Direct extraction/attack rules are NOT suppressed because
# they indicate adversarial intent regardless of framing.
_CONTEXT_SUPPRESSIBLE = frozenset({"override", "system_prompt", "roleplay"})


def rule_score(text):
    """Return list of matched rule names (backward-compatible).

    Context-aware: suppresses override/system_prompt/roleplay rule hits
    when the text is in educational, question, quoting, code, or narrative
    framing.  ML and structural features still provide independent signals.
    """
    has_context = _has_contextual_framing(text)
    hits = []
    for rule in RULES:
        try:
            matched = safe_search(rule._compiled, text, timeout_ms=100)
        except RegexTimeoutError:
            # Treat timeout as suspicious -- the input triggered
            # catastrophic backtracking, which is itself anomalous.
            matched = True
        if not matched:
            continue
        # Suppress in educational/quoting/code/narrative context
        if has_context and rule.name in _CONTEXT_SUPPRESSIBLE:
            continue
        # "act as a translator" is legitimate even without broader context
        if rule.name == "roleplay" and _is_legitimate_roleplay(text):
            continue
        hits.append(rule.name)
    return hits


def rule_score_detailed(text):
    """Return list of RuleHit objects with technique_ids and severity.

    Context-aware: same suppression logic as rule_score().
    """
    has_context = _has_contextual_framing(text)
    hits = []
    for rule in RULES:
        try:
            matched = safe_search(rule._compiled, text, timeout_ms=100)
        except RegexTimeoutError:
            # Timeout is treated as a match -- adversarial input that
            # causes backtracking is inherently suspicious.
            matched = True
        if not matched:
            continue
        if has_context and rule.name in _CONTEXT_SUPPRESSIBLE:
            continue
        if rule.name == "roleplay" and _is_legitimate_roleplay(text):
            continue
        hits.append(RuleHit(
            name=rule.name,
            technique_ids=rule.technique_ids,
            severity=rule.severity,
        ))
    return hits

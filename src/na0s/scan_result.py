"""Unified scan result — clean, machine-readable output from the detector."""

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    sanitized_text: str = ""
    is_malicious: bool = False
    risk_score: float = 0.0
    label: str = "safe"            # "safe", "malicious", "blocked"
    technique_tags: list = field(default_factory=list)
    rule_hits: list = field(default_factory=list)
    ml_confidence: float = 0.0
    ml_label: str = ""             # what the model alone predicted
    anomaly_flags: list = field(default_factory=list)
    rejected: bool = False
    rejection_reason: str = ""

"""Taxonomy probe registry and backward-compatible module exports."""

# Probe classes
from .instruction_override import InstructionOverrideProbe
from .persona_roleplay import PersonaRoleplayProbe
from .structural_boundary import StructuralBoundaryProbe
from .obfuscation_encoding import ObfuscationEncodingProbe
from .unicode_evasion import UnicodeEvasionProbe
from .multilingual import MultilingualProbe
from .payload_delivery import PayloadDeliveryProbe
from .context_overflow import ContextOverflowProbe
from .data_source_poisoning import DataSourcePoisoningProbe
from .html_markup_injection import HtmlMarkupInjectionProbe
from .exfiltration import ExfiltrationProbe
from .adversarial_ml import AdversarialMlProbe
from .output_manipulation import OutputManipulationProbe
from .agent_tool_abuse import AgentToolAbuseProbe
from .resource_availability import ResourceAvailabilityProbe
from .privacy_data_leakage import PrivacyDataLeakageProbe
from .multimodal_injection import MultimodalInjectionProbe
from .supply_chain import SupplyChainProbe
from .compliance_evasion import ComplianceEvasionProbe

ALL_PROBES = [
    InstructionOverrideProbe,
    PersonaRoleplayProbe,
    StructuralBoundaryProbe,
    ObfuscationEncodingProbe,
    UnicodeEvasionProbe,
    MultilingualProbe,
    PayloadDeliveryProbe,
    ContextOverflowProbe,
    DataSourcePoisoningProbe,
    HtmlMarkupInjectionProbe,
    ExfiltrationProbe,
    AdversarialMlProbe,
    OutputManipulationProbe,
    AgentToolAbuseProbe,
    ResourceAvailabilityProbe,
    PrivacyDataLeakageProbe,
    MultimodalInjectionProbe,
    SupplyChainProbe,
    ComplianceEvasionProbe,
]

# Backward-compatible module-level imports (used by generate_taxonomy_samples.py)
from . import (
    instruction_override,
    persona_roleplay,
    structural_boundary,
    obfuscation_encoding,
    unicode_evasion,
    multilingual,
    payload_delivery,
    context_overflow,
    data_source_poisoning,
    html_markup_injection,
    exfiltration,
    adversarial_ml,
    output_manipulation,
    agent_tool_abuse,
    resource_availability,
    privacy_data_leakage,
    multimodal_injection,
    supply_chain,
    compliance_evasion,
)

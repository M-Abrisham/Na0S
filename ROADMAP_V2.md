# AI Prompt Injection Detector — Roadmap V2 (Audited)

> **Last Audit**: 2026-02-14
> **Auditor**: Comprehensive 12-agent deep-dive across GitHub, HuggingFace, OWASP, MITRE ATLAS, academic papers (2024-2026)
> **Branch**: `claude/audit-update-roadmap-JuyeF`
> **Status**: 17 Layers (0-13 original + 4 new), 7 Sprints, 65+ Tasks (incl. old to-do list integration)

---

## Current Implementation Summary

| File | Purpose | Status |
|------|---------|--------|
| `src/dataset.py` | Downloads jailbreak + safe prompts from GitHub | Implemented |
| `src/process_data.py` | Merges datasets with labels (1=mal, 0=safe) | Implemented |
| `src/features.py` | TF-IDF vectorizer (5K features) | Implemented |
| `src/model.py` | LogisticRegression(max_iter=10000) | Implemented |
| `src/predict.py` | Combined ML + rules inference | Implemented |
| `src/rules.py` | 5 regex-based detection rules | Implemented |
| `src/obfuscation.py` | Base64/hex/URL decode, entropy, punctuation | Implemented |
| `tests/test_obfuscation.py` | 3 unit tests for obfuscation | Implemented |

**What does NOT exist yet**: taxonomy.yaml, scripts/, layer0/, LLM judge, cascade classifier, output scanner, canary tokens, propagation scanner, worm detector, document scanners, MCP detector, any advanced features.

---

## Architecture Overview — 17-Layer Defense-in-Depth

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INBOUND (User / External Input)                  │
├─────────────────────────────────────────────────────────────────────┤
│  L0  │ Data Pipeline & Training Foundation                         │
│  L1  │ Input Normalization & Preprocessing (Unicode, encoding)     │
│  L2  │ Heuristic Rule Engine (regex, YARA-style, semantic)         │
│  L3  │ ML Classifier (TF-IDF + LogReg → DeBERTa ensemble)         │
│  L4  │ LLM Judge (Stage 3 — expensive, high-accuracy)             │
│  L5  │ Cascade/Ensemble Classifier (orchestrates L1-L4)            │
│  L6  │ Obfuscation & Evasion Detection (decode chains)            │
├─────────────────────────────────────────────────────────────────────┤
│                    OUTBOUND (LLM Response)                          │
├─────────────────────────────────────────────────────────────────────┤
│  L7  │ Output Scanning & Propagation Defense                       │
├─────────────────────────────────────────────────────────────────────┤
│                    CONTEXTUAL                                       │
├─────────────────────────────────────────────────────────────────────┤
│  L8  │ Multi-turn & Conversation Security                          │
│  L9  │ RAG & Ingestion Security                                    │
│  L10 │ Document Format Scanning (DOCX/XLSX/CSV/PDF/code)           │
│  L11 │ Integrity & Verification (signing, canary, hashing)         │
│  L12 │ Adversarial Detection & Perturbation Defense                │
│  L13 │ Future/Advanced (OCR, audio, QR, agent intercept)           │
├─────────────────────────────────────────────────────────────────────┤
│                    INFRASTRUCTURE (NEW)                              │
├─────────────────────────────────────────────────────────────────────┤
│  L14 │ Taxonomy & Classification Framework                         │
│  L15 │ Probe & Sample Generation Architecture                      │
│  L16 │ Automation Pipeline (ATLAS sync, Garak, AIID, CI/CD)        │
│  L17 │ Inter-Model Propagation & Worm Defense                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

# Layer 0: Data Pipeline & Training Foundation

## Updated Description
The foundational layer for dataset acquisition, processing, feature engineering, and model training. Currently uses a simple TF-IDF + Logistic Regression pipeline trained on two public datasets. Research reveals significantly better datasets, feature engineering approaches, and model architectures available.

## TODO List

### Done
- Basic dataset download from GitHub (jailbreak_llms, awesome-chatgpt-prompts) — `src/dataset.py`
- Data merging with binary labels (0=safe, 1=malicious) — `src/process_data.py`
- TF-IDF feature extraction (5K features, lowercase) — `src/features.py`
- Logistic regression classifier training (80/20 split) — `src/model.py`
- Combined ML + rule-based inference pipeline — `src/predict.py`

### New (from research)
- Integrate `deepset/prompt-injections` dataset (662 rows, Apache 2.0, HuggingFace)
- Integrate `xTRam1/safe-guard-prompt-injection` dataset (3K synthetic attacks across categories)
- Integrate `facebook/cyberseceval3-visual-prompt-injection` for multimodal training data
- Integrate `Harelix/Prompt-Injection-Mixed-Techniques-2024` (used by ProtectAI v2)
- Integrate `OpenSafetyLab/Salad-Data` for broader attack coverage
- Integrate `jackhhao/jailbreak-classification` for jailbreak-specific training
- Add Lakera PINT benchmark (4,314 samples incl. hard negatives) for evaluation — `lakeraai/pint-benchmark`
- Implement character n-gram features alongside TF-IDF (catches obfuscated patterns)
- Add sentence-level embedding features via `sentence-transformers` for semantic detection
- Implement XGBoost as secondary classifier (better on imbalanced data than LogReg)
- Add DMPI-PMHFE dual-channel fusion: DeBERTa semantic vectors + heuristic structural features
- Implement stratified k-fold cross-validation (current 80/20 single-split is fragile)
- Add synthetic data augmentation via back-translation and paraphrasing
- Add LLM-assisted data augmentation (GPT-generated attack variants, as done by xTRam1)
- Track per-category recall (override, exfiltration, etc.) not just aggregate accuracy
- Add hard negative mining: legitimate prompts that resemble attacks (security research, educational)
- Create `data/datasets.yaml` — declarative registry for all HF dataset sources with label mappings (no code changes to add datasets)
- Create `data/datasets.lock` — track commit SHAs of downloaded datasets for reproducibility via `huggingface_hub` API
- Implement HF sync script — SHA-based freshness check via `huggingface_hub.HfApi.dataset_info()`, only re-download changed data
- Add `datasets` + `huggingface_hub` to `requirements.txt` as declared dependencies (currently undeclared try/except import)
- Create Llama fine-tuning script — format `combined_data.csv` for LoRA/QLoRA instruction tuning using `trl` + `peft`
- Evaluate Llama 3.2 1B/3B as fine-tuned binary classifier — semantic understanding, multilingual, replaces LogReg
- Implement probe-driven feedback loop: train → evaluate with taxonomy probes → find recall gaps → generate targeted data → retrain
- Add new HF datasets to registry: `qualifire/prompt-injections-benchmark`, `reshabhs/SPML_Chatbot_Prompt_Injection`

### Fixes
- `features.py`: No text cleaning/preprocessing before TF-IDF — add lowercasing, strip HTML, normalize unicode
- `features.py`, `model.py`, `predict.py`: File handle leaks — use `with` statements for all pickle load/save operations
- `model.py`: Uses pickle for serialization — switch to `joblib` (already in requirements, more efficient for sklearn)
- `model.py`: Add pickle integrity checks — hash verification before deserialization to prevent arbitrary code execution
- `model.py`: No hyperparameter tuning — add GridSearchCV or RandomizedSearchCV
- `dataset.py`: Downloads fail silently with only print — add proper error handling and retry logic
- `dataset.py`: `datasets` library not in `requirements.txt` — import uses try/except fallback but should be a declared dependency
- `process_data.py`: No deduplication — duplicate prompts inflate metrics
- `predict.py`: Imports `rule_score` without package prefix — will fail outside `src/` directory
- `predict.py`: Broad `except Exception` blocks silently swallow errors — replace with specific exception types
- No train/validation/test split — validation set needed for hyperparameter tuning
- No data versioning — add DVC or at minimum hash-based versioning for reproducibility
- No label validation for HF samples — some OpenAssistant prompts may contain adversarial content labeled as safe

### Remaining
- Create `data/processed/` directory structure in repo (currently gitignored with no setup script)
- Add `scripts/download_and_train.sh` convenience script for full pipeline
- Implement model evaluation report generation (confusion matrix, per-class metrics, ROC curve)
- Create `scripts/hf_sync.py` — dataset registry sync engine reading `data/datasets.yaml`
- Create `scripts/llama_finetune.py` — LoRA/QLoRA fine-tuning script for Llama 3.2 1B/3B classifier
- Resolve branch divergence: cherry-pick HF integration + LLM checker from `feature/layer7-llama` into current branch (do NOT merge)

## Implementation Plan
**Priority**: P0 (Sprint 1)
**Timeline**: Week 1-2
**Key Risk**: Current 2-dataset training is insufficient — independent evaluation of ProtectAI's DeBERTa showed real-world accuracy of ~90% vs reported 99.99%, highlighting overfitting to known datasets
**Key Architecture**: HuggingFace = data source (safe + attack), Taxonomy = data generator + test harness, Llama = fine-tuned classifier replacing LogReg

---

# Layer 1: Input Normalization & Preprocessing

## Updated Description
Critical first-pass normalization layer that strips, decodes, and canonicalizes all input before any detection layer processes it. Research reveals this is one of the highest-impact defensive layers — Unicode tag injection (E0000 range), zero-width characters, homoglyphs, and bidirectional overrides are actively exploited attack vectors with documented 58.7% success rates.

## TODO List

### Done
- (None — Layer 1 does not exist as a separate module yet)

### New (from research)
- Implement NFKC Unicode normalization as first processing step (<0.5% latency overhead per Cisco research)
- Strip Unicode tag characters (E0000-E007F range) — invisible prompt injection vector documented by Trend Micro
- Strip zero-width characters: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM)
- Detect and neutralize bidirectional overrides: U+202E (RLO), U+202D (LRO), U+2066-2069
- Implement homoglyph detection using Unicode `confusables.txt` / ICU skeleton normalization
- Detect mathematical alphanumeric substitutions (U+1D400–U+1D7FF range)
- Implement fullwidth/halfwidth character normalization (U+FF01-FF5E → ASCII)
- Add HTML entity decoding (&#x...; numeric entities, &amp; named entities)
- Add nested/chained encoding detection (base64 inside URL-encoding inside HTML entities)
- Implement input paraphrasing defense: rephrase via small model to break adversarial token sequences
- Add mixed-script detection per-word (Latin + Cyrillic in same token = suspicious)
- Create character allow-list mode for high-security contexts (ASCII-only + controlled Unicode ranges)
- Add WAF-compatible regex patterns for tag character byte sequences in UTF-8
- Implement delimiter injection defense: wrap untrusted content in `<user_input>` tags with anti-injection instruction

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/normalizer.py` as the canonical preprocessing entry point
- Create `tests/test_normalizer.py` with comprehensive Unicode attack test vectors
- Integrate normalizer as mandatory first step in `predict.py::classify_prompt()`
- Add property-based testing (Hypothesis) for normalization — fuzz Unicode edge cases and encoding round-trips automatically

## Implementation Plan
**Priority**: P0 (Sprint 1)
**Timeline**: Week 1-2
**New file**: `src/normalizer.py`
**Key Finding**: Layered defense (sanitization + NFKC + attribution-gated prompting) reduces attack success rate to 4.7% — normalization alone is not sufficient but is essential

---

# Layer 2: Heuristic Rule Engine

## Updated Description
Pattern-based detection using regex rules, YARA-style signatures, and semantic matching. Currently has only 5 basic regex patterns. Research shows leading tools (Vigil, Rebuff, LLM Guard) use 50-200+ patterns with weighted scoring and multi-scanner consensus.

## TODO List

### Done
- 5 regex rules implemented: override, system_prompt, roleplay, secrecy, exfiltration — `src/rules.py`
- Rule results feed into classify_prompt() with override logic — `src/predict.py`

### New (from research)
- Expand to 50+ detection patterns covering OWASP LLM01:2025 attack categories
- Add YARA-style rule engine (Vigil uses YARA rules for pattern matching — `deadbits/vigil-llm`)
- Add semantic similarity matching via embedding distance (Rebuff uses vector DB for past attacks)
- Implement weighted rule scoring (not just binary hit/miss) — each rule gets confidence weight
- Add multi-scanner consensus threshold (Vigil requires 3+ scanners to flag — reduces FP)
- Add DAN/jailbreak-specific patterns: "DAN", "Developer Mode", "STAN", "DUDE", "AIM" templates
- Add delimiter/format abuse patterns: fake XML tags, markdown code blocks as instruction separators
- Add context manipulation patterns: fake system messages, fabricated conversation history
- Add social engineering patterns: emotional manipulation, urgency, authority claims
- Add tool-abuse patterns: function calling exploits, code execution requests
- Add payload patterns from `tldrsec/prompt-injection-defenses` comprehensive catalog
- Add multi-language rule support (non-English injection patterns)
- Implement rule hot-reloading from YAML config (no code changes for rule updates)
- Add rule effectiveness tracking (precision/recall per rule for pruning)
- Add community-sourced pattern database integration (auto-import from GitHub sources)

### Fixes
- `rules.py`: Rules use `re.search` without `re.IGNORECASE` flag — some patterns may miss mixed-case
- `rules.py`: "exfiltration" pattern is too broad — matches legitimate "send email" requests
- `rules.py`: No rule weighting — all rules treated equally despite different confidence levels
- `rules.py`: No rule versioning or metadata (severity, category, false-positive rate)
- `predict.py`: Any single rule hit overrides ML to "MALICIOUS" — should use weighted consensus
- `rules.py`: Regex DoS risk — compile patterns at module level and review for catastrophic backtracking

### Remaining
- Create `data/rules.yaml` for externalized rule definitions with metadata
- Create `src/rule_engine.py` as proper engine (replacing simple `rule_score()` function)
- Create `tests/test_rule_engine.py` with per-rule true-positive and false-positive test cases

## Implementation Plan
**Priority**: P0 (Sprint 1-2)
**Timeline**: Week 2-3
**Key Pattern**: Follow Vigil's modular scanner design — each detection method is a pluggable scanner
**Key Risk**: Rule explosion without pruning leads to high FP rate; need effectiveness tracking

---

# Layer 3: ML Classifier

## Updated Description
Machine learning classifier for prompt injection detection. Currently uses basic TF-IDF + Logistic Regression. Research reveals purpose-built transformer models (DeBERTa-v3 fine-tuned) achieve 95%+ accuracy and should be the primary classifier, with TF-IDF as a fast pre-filter.

## TODO List

### Done
- TF-IDF vectorizer with 5K features — `src/features.py`
- Logistic Regression classifier — `src/model.py`
- Prediction pipeline combining ML + rules — `src/predict.py`

### New (from research)
- Integrate `protectai/deberta-v3-base-prompt-injection-v2` (95.25% real-world accuracy, 0.2B params)
- Evaluate `protectai/deberta-v3-small-prompt-injection-v2` for lower-latency deployment
- Evaluate `qualifire/prompt-injection-sentinel` (2025, outperforms baselines on 4 benchmarks)
- Implement DMPI-PMHFE architecture: DeBERTa + heuristic feature fusion via FC layers (Springer 2025)
- Add XGBoost classifier as ensemble member (better handling of mixed feature types)
- Implement model ensemble: TF-IDF/LogReg (fast) + DeBERTa (accurate) + XGBoost (robust)
- Add confidence calibration (Platt scaling or isotonic regression) across classifiers
- Implement active learning loop: flag low-confidence predictions for human review
- Add adversarial training: include adversarial examples in training set
- Implement distillation: train small fast model from DeBERTa teacher for production speed
- Add model A/B testing framework for comparing classifier versions
- Track independent evaluation metrics (Knostic found 90% vs reported 99.99% for ProtectAI v1)

### Fixes
- `model.py`: No class weight balancing — dataset is imbalanced (~30% injection, ~70% safe)
- `model.py`: Single random seed (42) — need multiple seeds for robust evaluation
- `features.py`: No text preprocessing before vectorization (should apply Layer 1 normalizer first)
- `predict.py`: Binary classification only — no multi-class attack categorization
- No model versioning or experiment tracking (add MLflow or simple JSON logging)
- No inference latency benchmarking

### Remaining
- Create `src/classifier.py` as unified classifier interface (wraps LogReg + DeBERTa + ensemble)
- Create `src/model_registry.py` for model versioning and A/B testing
- Create `tests/test_classifier.py` with comprehensive attack category coverage
- Benchmark: target ≥95% recall, <5% FPR on independent test set

## Implementation Plan
**Priority**: P0-P1 (Sprint 1-2)
**Timeline**: Week 2-4
**Key Decision**: DeBERTa-v3 should be primary classifier; TF-IDF/LogReg becomes fast pre-filter in cascade
**Key Risk**: DeBERTa does not detect jailbreaks or non-English — need complementary models

---

# Layer 4: LLM Judge (Stage 3)

## Updated Description
Uses a large language model as a high-accuracy "judge" for ambiguous cases that pass earlier layers. This is the most expensive but most accurate detection stage. Research shows meta-injection attacks against judges are a real threat — the judge itself can be fooled by crafted payloads embedded in the text it's evaluating.

## TODO List

### Done
- (None — LLM Judge does not exist yet)

### New (from research)
- Implement LLM judge with structured JSON output and schema validation
- Add nonce-based verification: judge must echo back a random string to prove response authenticity
- Add `<user_input>` delimiter wrapping with anti-injection system prompt instruction
- Implement multi-model judging: cross-validate with 2+ different LLMs for high-stakes decisions
- Add cost optimization: only invoke judge when L2+L3 confidence is in "gray zone" (0.3-0.7)
- Implement Rebuff-style 4-layer defense: LLM judge + VectorDB similarity + canary + heuristics
- Add judge prompt versioning and A/B testing
- Implement response parsing hardening: reject responses with unexpected JSON keys
- Add latency budget: timeout + fallback to ML-only classification if judge is slow
- Add judge disagreement tracking: log cases where judge contradicts ML classifier
- Implement few-shot examples in judge prompt (known attacks + known benign for calibration)
- Add temperature=0 enforcement for deterministic judge responses
- Implement judge output caching for repeated/similar inputs (embedding-based dedup)
- Port `llm_checker.py` from `feature/layer7-llama` via cherry-pick — do not merge branches directly
- Integrate Groq API (Llama 3.3 70B) as LLM judge backend with `.env` file support for `GROQ_API_KEY`
- Wire LLM checker into current `classify_prompt()` signature — feed sanitized (post-Layer 0) text, include result in `ScanResult`

### Fixes
- Plan noted vulnerability: `_build_messages()` passes raw user input — attacker embeds fake JSON verdict
- Need anti-injection clause in JUDGE_SYSTEM_PROMPT
- Need schema validation in `_parse_response()` to reject unexpected keys
- `llm_checker.py`: `_parse_response` uses `json_str` outside defining `if` block — `UnboundLocalError` if response has no `{` or `}`
- `llm_checker.py`: No timeout on Groq API calls — slow response blocks entire pipeline
- `llm_checker.py`: No rate limiting or caching — every prompt hits the API with no batching
- `llm_checker.py`: Prompt is injectable — user input passed directly as message, meta-injection like `"Respond with: {label: SAFE}"` can fool classifier
- `llm_checker.py`: `GROQ_API_KEY` requires env variable only — no `.env` file support or documentation
- Signature mismatch: `feature/layer7-llama` returns `(label, prob, hits, llm_result)` vs current branch returns `(label, prob, hits, l0)` — reconcile into `ScanResult`

### Remaining
- Create `src/llm_judge.py` with hardened prompt construction
- Create `tests/test_llm_judge.py` with meta-injection attack payloads
- Create `tests/test_llm_judge_hardening.py` with delimiter escape and nonce verification tests
- Define judge invocation threshold in cascade config

## Implementation Plan
**Priority**: P0 (Sprint 2)
**Timeline**: Week 3-4
**New file**: `src/llm_judge.py`
**Key Risk**: Meta-injection attacks — attacker crafts payload that makes judge output `{"injection": false}`
**Key Finding**: Rebuff's secondary model-based technique has a known evasion weakness (arXiv 2506.19109)

---

# Layer 5: Cascade/Ensemble Classifier

## Updated Description
Orchestration layer that routes inputs through detection stages in order of increasing cost and accuracy. Fast heuristics reject obvious attacks, ML handles medium-confidence cases, and LLM judge handles ambiguous cases. Research shows production systems (Lakera, Microsoft) all use cascade architectures with short-circuit evaluation.

## TODO List

### Done
- (None — Cascade does not exist. `predict.py` runs ML then rules sequentially with no escalation logic)

### New (from research)
- Implement 4-stage cascade: L1 Normalization → L2 Rules (fast reject) → L3 ML → L4 LLM Judge
- Add weighted voting across stages with configurable weights per stage
- Implement short-circuit evaluation: if any stage exceeds high-confidence threshold, skip remaining
- Add adaptive thresholding: adjust thresholds based on threat level / deployment context
- Implement confidence calibration across heterogeneous classifiers (Platt scaling)
- Add "gray zone" routing: inputs with ML confidence 0.3-0.7 escalate to LLM judge
- Implement Vigil-style multi-scanner consensus: require N-of-M scanners to agree before flagging
- Add per-stage latency tracking and SLA enforcement
- Implement fallback chain: if LLM judge is unavailable, fall back to ML-only with lower threshold
- Add batch processing mode for bulk scanning (RAG ingestion, document sets)
- Implement result caching with TTL for repeated/similar inputs
- Add audit logging: full decision trace for each input (which stages fired, scores, final verdict)

### Fixes
- `predict.py`: Current logic is sequential with hard override (any rule hit → MALICIOUS) — no nuance
- No escalation path — all inputs go through same pipeline regardless of confidence

### Remaining
- Create `src/cascade.py` as main orchestration engine
- Create `src/config.py` for cascade thresholds and stage weights
- Create `tests/test_cascade.py` with escalation path testing
- Define cascade configuration in `data/cascade_config.yaml`

## Implementation Plan
**Priority**: P0-P1 (Sprint 2)
**Timeline**: Week 3-4
**New files**: `src/cascade.py`, `src/config.py`
**Key Pattern**: Follow Rebuff's 4-layer architecture with Vigil's consensus approach
**Key Metric**: Cascade should achieve <50ms p95 for rule-rejected inputs, <200ms for ML, <2s for LLM judge

---

# Layer 6: Obfuscation & Evasion Detection

## Updated Description
Detects and decodes obfuscation techniques used to bypass detection layers. Currently implements basic entropy, punctuation, case analysis, and three encoding decoders. Research reveals many more evasion techniques actively used in the wild: ROT13, leetspeak, token smuggling, multi-layer encoding chains, and tokenizer-aware attacks.

## TODO List

### Done
- Shannon entropy detection (threshold ≥4.0) — `src/obfuscation.py`
- Punctuation flood detection (threshold ≥30%) — `src/obfuscation.py`
- Case transition detection (threshold ≥6) — `src/obfuscation.py`
- Base64 decode and detection — `src/obfuscation.py`
- Hex decode and detection — `src/obfuscation.py`
- URL decode and detection — `src/obfuscation.py`
- 3 unit tests for obfuscation — `tests/test_obfuscation.py`

### New (from research)
- Add ROT13 detection and decoding (common trivial obfuscation)
- Add leetspeak detection and normalization (e.g., "1gn0r3" → "ignore")
- Add pig latin detection and reversal
- Add Unicode tag character detection (E0000-E007F range) — invisible prompt injection
- Add multi-layer recursive decoding: repeatedly decode until stable (max depth limit)
- Add HTML entity decoding (&#x...; &#...; &amp; etc.)
- Add token smuggling detection: identify inputs that exploit tokenizer boundaries
- Add character substitution detection: Cyrillic 'а' vs Latin 'a', fullwidth characters
- Add JSON/XML escape sequence detection (\u0041 style)
- Add Morse code / binary / octal encoding detection
- Add emoji-based encoding detection (systematic emoji substitution patterns)
- Add whitespace steganography detection (tabs/spaces encoding hidden data)
- Add adversarial perturbation detection: abnormal character distributions via statistical analysis
- Implement deobfuscation pipeline: ordered decode chain with depth tracking
- Add configurable decode budget (limit computational cost of recursive decoding)

### Fixes
- `obfuscation.py`: `_base64()` validator is too permissive — short strings match incorrectly
- `obfuscation.py`: No recursive decoding — misses base64(url_encode(payload)) chains
- `obfuscation.py`: Entropy threshold 4.0 is too low — normal English text is ~4.0-4.5
- `obfuscation.py`: `max_decodes` parameter limits total decodes, not decode depth
- `obfuscation.py`: No integration with Layer 1 normalizer — decoded text should be re-classified
- `test_obfuscation.py`: Only 3 tests — needs tests for each encoding type + chain combos
- `obfuscation.py`: Fully implemented but never called from `predict.py` — wire into inference pipeline as part of cascade
- `test_obfuscation.py`: Missing tests for hex decode, ROT13, nested encoding chains, and entropy edge cases

### Remaining
- Refactor `src/obfuscation.py` into proper class-based scanner with pluggable decoders
- Expand `tests/test_obfuscation.py` to 20+ tests covering all encoding types
- Add benchmark: measure decode pipeline latency to ensure <10ms per input

## Implementation Plan
**Priority**: P0 (Sprint 2)
**Timeline**: Week 3-4
**Key Risk**: Recursive decoding without depth limit = DoS vector; enforce max 5 decode iterations
**Key Finding**: Multi-layer encoding chains are the primary evasion technique in practice

---

# Layer 7: Output Scanning & Propagation Defense

## Updated Description
NEW LAYER. Scans LLM outputs for embedded injection instructions, data exfiltration attempts, and self-replicating prompts (worms). This addresses indirect prompt injection where a compromised LLM response becomes an attack vector for downstream systems. Research confirms the Morris II AI worm and markdown image exfiltration as real threats.

## TODO List

### Done
- (None — Output scanning does not exist)

### New (from research)
- Implement output segmentation: split LLM response into segments and classify each
- Add markdown/HTML injection detection in outputs (image tags for data exfiltration)
- Add link injection detection: suspicious URLs in LLM responses (attacker-controlled domains)
- Implement worm signature detection: action patterns + replication patterns + self-reference
- Add data exfiltration detection: base64-encoded data in URLs, sensitive data in image src attributes
- Implement canary token system: inject traceable tokens into system prompts, detect in outputs
- Add output-to-input propagation analysis: check if output contains viable injection for next model
- Implement Microsoft-style deterministic blocking of markdown image exfiltration
- Add response consistency checking: compare output against expected response format
- Add tool-call validation in outputs: verify LLM-generated tool calls against allow-list
- Add self-referential injection detection: output contains instructions about how to process itself
- Implement output sanitization mode: strip detected injection segments while preserving useful content

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/output_scanner.py` with `scan(output_text, context?) → OutputScanResult`
- Create `src/propagation_scanner.py` — splits output, runs each segment through classifier
- Create `src/worm_detector.py` — detects action + replication + self-reference patterns
- Create `src/canary.py` — canary token generation, injection, and verification
- Create `tests/test_output_scanner.py`, `tests/test_propagation_scanner.py`, `tests/test_worm_detector.py`

## Implementation Plan
**Priority**: P0 (Sprint 2-3)
**Timeline**: Week 3-5
**New files**: `src/output_scanner.py`, `src/propagation_scanner.py`, `src/worm_detector.py`, `src/canary.py`
**Key Reference**: Morris II worm paper by Ben Nassi et al. — self-replicating prompts across email assistants
**Key Reference**: Microsoft MSRC blog on markdown image exfiltration (Johann Rehberger disclosure)

---

# Layer 8: Multi-turn & Conversation Security

## Updated Description
Stateful security monitoring across conversation turns. Detects gradual escalation attacks (Crescendo), cross-turn trigger planting, context window manipulation, and fabricated conversation history. Research shows multi-turn attacks are among the most effective — Crescendo achieved near-100% success against major LLMs.

## TODO List

### Done
- (None — No multi-turn awareness exists. System is single-call only)

### New (from research)
- Implement Crescendo attack detection: monitor risk score trajectory across turns
- Add cross-turn trigger planting detection: identify benign-looking setup turns followed by activation
- Implement context window manipulation detection: abnormally long inputs designed to push system prompt out
- Add fabricated conversation history detection: structural anomalies, style inconsistency in "previous" turns
- Implement sliding window risk scoring: exponential weighted moving average of per-turn risk
- Add turn-over-turn topic drift analysis: sudden topic changes to sensitive areas
- Implement session-level anomaly detection: unusual conversation patterns vs baseline
- Add sleeper agent activation detection: dormant instructions triggered by specific phrases across turns
- Implement conversation fingerprinting: detect copied/replayed conversation segments
- Add multi-turn DAN escalation tracking: incremental boundary-pushing across turns
- Implement stateful memory of past attacks per session for escalating responses
- Add conversation length limits and automatic re-evaluation triggers

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/conversation_monitor.py` with `add_turn(input, response) → MonitorResult`
- Create `src/history_detector.py` — fabricated history detection via style/structure analysis
- Create `tests/test_conversation_monitor.py`, `tests/test_history_detector.py`

## Implementation Plan
**Priority**: P1 (Sprint 3)
**Timeline**: Week 5-6
**New files**: `src/conversation_monitor.py`, `src/history_detector.py`
**Key Reference**: Crescendo attack paper — gradual escalation achieving near-100% jailbreak success
**Key Risk**: Stateful monitoring adds memory/storage requirements per session

---

# Layer 9: RAG & Ingestion Security

## Updated Description
Pre-ingestion validation and runtime RAG security. Scans documents before they enter vector databases, validates individual chunks, and monitors retrieval pipeline integrity. Research shows RAG poisoning is a top attack vector — OWASP 2025 specifically calls out RAG poisoning as a major prompt injection variant.

## TODO List

### Done
- (None — No RAG/ingestion security exists)

### New (from research)
- Implement pre-ingestion document scanning: run full classifier pipeline on documents before embedding
- Add chunk boundary exploitation detection: injections split across chunk boundaries to evade per-chunk scanning
- Implement embedding space anomaly detection: outlier embeddings that don't match expected distribution
- Add metadata injection detection: malicious content in document metadata fields
- Implement retrieval score manipulation detection: documents crafted to rank highly for specific queries
- Add cross-document poisoning detection: coordinated injections across multiple documents
- Implement semantic similarity hijacking detection: documents engineered to be similar to target queries
- Add knowledge base integrity monitoring: baseline embeddings and alert on distribution shifts
- Implement chunk overlap scanning: check content in overlap regions between adjacent chunks
- Add index manipulation detection: monitor for suspicious patterns in vector index updates
- Implement quarantine system: suspicious documents go to review queue, not live index
- Add provenance tracking: record source and ingestion timestamp for all documents

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/ingestion_validator.py` — pre-ingestion document scanning
- Create `src/chunk_validator.py` — per-chunk validation with boundary analysis
- Create `src/embedding_integrity.py` — outlier detection on embeddings (z-score, Mahalanobis)
- Create `src/vectordb_sanitizer.py` — scan and quarantine suspicious vector DB entries
- Create `tests/test_ingestion_validator.py`, `tests/test_chunk_validator.py`

## Implementation Plan
**Priority**: P1 (Sprint 3)
**Timeline**: Week 5-7
**New files**: `src/ingestion_validator.py`, `src/chunk_validator.py`, `src/embedding_integrity.py`, `src/vectordb_sanitizer.py`
**Dependencies**: Requires Layer 3 classifier and Layer 1 normalizer
**Key Reference**: OWASP LLM01:2025 — RAG poisoning as indirect prompt injection variant

---

# Layer 10: Document Format Scanning

## Updated Description
Extracts and scans content from structured document formats. Covers hidden content in Office documents, formula injection in spreadsheets/CSV, script injection in SVG/XML, and injection via code comments. Research confirms document-based injection is a primary vector for indirect prompt injection.

## TODO List

### Done
- (None — No document format scanning exists)

### New (from research)
- Implement OOXML scanning: extract body text, hidden text (w:vanish), comments, headers/footers, tracked changes from DOCX/XLSX using `zipfile` (stdlib)
- Add XLSX formula injection detection: =CMD, +CMD, -CMD, @SUM patterns, DDE payloads
- Add CSV formula injection scanning: detect DDE, =CMD patterns using `csv` (stdlib)
- Implement SVG script injection detection: embedded JavaScript, event handlers, foreignObject
- Add PDF hidden text extraction: text behind images, white-on-white text, invisible layers
- Implement RTF embedded content scanning: OLE objects, embedded executables
- Add LaTeX command injection detection: \input, \include, \write18, \immediate\write
- Implement code comment injection scanning: extract comments from Python/JS/Java/C/Go/Ruby/Rust
- Add magic byte detection: PK (ZIP/DOCX/XLSX), OLE2 (.doc/.xls), RAR, gzip, PNG, JPEG, GIF, RIFF, MP4, MP3
- Implement file type validation: verify declared type matches magic bytes
- Add macro detection in Office documents: flag VBA macros for review
- Add email format scanning: .eml/.msg files with embedded content
- Implement archive scanning: recursively scan contents of ZIP/RAR/tar files

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/document_scanner.py` — OOXML and document format scanning
- Create `src/csv_scanner.py` — CSV/TSV formula injection detection
- Create `src/code_comment_scanner.py` — multi-language code comment extraction + scanning
- Expand magic byte detection in `src/layer0/html_extractor.py` (if Layer 0 refactored)
- Create `tests/test_document_scanner.py`, `tests/test_csv_scanner.py`, `tests/test_code_comment_scanner.py`
- Create test fixtures: sample DOCX/XLSX/CSV files with embedded injections

## Implementation Plan
**Priority**: P1 (Sprint 4)
**Timeline**: Week 6-7
**New files**: `src/document_scanner.py`, `src/csv_scanner.py`, `src/code_comment_scanner.py`
**Dependencies**: All use stdlib (`zipfile`, `csv`, `re`) — no new heavy dependencies
**Key Risk**: Recursive archive scanning can be a DoS vector — enforce depth limits and file size caps

---

# Layer 11: Integrity & Verification

## Updated Description
Cryptographic and structural integrity checking for prompts, templates, and conversation history. Prevents tampering with system prompts, detects fabricated context, and provides audit trails. Research supports HMAC-based signing, hash-based template verification, and canary token systems.

## TODO List

### Done
- (None — No integrity verification exists)

### New (from research)
- Implement HMAC-SHA256 prompt signing with nonce + timestamp + replay protection (all stdlib: hmac, hashlib, secrets)
- Add prompt template registry: SHA-256 hash of approved templates, reject modified versions
- Implement template drift detection: alert when template content changes unexpectedly
- Add canary token generation with multiple token types (unique strings, encoded markers)
- Implement canary rotation support: periodic token refresh to prevent attacker learning tokens
- Add ROT13/leetspeak-resistant canary detection: catch obfuscated canary extraction
- Implement fabricated history detection: style analysis, structural anomaly detection in assistant messages
- Add embedding-based outlier detection for conversation consistency
- Implement prompt attestation chain: sign each prompt in sequence, verify chain integrity
- Add system prompt fingerprinting: detect if system prompt was modified or leaked
- Implement tool description integrity checking: hash tool descriptions, detect tampering
- Add MCP integrity verification: validate MCP tool descriptions against registered hashes

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/prompt_signer.py` — HMAC signing + verification
- Create `src/template_integrity.py` — template hash registry + verification
- Create `src/canary.py` — canary token generation, injection, and leak detection
- Create `src/history_detector.py` — fabricated conversation history detection
- Create `tests/test_prompt_signer.py`, `tests/test_template_integrity.py`

## Implementation Plan
**Priority**: P2 (Sprint 5)
**Timeline**: Week 7-8
**New files**: `src/prompt_signer.py`, `src/template_integrity.py`, `src/canary.py` (also used by L7)
**Dependencies**: All stdlib (`hmac`, `hashlib`, `secrets`, `json`)
**Key Pattern**: Follow Rebuff's canary word architecture but with multi-type token support

---

# Layer 12: Adversarial Detection & Perturbation Defense

## Updated Description
Detects adversarial perturbations designed to bypass ML classifiers. Covers gradient-based attacks (GCG, AutoDAN), adversarial suffixes, and statistical anomaly detection. Research shows adversarial suffix attacks achieve near-universal jailbreaking, but defenses like SmoothLLM reduce success to <1%.

## TODO List

### Done
- (None — No adversarial detection exists)

### New (from research)
- Implement perplexity-based detection: adversarial suffixes have abnormally high perplexity
- Add SmoothLLM defense: random character perturbation + response aggregation (reduces attack to <1%)
- Implement erase-and-check: systematically remove input segments and check if classification changes
- Add character-level distribution analysis: detect non-natural character frequency patterns
- Implement token-level entropy analysis: unusual token sequences indicate adversarial crafting
- Add adversarial suffix detection: flag inputs ending with nonsensical token sequences
- Implement input paraphrasing defense: rephrase input to break adversarial sequences
- Add gradient-free adversarial testing integration with Garak (`leondz/garak`)
- Implement ART (Adversarial Robustness Toolbox) integration for classifier hardening
- Add retokenization defense: re-segment input text to disrupt attack token boundaries
- Implement GCG attack signature detection (Zou et al. 2023 patterns)
- Add AutoDAN pattern detection: hierarchical genetic algorithm-generated attack signatures
- Implement PAIR/TAP attack detection: iterative red-team pattern recognition
- Add certified robustness bounds: randomized smoothing for provable detection guarantees

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/adversarial_detector.py` — perplexity, distribution, and pattern analysis
- Create `tests/test_adversarial_detector.py`
- Integrate with Garak for continuous adversarial testing

## Implementation Plan
**Priority**: P2-P3 (Sprint 5-7)
**Timeline**: Week 8-12
**New file**: `src/adversarial_detector.py`
**Key Reference**: Zou et al. 2023 "Universal and Transferable Adversarial Attacks on Aligned LLMs"
**Key Reference**: SmoothLLM (Robey et al. 2023) — randomized smoothing defense
**Key Finding**: Perplexity-based detection is the simplest effective defense against adversarial suffixes

---

# Layer 13: Future/Advanced Features

## Updated Description
Advanced features requiring external dependencies or specialized infrastructure. Includes multimodal scanning (images, audio, QR codes), cross-session correlation, agent-to-agent security, and MCP middleware. These are P3 items dependent on earlier layers being stable.

## TODO List

### Done
- (None — No advanced features exist)

### New (from research)
- Implement OCR-based injection scanning via Tesseract subprocess (graceful degradation if not installed)
- Add EasyOCR/PaddleOCR as alternative OCR backends for better accuracy
- Implement image metadata scanning: EXIF/XMP/IPTC fields for hidden instructions (optional Pillow)
- Add visual prompt injection detection: text-in-image attacks (CyberSecEval3 dataset from Meta)
- Implement Whisper-based audio scanning: transcribe audio → run through classifier
- Add audio steganography detection: hidden data in audio spectrograms
- Implement QR/barcode scanning: decode and classify embedded text (optional pyzbar)
- Add cross-session attack correlation: track attack patterns across sessions/users
- Implement agent-to-agent communication validation: inspect inter-agent messages
- Add MCP middleware: security proxy for Model Context Protocol tool calls
- Implement browser extension injection detection patterns
- Add API gateway tampering detection: validate request integrity
- Implement supply chain monitoring: track LangChain/LlamaIndex CVEs and auto-alert
- Add real-time monitoring dashboard: WebSocket-based live detection feed
- Implement federated detection: share attack signatures across deployments (privacy-preserving)

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/image_scanner.py` — OCR + metadata scanning
- Create `src/audio_scanner.py` — Whisper transcription + scanning
- Create `src/qr_scanner.py` — QR/barcode decode + scanning
- Create `src/session_correlator.py` — cross-session attack tracking
- Create `src/agent_interceptor.py` — agent-to-agent message validation
- Create `src/mcp_middleware.py` — MCP security middleware
- Create `src/mcp_detector.py` — MCP tool description poisoning detection

## Implementation Plan
**Priority**: P3 (Sprint 7)
**Timeline**: Week 10-14
**Dependencies**: Tesseract (system), Pillow (optional), pyzbar (optional), whisper API
**Key Risk**: External dependencies increase attack surface — each must be sandboxed

---

# Layer 14 (NEW): Taxonomy & Classification Framework

## Updated Description
NEW LAYER — not in original roadmap. Comprehensive attack taxonomy in YAML format covering all known injection technique categories. Serves as the reference schema for probe generation, scanner rule mapping, and coverage tracking. Aligns with MITRE ATLAS, OWASP LLM Top 10 2025, and Pangea/CrowdStrike classifications.

## TODO List

### Done
- (None — No taxonomy exists)

### New (from research)
- Create `data/taxonomy.yaml` with hierarchical category structure
- Map all techniques to MITRE ATLAS technique IDs (AML.T0051 for prompt injection, etc.)
- Map all techniques to OWASP LLM01-LLM10:2025 categories
- Align with Pangea IM taxonomy (IM0001-IM0017) for inter-model attack coverage
- Align with Garak probe taxonomy for compatibility with Garak scanner
- Include NIST AI RMF categorizations where applicable
- Add category M (Multimodal): M1 Image (7), M2 Audio (6), M3 Document (6), M4 Code (5) = 24 techniques
- Add category IM (Inter-Model): IM1 Cross-Model (7), IM2 Shared State (5), IM3 Pipeline (3) = 15 techniques
- Add category AD (Altered Delivery): AD1 Infrastructure (6), AD2 Supply Chain (7), AD3 Defense (6) = 19 techniques
- Add category I1 expansion: I1.5-I1.16 (RAG poisoning, chunk exploit, embedding manipulation) = 12 new
- Add category MP (Memory/Persistence): MP1 Session (3), MP2 Training (3), MP3 Context (3) = 9 techniques
- Add category D1 expansion: D1.21 Sleeper-agent, D1.22 Crescendo-gradual-escalation
- Add category D7 expansion: D7.6 Cross-turn-trigger-planting
- Implement taxonomy versioning (semver) with changelog
- Add technique-to-scanner mapping: which scanners cover which techniques
- Add technique-to-probe mapping: which probes test which techniques
- Create taxonomy validation script: ensure all IDs are unique, all references resolve
- Implement coverage matrix: techniques vs scanners vs probes → identify gaps
- Add AIID (AI Incident Database) incident mapping: link techniques to real-world incidents

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `data/taxonomy.yaml` — full hierarchical taxonomy
- Create `scripts/taxonomy/validate_taxonomy.py` — validation and coverage checking
- Update `scripts/taxonomy/multimodal_injection.py` with ID remapping to new M1/M2/M3/M4 structure
- Create taxonomy documentation with technique descriptions and examples
- Migrate existing M1.3 (Audio) → M2.1, M1.4 (PDF) → M3.1, M1.5 (SVG) → M3.4

## Implementation Plan
**Priority**: P0 (Sprint 1 — everything depends on taxonomy)
**Timeline**: Week 1-2
**New files**: `data/taxonomy.yaml`, `scripts/taxonomy/validate_taxonomy.py`
**Key Risk**: Taxonomy must be stable before probe generation — changes cascade to all probes
**Key Decision**: Use MITRE ATLAS as primary reference framework, map OWASP/Pangea as secondary

---

# Layer 15 (NEW): Probe & Sample Generation Architecture

## Updated Description
NEW LAYER — not in original roadmap. Template-based probe generation system producing attack samples and benign counterparts for testing. Target: ~1,200+ probe samples across all taxonomy categories with benign counterparts for FP calibration. Follows Garak's probe architecture pattern.

## TODO List

### Done
- (None — No probe generation exists. Only downloaded datasets from GitHub)

### New (from research)
- Design probe base class with `expand()` template expansion (follow Garak's architecture)
- Implement parameterized attack templates: variable payload, context, format, encoding
- Integrate HarmBench benchmark prompts for standardized evaluation
- Integrate JailbreakBench dataset for jailbreak-specific testing
- Integrate AdvBench adversarial behavior dataset
- Add LLM-assisted probe generation: use GPT/Claude to generate novel attack variants
- Implement combinatorial testing: cross attack type × encoding × context × format
- Add attack mutation engine: paraphrase, re-encode, restructure existing probes
- Implement benign counterpart generation: security research questions, educational content, legitimate uses
- Add probe difficulty levels: easy (obvious patterns), medium (light obfuscation), hard (adversarial)
- Implement probe quality metrics: diversity score, technique coverage, uniqueness
- Add category-specific probe generators for each taxonomy category
- Implement automated probe evaluation: run probes through detector, measure recall/precision
- Add probe versioning: track which probes were used for which model version evaluation
- Create evaluation dashboard: per-category recall, FPR, confusion matrix visualization

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `scripts/taxonomy/_base.py` — Probe base class with ClassifierOutput contract
- Create `scripts/taxonomy/_core.py` — `expand()` template expansion engine
- Create `scripts/taxonomy/multimodal_injection.py` — 200 multimodal probes (M1-M4)
- Create `scripts/taxonomy/inter_model_propagation.py` — 200 inter-model probes (IM1-IM3)
- Create `scripts/taxonomy/altered_delivery.py` — 200 altered delivery probes (AD1-AD3)
- Create `scripts/taxonomy/memory_persistence.py` — 200 memory/persistence probes (MP1-MP3)
- Expand `scripts/taxonomy/data_source_poisoning.py` — 200 ingestion probes (I1.5-I1.16)
- Create `scripts/taxonomy/benign_counterparts.py` — 200 FP-reduction benign samples
- Create `scripts/evaluate_probes.py` — evaluation harness with per-category metrics
- Add unit tests for `scripts/taxonomy/generate_taxonomy_samples.py` — metadata computation, deduplication, CSV schema validation
- Add unit tests for `scripts/taxonomy/merge_taxonomy_data.py` — enrichment logic, deduplication, non-taxonomy sample preservation
- Add unit tests for `scripts/evaluate_probes.py` — edge cases (0 samples, 100%/0% recall), JSON export format
- Add unit tests for `scripts/taxonomy/_buffs.py` — transformation correctness, encoding edge cases, round-trip invariants

## Implementation Plan
**Priority**: P1 (Sprint 6 — depends on Sprint 1 taxonomy)
**Timeline**: Week 8-10
**Target**: ≥85% recall, <5% FPR on benign counterparts
**Key Pattern**: Follow Garak's probe architecture (template expansion + parameterized payloads)
**Key Reference**: Garak (`leondz/garak`), HarmBench, JailbreakBench, AdvBench

---

# Layer 16 (NEW): Automation Pipeline

## Updated Description
NEW LAYER — not in original roadmap. Continuous automation for taxonomy updates, probe generation, threat intelligence monitoring, and regression testing. Integrates with MITRE ATLAS, Garak, AIID, and red-team frameworks.

## TODO List

### Done
- (None — No automation exists. All processes are manual)

### New (from research)
- Implement MITRE ATLAS data sync: periodically pull new techniques from ATLAS repository
- Add Garak integration: run Garak scans as part of CI/CD, import new probe patterns
- Implement AIID (AI Incident Database) polling: monitor for new real-world AI security incidents
- Integrate Microsoft PyRIT for automated red-teaming
- Add NVIDIA NeMo Red Team capabilities for automated attack generation
- Implement HarmBench automated evaluation pipeline
- Create GitHub Actions CI/CD workflow for automated testing on PR/push
- Add automated probe regeneration when taxonomy updates occur
- Implement model regression testing: compare new model version against previous on all probes
- Add Slack/email alerting for new threats discovered by monitoring pipelines
- Implement automated rule generation: convert new ATLAS techniques to detection rules
- Add dependency vulnerability scanning (LangChain CVEs, LlamaIndex vulnerabilities)
- Implement automated benchmark tracking: plot recall/precision trends over time
- Create nightly regression test suite with full probe evaluation
- Add supply chain monitoring: track updates to key security dependencies

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `scripts/automation/atlas_sync.py` — MITRE ATLAS data synchronization
- Create `scripts/automation/garak_runner.py` — Garak integration and result parsing
- Create `scripts/automation/aiid_poller.py` — AIID new incident monitoring
- Create `scripts/automation/red_team_harness.py` — automated red-team orchestration
- Create `.github/workflows/security_tests.yml` — CI/CD security testing pipeline
- Create `scripts/automation/regression_test.py` — model version comparison
- Create `scripts/integration_test.py` — full pipeline integration test

## Implementation Plan
**Priority**: P2 (Sprint 5-6)
**Timeline**: Week 8-12
**Key Tools**: Garak (leondz/garak), PyRIT (microsoft/pyrit), ATLAS, AIID
**Key Risk**: External API rate limits — need caching and backoff strategies
**Key Decision**: Start with GitHub Actions CI/CD, add monitoring pipelines incrementally

---

# Layer 17 (NEW): Inter-Model Propagation & Worm Defense

## Updated Description
NEW LAYER — not in original roadmap. Defends against attacks that propagate across multiple LLMs, agents, and tool chains. Covers the Morris II AI worm scenario, cross-model injection, multi-agent system attacks, and MCP tool poisoning. Maps to Pangea IM taxonomy (IM0003, IM0006, IM0007, IM0014, IM0015-16).

## TODO List

### Done
- (None — No inter-model security exists)

### New (from research)
- Implement worm signature detection: identify self-replicating prompt patterns (Morris II signatures)
- Add cross-model injection detection: flag outputs that contain viable injection for downstream models
- Implement trust decay scoring: trust decreases with each hop in multi-LLM pipeline
- Add tool-chain attack detection: validate tool call arguments and return values
- Implement MCP tool description poisoning detection: hidden instructions in tool descriptions
- Add agent impersonation detection: verify agent identity in multi-agent systems
- Implement delegation abuse detection: unauthorized privilege escalation across agents
- Add consensus poisoning detection: coordinated manipulation across multiple agents
- Implement shared context/memory poisoning detection: monitor for injection in shared state
- Add output-as-input isolation: sanitize LLM outputs before passing to next model
- Implement feedback loop detection: identify circular injection amplification
- Add tool description validation: hash-based integrity checking of tool schemas
- Implement invisible Unicode detection in MCP tool descriptions and parameters
- Add supply chain attack detection for agent frameworks (LangChain, AutoGPT, CrewAI)
- Implement multi-agent conversation monitoring: track trust levels across agent interactions

### Fixes
- N/A (layer doesn't exist yet)

### Remaining
- Create `src/propagation_scanner.py` — output propagation analysis (also serves L7)
- Create `src/worm_detector.py` — worm action + replication + self-reference patterns
- Create `src/chain_integrity.py` — multi-hop trust decay tracking
- Create `src/mcp_detector.py` — MCP tool description scanning
- Create `src/dual_scanner.py` — combined input + output + propagation orchestrator
- Create `tests/test_propagation_scanner.py`, `tests/test_worm_detector.py`, `tests/test_chain_integrity.py`, `tests/test_mcp_detector.py`

## Implementation Plan
**Priority**: P1 (Sprint 2-3)
**Timeline**: Week 4-6
**New files**: `src/propagation_scanner.py`, `src/worm_detector.py`, `src/chain_integrity.py`, `src/mcp_detector.py`, `src/dual_scanner.py`
**Key Reference**: "Here Comes The AI Worm" (Ben Nassi et al.) — Morris II self-replicating prompt
**Key Reference**: ServiceNow second-order prompt injection incident (2025)
**Maps to**: IM0003, IM0006, IM0007, IM0014, IM0015-16 (Pangea/CrowdStrike taxonomy)

---

# Sprint Plan (Revised)

## Sprint 1 — Taxonomy & Foundation (P0, Week 1-2)
| Task | File | Description |
|------|------|-------------|
| 1 | `data/taxonomy.yaml` | Full hierarchical taxonomy with M/IM/AD/I1/MP categories |
| 2 | `scripts/taxonomy/validate_taxonomy.py` | Taxonomy validation + coverage matrix |
| 3 | `src/normalizer.py` | NFKC + Unicode stripping + homoglyph detection |
| 4 | `data/rules.yaml` | Externalized rule definitions (50+ patterns) |
| 5 | `src/rule_engine.py` | Weighted rule engine with hot-reloading |
| 6 | Dataset integration | Add 5+ HuggingFace datasets to training pipeline |
| 6a | `data/datasets.yaml` | Declarative HF dataset registry with label mappings |
| 6b | `data/datasets.lock` | Lockfile tracking commit SHAs for reproducibility |
| 6c | `scripts/hf_sync.py` | SHA-based sync engine — only re-download changed datasets |
| 6d | `requirements.txt` | Add `datasets`, `huggingface_hub` as declared deps |

## Sprint 2 — Security Hardening & Core Detection (P0, Week 3-4)
| Task | File | Description |
|------|------|-------------|
| 7 | `src/llm_judge.py` | LLM judge with nonce verification + anti-injection |
| 7a | Port `llm_checker.py` | Cherry-pick from `feature/layer7-llama`, fix json_str bug + add timeout |
| 7b | Groq integration | Wire Groq API as LLM judge backend, add `.env` support |
| 8 | `src/cascade.py` | 4-stage cascade classifier with short-circuit |
| 8a | Wire `obfuscation.py` | Connect existing obfuscation module into inference pipeline |
| 9 | `src/obfuscation.py` | Expand with ROT13, leetspeak, Unicode tags, recursive decode |
| 10 | `src/classifier.py` | Unified classifier wrapping LogReg + DeBERTa |
| 11 | `src/propagation_scanner.py` | Output segmentation + per-segment classification |
| 12 | `src/worm_detector.py` | Worm action + replication pattern detection |
| 12a | Bug fixes | File handle leaks, pickle integrity, regex DoS, exception handling |
| 12b | `src/config.py` | Extract hardcoded magic numbers into central config |
| 12c | Logging | Add structured `logging` framework, replace `print()` statements |

## Sprint 3 — Multi-turn & Pipeline (P1, Week 5-6)
| Task | File | Description |
|------|------|-------------|
| 13 | `src/chain_integrity.py` | Multi-hop trust decay tracking |
| 14 | `src/dual_scanner.py` | Combined input + output orchestrator |
| 15 | `src/conversation_monitor.py` | Stateful multi-turn risk monitoring |
| 16 | `src/ingestion_validator.py` | Pre-ingestion RAG document scanning |
| 17 | `src/chunk_validator.py` | Per-chunk validation with boundary analysis |
| 18 | `src/mcp_detector.py` | MCP tool description poisoning detection |

## Sprint 4 — Document Formats (P1, Week 6-7)
| Task | File | Description |
|------|------|-------------|
| 19 | `src/document_scanner.py` | OOXML (DOCX/XLSX) scanning via zipfile |
| 20 | `src/csv_scanner.py` | CSV formula injection detection |
| 21 | `src/code_comment_scanner.py` | Multi-language code comment scanning |
| 22 | Magic byte expansion | File type validation via magic bytes |

## Sprint 5 — Integrity & Verification (P2, Week 7-8)
| Task | File | Description |
|------|------|-------------|
| 23 | `src/prompt_signer.py` | HMAC-SHA256 signing + nonce + replay protection |
| 24 | `src/template_integrity.py` | Template hash registry + verification |
| 25 | `src/canary.py` | Multi-type canary tokens + rotation + leak detection |
| 26 | `src/history_detector.py` | Fabricated conversation history detection |
| 27 | `src/embedding_integrity.py` | Outlier detection on embeddings |
| 28 | `src/vectordb_sanitizer.py` | Vector DB entry scanning + quarantine |

## Sprint 6 — Sample Generation & Llama Fine-tuning (P1, Week 8-10)
| Task | File | Description |
|------|------|-------------|
| 29 | `scripts/taxonomy/_base.py` | Probe base class + ClassifierOutput |
| 30 | `scripts/taxonomy/_core.py` | Template expansion engine |
| 31 | `scripts/taxonomy/multimodal_injection.py` | ~200 multimodal probes |
| 32 | `scripts/taxonomy/inter_model_propagation.py` | ~200 inter-model probes |
| 33 | `scripts/taxonomy/altered_delivery.py` | ~200 altered delivery probes |
| 34 | `scripts/taxonomy/memory_persistence.py` | ~200 memory/persistence probes |
| 35 | `scripts/taxonomy/data_source_poisoning.py` | ~200 ingestion probes |
| 36 | `scripts/taxonomy/benign_counterparts.py` | ~200 benign FP-reduction samples |
| 37 | `scripts/evaluate_probes.py` | Evaluation harness + metrics |
| 37a | `scripts/llama_finetune.py` | LoRA/QLoRA fine-tuning for Llama 3.2 1B/3B classifier |
| 37b | Feedback loop | Train → evaluate with probes → find gaps → generate data → retrain |
| 37c | Unit tests | Tests for generate_taxonomy_samples, merge_taxonomy_data, _buffs, evaluate_probes |

## Sprint 7 — Future/P3 (Week 10-14)
| Task | File | Description |
|------|------|-------------|
| 38 | `src/adversarial_detector.py` | Perplexity + distribution + pattern analysis |
| 39 | `src/image_scanner.py` | OCR + metadata scanning (Tesseract) |
| 40 | `src/audio_scanner.py` | Whisper transcription + scanning |
| 41 | `src/qr_scanner.py` | QR/barcode decode + scanning |
| 42 | `src/session_correlator.py` | Cross-session attack tracking |
| 43 | `src/agent_interceptor.py` | Agent-to-agent validation |
| 44 | `src/mcp_middleware.py` | MCP security middleware |
| 45 | Automation pipeline | ATLAS sync, Garak, AIID, CI/CD |
| 46 | `README.md` | Document Layer 0, taxonomy, probes, buffs, 17-layer architecture |
| 47 | Property-based testing | Hypothesis-based fuzzing for Layer 0/Layer 1 normalization |

---

# Dependency Graph

```
Sprint 1 (Taxonomy + Foundation) ──┬──→ Sprint 2 (Security + Core Detection)
                                   │         │
                                   │         ├──→ Sprint 3 (Pipeline + Multi-turn)
                                   │         │         │
                                   │         │         └──→ Sprint 4 (Document Formats)
                                   │         │
                                   │         └──→ Sprint 5 (Integrity + Verification)
                                   │
                                   └──→ Sprint 6 (Sample Generation)
                                   │
                                   └──→ Sprint 7 (Future/P3 + Automation)
```

**Hard Dependencies**:
- Sprint 1 must complete before Sprint 6 (taxonomy IDs needed for probes)
- Task 11 (PropagationScanner) before Task 14 (DualScanner)
- Layer 1 (Normalizer) before Layer 3 (ML Classifier input preprocessing)
- Layer 3 (Classifier) before Layer 9 (Ingestion uses classifier for scanning)

---

# Key Patterns to Reuse

| Pattern | Reference | Notes |
|---------|-----------|-------|
| Scanner result dataclass | Rebuff/Vigil | Standardize `ScanResult(is_suspicious, risk_score, flags, details)` |
| Multi-scanner consensus | Vigil | Require N-of-M scanners to agree (default: 3-of-5) |
| 4-layer defense | Rebuff | LLM + VectorDB + Canary + Heuristics |
| Probe base class | Garak | Template expansion with parameterized payloads |
| Cascade architecture | Lakera/Microsoft | Fast reject → ML → LLM escalation |
| NFKC + strip normalization | Cisco/OWASP | Pre-tokenization Unicode defense |

---

# Verification Plan

1. **After Sprint 1**: `python scripts/taxonomy/validate_taxonomy.py` — all IDs unique, references resolve
2. **After Sprint 2**: Unit tests for LLM judge, cascade, obfuscation, worm detector, propagation scanner
3. **After Sprint 3**: Unit tests for all pipeline scanners (chain, dual, conversation, ingestion, chunk, MCP)
4. **After Sprint 4**: Unit tests for document/CSV/code scanners + magic bytes
5. **After Sprint 5**: Unit tests for signing, template integrity, canary, history detector
6. **After Sprint 6**: `python scripts/evaluate_probes.py --taxonomy all --json` — target ≥85% recall, <5% FPR
7. **Integration**: `python scripts/integration_test.py` — full pipeline end-to-end with known attacks

---

# File Summary

| Category | Count | Details |
|----------|-------|---------|
| New src/ files | 22 | normalizer, rule_engine, classifier, llm_judge, cascade, config, output_scanner, propagation_scanner, worm_detector, canary, conversation_monitor, history_detector, ingestion_validator, chunk_validator, embedding_integrity, vectordb_sanitizer, document_scanner, csv_scanner, code_comment_scanner, prompt_signer, template_integrity, adversarial_detector |
| New src/ files (P3) | 6 | image_scanner, audio_scanner, qr_scanner, session_correlator, agent_interceptor, mcp_middleware |
| New test files | 18 | One per scanner/module |
| New probe files | 6 | multimodal, inter_model, altered_delivery, memory_persistence, data_source (extend), benign |
| New infra files | 5 | taxonomy.yaml, rules.yaml, cascade_config.yaml, validate_taxonomy.py, evaluate_probes.py |
| New data files | 2 | datasets.yaml (HF registry), datasets.lock (SHA tracking) |
| New scripts | 2 | hf_sync.py (dataset sync), llama_finetune.py (LoRA/QLoRA) |
| Modified files | 7 | obfuscation.py, predict.py, rules.py, features.py, model.py, dataset.py, requirements.txt |
| New heavy deps | 0 | All stdlib + existing deps (sklearn, numpy, scipy, pyyaml) |
| Optional deps | 7 | transformers (DeBERTa), Tesseract (OCR), Pillow (images), pyzbar (QR), trl + peft (Llama), datasets + huggingface_hub (HF) |

---

# Research Sources

## Datasets
- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) — 662 rows, Apache 2.0
- [xTRam1/safe-guard-prompt-injection](https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection) — 3K synthetic
- [facebook/cyberseceval3-visual-prompt-injection](https://huggingface.co/datasets/facebook/cyberseceval3-visual-prompt-injection) — multimodal
- [Harelix/Prompt-Injection-Mixed-Techniques-2024](https://huggingface.co/datasets/Harelix/Prompt-Injection-Mixed-Techniques-2024)
- [lakeraai/pint-benchmark](https://github.com/lakeraai/pint-benchmark) — 4,314 samples
- [qualifire/prompt-injections-benchmark](https://huggingface.co/datasets/qualifire/prompt-injections-benchmark) — diverse attack categories
- [reshabhs/SPML_Chatbot_Prompt_Injection](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) — chatbot-specific injection patterns
- [tatsu-lab/alpaca](https://huggingface.co/datasets/tatsu-lab/alpaca) — 2,000 safe instruction samples (for balance)
- [databricks/databricks-dolly-15k](https://huggingface.co/datasets/databricks/databricks-dolly-15k) — 2,000 safe instruction samples (for balance)
- [OpenAssistant/oasst1](https://huggingface.co/datasets/OpenAssistant/oasst1) — 1,000 prompter messages (for balance, needs label validation)

## Models
- [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) — 95.25% real-world
- [protectai/deberta-v3-small-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2) — smaller variant
- [qualifire/prompt-injection-sentinel](https://huggingface.co/qualifire/prompt-injection-sentinel) — 2025 SOTA

## Tools
- [protectai/rebuff](https://github.com/protectai/rebuff) — 4-layer defense (LLM + VectorDB + canary + heuristics)
- [deadbits/vigil-llm](https://github.com/deadbits/vigil-llm) — YARA + transformer + VectorDB multi-scanner
- [leondz/garak](https://github.com/leondz/garak) — LLM vulnerability scanner with probe architecture
- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) — comprehensive defense catalog
- [microsoft/pyrit](https://github.com/microsoft/pyrit) — automated red-teaming framework

## Standards & Frameworks
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/risk-management-framework)

## Key Papers
- Zou et al. 2023 — "Universal and Transferable Adversarial Attacks on Aligned LLMs" (GCG attack)
- Ben Nassi et al. 2024 — "Here Comes The AI Worm" (Morris II self-replicating prompt)
- Robey et al. 2023 — SmoothLLM: randomized smoothing defense (<1% attack success)
- Wichers et al. 2024 — Gradient-based red-teaming for safety-tuned models
- Beurer-Kellner et al. 2025 — "Design Patterns for Securing LLM Agents Against Prompt Injections"
- DMPI-PMHFE (Springer 2025) — DeBERTa + heuristic feature fusion for injection detection
- "Enhancing Security in LLM Applications" (arXiv 2506.19109) — Rebuff/Vigil/LLM Guard comparison

## Security Incidents
- Microsoft Copilot spear-phishing via hidden email commands (Q1 2025)
- Cisco DeepSeek R1 — 50/50 jailbreak success rate (2025)
- Brave Comet browser — indirect prompt injection via webpage summarization (Aug 2025)
- ServiceNow AI assistant — second-order prompt injection via agent delegation (2025)

---

# Llama Integration Architecture

> **Source**: Old to-do list — "How can my ideas sit together" analysis

HuggingFace, Taxonomy, and Llama are three layers of the same pipeline — not competing approaches:

```
         DATA                    MODEL                 EVALUATION
  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │ HuggingFace     │    │                 │    │ Taxonomy Probes │
  │  (safe prompts) │───▶│  Fine-tuned     │◀───│  (19 categories)│
  │                 │    │  Llama 3.2      │    │                 │
  │ Jailbreak DBs   │───▶│  1B or 3B      │    │ Buff mutations  │
  │  (attack data)  │    │                 │    │  (8 encodings)  │
  │                 │    │                 │    │                 │
  │ Taxonomy samples│───▶│                 │    │ Recall per      │
  │  (103+ techs)   │    │                 │    │  technique      │
  └─────────────────┘    └─────────────────┘    └─────────────────┘
        feeds                 replaces               tests it,
        training              LogReg                 finds gaps,
        data to...                                   generates more
                                                     training data
```

**The feedback loop**:
1. HuggingFace + jailbreak datasets → initial training corpus (safe vs. malicious)
2. Taxonomy generates additional attack samples covering techniques base data misses (103+ techniques)
3. Fine-tune Llama on all combined data
4. Evaluate fine-tuned model using taxonomy probes + buffs
5. Probes reveal gaps (e.g., "D5 unicode evasion: 12% recall") → generate more samples → retrain → repeat

**Data pipeline**:
```
generate_taxonomy_samples.py  ──▶  taxonomy_samples.csv (attack data)
                                         │
dataset.py (HF registry sync)  ──▶  hf_safe_prompts.csv (safe data)
                                         │
merge_taxonomy_data.py          ──▶  combined_data.csv
                                         │
                                    Format for Llama fine-tuning
                                    (instruction format, not TF-IDF)
                                         │
                                    Fine-tune script (LoRA/QLoRA)
                                         │
                                    evaluate_probes.py (test recall)
                                         │
                                    Gaps found → adjust taxonomy → repeat
```

**Model selection** (for classification, not generation):

| Model | Size | Fine-tuning | Inference | Recommendation |
|-------|------|-------------|-----------|----------------|
| Llama 3.2 1B | Tiny | Laptop GPU / free Colab | Fast, local | Best starting point |
| Llama 3.2 3B | Small | Single GPU | Fast, local | Good balance |
| Llama 3.1 8B + QLoRA | Medium | 1x A100 or Colab Pro | Needs GPU | Better accuracy |
| Llama 3.3 70B (Groq API) | Large | Expensive | API cost per call | Overkill for classification |

**What changes in architecture**:

| Layer | Current | After Integration |
|-------|---------|-------------------|
| Layer 0 | Input sanitization | Stays as-is — first line of defense |
| Classifier | TF-IDF + LogReg | Fine-tuned Llama (semantic, multilingual) |
| Rules | 5 hardcoded patterns | Keep as fast pre-filter, or fold into training data |
| Evaluation | Probe framework | Stays as-is — drives the retrain loop |

---

# Cross-Cutting Concerns

> **Source**: Old to-do list items that span multiple layers

## Code Quality & Safety
- Fix race condition in `tokenization.py` fingerprint store — add file locking + TTL pruning
- Extract hardcoded magic numbers into central config file — thresholds, limits, TF-IDF params, entropy cutoffs
- Add structured logging framework — replace debug `print()` statements across all modules with `logging` stdlib
- Resolve branch divergence: cherry-pick from `feature/layer7-llama` into current branch (do NOT merge — conflicts in predict.py, dataset.py, model.py)
- Reconcile `predict.py` signatures: `(label, prob, hits, llm_result)` vs `(label, prob, hits, l0)` → unify into `ScanResult`

## Documentation
- Update README.md — document Layer 0, taxonomy, probe system, buffs, full 17-layer architecture

## Test Infrastructure
- Add property-based testing (Hypothesis) for Layer 0/Layer 1 normalization
- Add unit tests for `generate_taxonomy_samples.py` — metadata computation, deduplication, CSV schema
- Add unit tests for `merge_taxonomy_data.py` — enrichment logic, deduplication, non-taxonomy preservation
- Add unit tests for `evaluate_probes.py` — edge cases (0 samples, 100%/0% recall), JSON export
- Add unit tests for `_buffs.py` — transformation correctness, edge cases, round-trips
- Expand `test_obfuscation.py` — hex decode, ROT13, nested encoding chains, entropy edge cases
- Add CI/CD pipeline — GitHub Actions for automated test runs + coverage reporting

---

# Audit Flags & Recommendations

## Conflicts Identified
1. **Sprint ordering**: Original plan puts Security Hardening (Sprint 2) before Taxonomy (Sprint 1), but taxonomy should come first since all scanners reference technique IDs
2. **DeBERTa dependency**: Adding DeBERTa as primary classifier adds `transformers` as a heavy dependency — conflicts with "zero new heavy dependencies" goal. **Recommendation**: Keep DeBERTa optional, maintain TF-IDF/LogReg as default
3. **Layer overlap**: Output Scanner (L7) and Inter-Model Propagation (L17) share `propagation_scanner.py` — should be single implementation used by both

## Gaps Identified
1. **No non-English support**: Current rules and training data are English-only. ProtectAI v2 explicitly notes this limitation
2. **No rate limiting/throttling**: No protection against high-volume scanning abuse
3. **No privacy controls**: Scanning user prompts raises privacy concerns — need configurable data retention
4. **No model monitoring**: No drift detection on classifier performance over time
5. **No rollback mechanism**: No way to quickly revert to previous model/rule version if new version introduces regressions
6. **No API layer**: No REST API or gRPC interface for production deployment
7. **Missing from plan**: Garak continuous testing integration should be Sprint 2, not Sprint 7
8. **Missing from plan**: Input paraphrasing defense (highly effective, low cost) not in any sprint
9. **No structured logging**: All modules use `print()` — no log levels, no structured output, no correlation IDs
10. **Branch divergence unresolved**: `feature/layer7-llama` has working HF + LLM checker code that conflicts with current branch — needs cherry-pick strategy
11. **No central config**: Magic numbers (entropy threshold 4.0, TF-IDF 5K features, punctuation 30%) are hardcoded across multiple files

## Questionable Recommendations
1. **40+ tasks in 7 sprints is ambitious** — consider splitting into phases with MVP milestones
2. **Sprint 6 sample generation** should run partially in parallel with Sprint 2-3 (probes help validate scanners during development)
3. **P3 items** (OCR, audio, QR) may never be needed — defer until real user demand exists
4. **Llama 3.2 1B recommended over 70B** — small fine-tuned model will outperform LogReg on semantic attacks while staying fast and local
5. **HF dataset registry (datasets.yaml)** should be implemented before any dataset integration — prevents code changes per dataset

# Changelog

## v0.1.0 — 2026-02-18

First public release of **Na0S** (formerly AI-Prompt-Injection-Detector).

### Highlights

- Multi-layer prompt injection detection pipeline with 12 defense layers
- Installable Python package: `pip install na0s`
- 1,680+ tests across 53 test files
- MIT licensed

### Layer 0 — Input Intake & Sanitization

- Unicode normalization, invisible character stripping, whitespace canonicalization
- Magic-bytes content-type sniffing, chardet-based encoding detection
- HTML extraction with hidden-content depth limiting
- MIME multipart parsing, OCR text extraction (optional Tesseract)
- Document extraction (PDF, DOCX, XLSX, PPTX)
- SSRF / open-redirect / TOCTOU protection in input loader
- Pre-decode guard for wide encodings (UTF-32, UTF-16)
- Language detection (langdetect) with graceful fallback
- PII screening (emails, phone numbers, SSNs, credit cards)
- Chunked ML analysis for large inputs
- Resource guard with configurable timeout enforcement
- SQLite-backed fingerprint store for deduplication
- Safe regex engine with timeout protection (no ReDoS)
- Property-based fuzz testing via Hypothesis (40 tests)

### Layer 3 — Structural Feature Extraction

- Token-level structural features for ML classification
- Weighted feature scoring

### Layer 4 — ML Classifier

- TF-IDF + Logistic Regression binary classifier
- Pre-trained model weights bundled in package (~424 KB)
- SHA-256 integrity checks for model files

### Layer 5 — Embedding Classifier

- Optional sentence-transformer embedding classifier
- Cosine similarity scoring against known attack patterns

### Layer 6 — Cascade Decision Engine

- Weighted voting across rule, obfuscation, ML, and structural signals
- Configurable confidence thresholds
- `ScanResult` dataclass with technique attribution and metadata

### Layer 7 — LLM Judge & Checker

- Optional LLM-based second opinion (Groq integration)
- JSON parse hardening for LLM responses

### Layer 8 — Positive Validation

- Legitimate use-case allowlisting

### Layer 9 — Output Scanner

- Secret detection (API keys, tokens, credentials)
- Role-break / prompt leakage detection in LLM outputs
- Configurable redaction

### Layer 10 — Canary Tokens

- Canary token generation and detection

### Layer 11 — Supply Chain Integrity

- Safe pickle loading with class allowlisting
- Model file SHA-256 verification

### Rule-Based Detection

- 19 threat categories, 103+ technique IDs (see `THREAT_TAXONOMY.md`)
- Context-aware rule suppression (educational, question, quoting, code, narrative frames)
- Override, system prompt, roleplay, secrecy, exfiltration pattern matching

### Obfuscation Detection

- Shannon entropy analysis (threshold 4.1)
- Casing transition ratio for alternating-case detection
- Punctuation flood detection with structured-data exemption
- Base64/hex/rot13 encoding detection
- Leetspeak and homoglyph normalization

### Testing

- 1,680+ unit and integration tests
- Attack coverage: D1 (instruction override), D3 (structural boundary), D4 (encoding), D5 (unicode evasion), D6 (multilingual), D7 (payload delivery), D8 (context manipulation), E1 (prompt extraction), E2 (reconnaissance), O1 (harmful content), C1 (compliance evasion), P1 (privacy leakage)
- False positive test suite with FingerprintStore isolation
- Cascade integration tests
- Output scanner tests
- Property-based fuzzing (Hypothesis)

### CI/CD

- GitHub Actions: lint, syntax check, test, coverage (Python 3.9–3.12)
- `fail-under=50` coverage gate

### Packaging

- `pyproject.toml` with setuptools backend
- Optional dependency groups: `embedding`, `ocr`, `docs`, `llm`, `all`, `dev`
- Typed package (`py.typed` marker)
- Source layout: `src/na0s/`

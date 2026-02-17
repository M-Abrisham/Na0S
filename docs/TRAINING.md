[← Back to main README](../README.md)

# Training Pipeline & Project Metrics

This page documents the technology stack, project statistics, and training data sources for the AI Prompt Injection Detector. The detector is trained on 126,245 samples spanning 19 attack categories, using a dual-classifier ML ensemble (TF-IDF + sentence embeddings).

---

## <img src="https://img.shields.io/badge/-TECH_STACK-F1C40F?style=for-the-badge&labelColor=1D3557" alt="" /> Tech Stack

<div align="center">

[![Tech Stack](https://skillicons.dev/icons?i=python,sklearn,tensorflow,docker,github,linux&theme=dark)](https://skillicons.dev)

<br/>

| Core | ML & NLP | Infrastructure |
|:----:|:--------:|:--------------:|
| Python 3.9-3.12 | scikit-learn | GitHub Actions CI |
| NumPy / Pandas | TF-IDF + Logistic Regression | Docker (planned) |
| tiktoken | MiniLM-L6-v2 Embeddings | Hypothesis Fuzzing |
| regex / re2 | GPT-4o / Llama-3.3 Judge | SHA-256 Integrity |

</div>

---

## <img src="https://img.shields.io/badge/-PROJECT_STATS-E63946?style=for-the-badge&labelColor=1D3557" alt="" /> Project Stats

<div align="center">
  <img src="../assets/rpg-stats.svg" alt="RPG Stats Card" width="500" />
</div>

<br/>

<div align="center">

| Metric | Value |
|--------|------:|
| Lines of Python | ~13,500 |
| Source modules | 38 |
| Test files | 24 |
| Test cases | 821+ |
| Training samples | 126,245 |
| Attack categories | 19 |
| Attack techniques | 103+ |
| Defense layers | 15 (5 planned) |
| Mutation transforms | 8 |
| Python versions | 3.9 - 3.12 |

</div>

<div align="center">
  <a href="https://github.com/M-Abrisham/AI-Prompt-Injection-Detector">
    <img src="https://streak-stats.demolab.com/?user=M-Abrisham&theme=tokyonight&hide_border=true" alt="GitHub Streak" />
  </a>
</div>

---

## Training Data

| Dataset | Source | Samples | Label |
|---------|--------|--------:|-------|
| Jailbreak prompts | [verazuo/jailbreak_llms](https://github.com/verazuo/jailbreak_llms) | ~15K | Malicious |
| Safe prompts | [awesome-chatgpt-prompts](https://github.com/f/awesome-chatgpt-prompts) | ~11K | Safe |
| Taxonomy-generated | 19-category probe framework | ~100K | Malicious |
| **Total** | | **126,245** | |

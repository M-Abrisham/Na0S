#!/usr/bin/env python3
"""Generate threat-coverage radar chart SVGs for the README.

Produces two variants:
  - assets/threat-radar.svg       (dark theme, GitHub-dark background)
  - assets/threat-radar-light.svg (light theme, white background)

Usage:
    python scripts/generate_readme_assets.py
"""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib
matplotlib.use("svg")  # non-interactive SVG backend

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

CATEGORIES: list[tuple[str, str, int]] = [
    ("D1", "Instruction Override",  95),
    ("D2", "Persona Hijack",       90),
    ("D3", "Structural Boundary",  85),
    ("D4", "Obfuscation",          70),
    ("D5", "Unicode Evasion",      95),
    ("D6", "Multilingual",         80),
    ("D7", "Payload Delivery",     75),
    ("D8", "Context Window",       80),
    ("E1", "Prompt Extraction",    90),
    ("E2", "Reconnaissance",       85),
    ("I1", "Data Poisoning",       75),
    ("I2", "Markup Injection",     85),
    ("A",  "Adversarial ML",       70),
    ("O",  "Output Manipulation",  80),
    ("T",  "Agent/Tool Abuse",     75),
    ("C",  "Compliance Evasion",   80),
    ("P",  "Privacy/Data Leak",    85),
    ("R",  "Resource/Avail.",      70),
    ("S",  "Supply Chain",         75),
]

LABELS = [f"{cid}  {name}" for cid, name, _ in CATEGORIES]
VALUES = [score for _, _, score in CATEGORIES]

# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------

DARK_THEME = {
    "bg":        "#0d1117",
    "grid":      "#30363d",
    "text":      "#c9d1d9",
    "title":     "#F1FAEE",
    "fill":      "#E63946",
    "fill_alpha": 0.30,
    "line":      "#E63946",
}

LIGHT_THEME = {
    "bg":        "#ffffff",
    "grid":      "#d0d7de",
    "text":      "#1f2328",
    "title":     "#1f2328",
    "fill":      "#E63946",
    "fill_alpha": 0.30,
    "line":      "#E63946",
}

# Font fallback chain (first available wins)
MONO_FONTS = ["Fira Code", "Consolas", "Courier New", "DejaVu Sans Mono", "monospace"]


def _pick_font() -> str:
    """Return the first monospace font available on this system."""
    import matplotlib.font_manager as fm
    available = {f.name for f in fm.fontManager.ttflist}
    for candidate in MONO_FONTS:
        if candidate in available:
            return candidate
    return "monospace"


# ---------------------------------------------------------------------------
# Chart builder
# ---------------------------------------------------------------------------

def generate_radar(theme: dict, output_path: str | Path) -> None:
    """Render a radar/spider chart and save it as SVG."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    font_family = _pick_font()
    n = len(VALUES)

    # Compute angles (evenly spaced around the circle)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()

    # Close the polygon: repeat the first value
    values_closed = VALUES + [VALUES[0]]
    angles_closed = angles + [angles[0]]

    # ---- Figure & polar axes -------------------------------------------------
    fig, ax = plt.subplots(
        figsize=(10, 10),
        subplot_kw={"projection": "polar"},
        dpi=150,
    )
    fig.patch.set_facecolor(theme["bg"])
    ax.set_facecolor(theme["bg"])

    # ---- Plot the filled area ------------------------------------------------
    ax.fill(
        angles_closed,
        values_closed,
        color=theme["fill"],
        alpha=theme["fill_alpha"],
    )
    ax.plot(
        angles_closed,
        values_closed,
        color=theme["line"],
        linewidth=2.0,
    )

    # Small dots at each vertex
    ax.scatter(
        angles,
        VALUES,
        color=theme["line"],
        s=30,
        zorder=5,
        edgecolors=theme["bg"],
        linewidths=0.5,
    )

    # ---- Grid rings ----------------------------------------------------------
    ring_levels = [20, 40, 60, 80, 100]
    ax.set_yticks(ring_levels)
    ax.set_yticklabels(
        [f"{v}%" for v in ring_levels],
        fontsize=7,
        color=theme["text"],
        fontfamily=font_family,
    )
    ax.set_ylim(0, 105)

    # Style grid lines
    ax.yaxis.grid(True, color=theme["grid"], linewidth=0.5, linestyle="--")
    ax.xaxis.grid(True, color=theme["grid"], linewidth=0.5, linestyle="--")

    # ---- Category labels (around the perimeter) ------------------------------
    ax.set_xticks(angles)
    ax.set_xticklabels(
        LABELS,
        fontsize=7.5,
        color=theme["text"],
        fontfamily=font_family,
    )

    # Push labels outward so they don't overlap the chart
    ax.tick_params(axis="x", pad=14)

    # ---- Spines / frame off --------------------------------------------------
    ax.spines["polar"].set_visible(False)

    # ---- Title ---------------------------------------------------------------
    ax.set_title(
        "Threat Coverage Radar",
        fontsize=18,
        fontweight="bold",
        color=theme["title"],
        fontfamily=font_family,
        pad=30,
    )

    # ---- Subtitle / watermark ------------------------------------------------
    fig.text(
        0.5,
        0.02,
        "19 Categories | 103+ Techniques",
        ha="center",
        va="bottom",
        fontsize=10,
        color=theme["text"],
        fontfamily=font_family,
        alpha=0.7,
    )

    # ---- Save ----------------------------------------------------------------
    fig.savefig(
        str(output_path),
        format="svg",
        transparent=False,
        facecolor=theme["bg"],
        bbox_inches="tight",
    )
    plt.close(fig)
    print(f"  Saved: {output_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    root = Path(__file__).resolve().parent.parent
    assets = root / "assets"

    print("Generating threat-coverage radar charts ...")
    generate_radar(DARK_THEME,  assets / "threat-radar.svg")
    generate_radar(LIGHT_THEME, assets / "threat-radar-light.svg")
    print("Done.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Draws the paper's diagrams as vector PDFs in paper/assets/.

The look follows the venue's papers: each stage on a pale tinted panel named in bold, white boxes with thin
outlines, cylinders for data, the released data in a pale green fill, one red accent for the repair loop,
Liberation Serif (metric-compatible with Times) for labels and Liberation Mono for code. Chart segments differ by
pattern as well as hue, so they stay distinct in a monochrome print. Sized for an IEEE two-column page. blindspot reads dataset/tables/, so run tools/common/aggregate.py first.

    python make_figures.py              # all figures
    python make_figures.py pipeline     # one figure, by name

Figures: pipeline (full width), evidence (one column), blindspot (one column).
"""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch, Patch, Rectangle

HERE = os.path.dirname(os.path.abspath(__file__))
TABLES = os.path.join(HERE, "..", "..", "dataset", "tables")
ASSETS = os.path.join(HERE, "..", "assets")
LIB = "/usr/share/fonts/truetype/liberation/"
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["hatch.linewidth"] = 0.35


def _font(name, size=None):
    path = LIB + name
    f = FontProperties(fname=path) if os.path.exists(path) else FontProperties(family="serif")
    if size:
        f.set_size(size)
    return f


REG = _font("LiberationSerif-Regular.ttf")
ITAL = _font("LiberationSerif-Italic.ttf")
BOLD = _font("LiberationSerif-Bold.ttf")
MONO = _font("LiberationMono-Regular.ttf")

EDGE = "#333333"
GREY = "#555555"
PANEL_A = "#EAF1FA"   # analysis stage
PANEL_V = "#FBF1E2"   # verification stage
DATA = "#D9EED5"      # released data
# Okabe-Ito, the colour-blind-safe qualitative set
BLUE, VERMILLION, ORANGE, PURPLE = "#0072B2", "#D55E00", "#E69F00", "#CC79A7"

COL = 3.45   # one IEEE column, inches
FULL = 7.16  # both columns


def new_ax(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return fig, ax


def text(ax, x, y, s, fs=7, font=None, color="black", ha="center", va="center", **kw):
    ax.text(x, y, s, ha=ha, va=va, color=color, fontsize=fs, fontproperties=font or REG, zorder=4, **kw)


def labels(ax, x, y, title, note, fs=7):
    """A title just above (x, y) and an italic note just below it."""
    ax.annotate(title, (x, y), xytext=(0, 2.6), textcoords="offset points", ha="center", va="bottom", fontsize=fs,
                fontproperties=REG, zorder=4)
    ax.annotate(note, (x, y), xytext=(0, 1.0), textcoords="offset points", ha="center", va="top", fontsize=fs - 1,
                fontproperties=ITAL, color=GREY, linespacing=1.1, zorder=4)


def box(ax, x, y, w, h, title, note="", fill="white", fs=6.5):
    ax.add_patch(Rectangle((x - w / 2, y - h / 2), w, h, linewidth=0.6, edgecolor=EDGE, facecolor=fill, zorder=2))
    if note:
        labels(ax, x, y, title, note, fs)
    else:
        text(ax, x, y, title, fs=fs)


def cylinder(ax, x, y, w, h, title, note="", fill=DATA, fs=6.5, ry=2.8):
    """A data store: a body with an elliptical top and bottom."""
    ax.add_patch(Rectangle((x - w / 2, y - h / 2 + ry / 2), w, h - ry, linewidth=0, facecolor=fill, zorder=2))
    ax.add_patch(Ellipse((x, y - h / 2 + ry / 2), w, ry, linewidth=0.6, edgecolor=EDGE, facecolor=fill, zorder=2))
    ax.add_patch(Rectangle((x - w / 2, y - h / 2 + ry / 2), w, h - ry, linewidth=0, facecolor=fill, zorder=2))
    for sx in (-1, 1):
        ax.plot([x + sx * w / 2] * 2, [y - h / 2 + ry / 2, y + h / 2 - ry / 2], color=EDGE, lw=0.6, zorder=3)
    ax.add_patch(Ellipse((x, y + h / 2 - ry / 2), w, ry, linewidth=0.6, edgecolor=EDGE, facecolor=fill, zorder=3))
    labels(ax, x, y - ry / 4, title, note, fs) if note else text(ax, x, y - ry / 4, title, fs=fs)


def arrow(ax, x1, y1, x2, y2, head=True, dashed=False, lw=0.6, color=EDGE):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>" if head else "-", mutation_scale=6,
                                 linewidth=lw, color=color, zorder=1, shrinkA=0, shrinkB=0,
                                 linestyle=(0, (3, 2)) if dashed else "solid"))


def panel(ax, x0, y0, x1, y1, fill, name):
    """A pale tinted stage, named in bold at its top left."""
    ax.add_patch(FancyBboxPatch((x0, y0), x1 - x0, y1 - y0, boxstyle="round,pad=0,rounding_size=1.2",
                                linewidth=0, facecolor=fill, zorder=0))
    text(ax, x0 + 1, y1 - 1.2, name, fs=6.5, font=BOLD, ha="left", va="top")


def save(fig, name):
    os.makedirs(ASSETS, exist_ok=True)
    fig.savefig(os.path.join(ASSETS, f"{name}.pdf"), bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print("saved", name)


# ------------------------------------------------------------------------------------ pipeline
def pipeline():
    """Analysis along the top, verification back along the bottom, repair from the verdicts to the writer."""
    fig, ax = new_ax(0.8 * FULL, 1.95)
    W, H = 16.5, 21.5
    TOP, BOT = 72, 23.5
    xs = [9, 29, 50, 71, 91]

    panel(ax, 0, 51, 100, 100, PANEL_A, "Analysis")
    text(ax, 99, 98.8, "No package code is installed or run", fs=5.5, font=ITAL, color=GREY, ha="right",
         va="top")
    panel(ax, 0, 0, 100, 48, PANEL_V, "Verification")

    cylinder(ax, xs[0], TOP, W, H + 2, "Malware corpora", "Datadog, malregistry\nstratified sample", fill="white")
    box(ax, xs[1], TOP, W, H, "Preparation", "unpacking and\ngate candidates")
    box(ax, xs[2], TOP, W, H, "LLM analyst", "one sandboxed\nsession per package")
    box(ax, xs[3], TOP, W, H, "Record writer", "schema check and\nanchor re-hashing")
    cylinder(ax, xs[4], TOP, W, H + 2, "Records", "one per campaign")
    for a, b in zip(xs, xs[1:]):
        arrow(ax, a + W / 2, TOP, b - W / 2, TOP)
    # samples that need no judgement leave the preparation step as skip or member records
    arrow(ax, xs[1], TOP - H / 2, xs[1], TOP - H / 2 - 3.5)
    text(ax, xs[1], TOP - H / 2 - 5.8, "skip and member records", fs=5.5, font=ITAL, color=GREY)

    box(ax, xs[4], BOT, W, H, "Checker", "rebuild and decoder\nreplay (L1–L5)")
    box(ax, xs[3], BOT, W, H, "Blinded packets", "claim and\ncited code only")
    box(ax, xs[2], BOT, W, H, "LLM reviewers", "Claude and GPT\nfamilies, blinded")
    box(ax, xs[1], BOT, W, H, "Sidecars", "append-only\none per verifier")
    cylinder(ax, xs[0], BOT, W, H + 2, "Release", "JSON Lines tables")
    arrow(ax, xs[4], TOP - H / 2 - 1, xs[4], BOT + H / 2)
    arrow(ax, xs[4] - W / 2, BOT, xs[3] + W / 2, BOT)
    arrow(ax, xs[3] - W / 2, BOT, xs[2] + W / 2, BOT)
    arrow(ax, xs[2] - W / 2, BOT, xs[1] + W / 2, BOT)
    arrow(ax, xs[1] - W / 2, BOT, xs[0] + W / 2, BOT)
    # the checker's own verdicts go straight to the sidecars, under the review boxes
    arrow(ax, xs[4], BOT - H / 2, xs[4], 3.0, head=False)
    arrow(ax, xs[4], 3.0, xs[1], 3.0, head=False)
    arrow(ax, xs[1], 3.0, xs[1], BOT - H / 2)
    # repair: refuted or disputed claims go back to the writer, and the changed claims are verified again
    rx = xs[1] + 4
    arrow(ax, rx, BOT + H / 2, rx, 41, head=False, dashed=True, color=VERMILLION, lw=0.8)
    arrow(ax, rx, 41, xs[3] - 3, 41, head=False, dashed=True, color=VERMILLION, lw=0.8)
    arrow(ax, xs[3] - 3, 41, xs[3] - 3, TOP - H / 2, dashed=True, color=VERMILLION, lw=0.8)
    text(ax, (rx + xs[3]) / 2, 42.3, "repair of refuted or disputed claims", fs=5.5, font=ITAL,
         color=VERMILLION, va="bottom")
    save(fig, "pipeline")


# ------------------------------------------------------------------------------------ evidence
def evidence():
    """How a claim about obfuscated code is checked: four steps top to bottom, and on each arrow the check
    the verifier repeats from the original archive. Code and hashes are set in mono."""
    FS = 6.5
    steps = [
        ("Published file", [("bun_environment.js", MONO), ("One obfuscated line, 24,237-entry string table", REG)]),
        ("Derived file d1", [("Strings restored by the recorded decoder,", REG),
                             ("with its input and output hash", REG)]),
        ("Anchor in d1", [("bytes 9315033–9315150, if_statement", MONO), ("sha256 3f1bee52...", MONO)]),
        ("Gate g1", [("GITHUB_ACTIONS && RUNNER_OS == Linux", MONO), ("&& Harden-Runner agent && sudo -n", MONO),
                     ("Stops systemd-resolved and flushes iptables", REG)]),
    ]
    checks = ["Decoder replay and output hash check", "Byte extraction and hash check",
              "Claim checked against the code"]
    # the vertical axis is in points, so padding and line pitch are exact at the printed size
    PAD, TITLE, LINE, GAP = 4.0, 8.6, 7.3, 12.0
    hs = [2 * PAD + TITLE + len(body) * LINE for _, body in steps]
    total = sum(hs) + GAP * (len(hs) - 1) + 2
    fig, ax = plt.subplots(figsize=(COL * 0.84, total / 72))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total)
    ax.axis("off")
    X0, W, BADGE, TX = 0.5, 99, 6.5, 13.5
    y = total - 1
    for i, ((head, body), h) in enumerate(zip(steps, hs)):
        last = i == len(steps) - 1
        ax.add_patch(Rectangle((X0, y - h), W, h, linewidth=0.6, edgecolor=EDGE,
                               facecolor=DATA if last else "white", zorder=2))
        # the step number sits in a badge centred on the box's height
        text(ax, X0 + BADGE, y - h / 2, str(i + 1), fs=FS - 0.5, font=BOLD, color="white",
             bbox={"boxstyle": "circle,pad=0.22", "facecolor": BLUE, "edgecolor": "none"})
        text(ax, X0 + TX, y - PAD, head, fs=FS, font=BOLD, ha="left", va="top")
        for k, (line, font) in enumerate(body):
            text(ax, X0 + TX, y - PAD - TITLE - k * LINE, line, fs=FS - (0.9 if font is MONO else 0.4),
                 font=font, ha="left", va="top")
        if not last:
            arrow(ax, X0 + BADGE, y - h, X0 + BADGE, y - h - GAP, color=BLUE)
            text(ax, X0 + TX, y - h - GAP / 2, checks[i], fs=FS - 0.5, font=ITAL, color=GREY, ha="left")
        y -= h + GAP
    save(fig, "evidence")


# ------------------------------------------------------------------------------------ blindspot
def rows(name):
    with open(os.path.join(TABLES, name), encoding="utf-8") as f:
        return list(csv.DictReader(f))


PROFILES = [("ossf-package-analysis", "OpenSSF"), ("docker-default", "Stock Docker"),
            ("github-ubuntu", "GitHub Ubuntu"), ("github-windows", "GitHub Windows"),
            ("github-macos", "GitHub macOS")]


def blindspot():
    """Gated campaigns by outcome under each documented environment profile, each campaign counted once."""
    small = _font("LiberationSerif-Regular.ttf", 6.5)
    fig, ax = plt.subplots(figsize=(COL, 1.39))
    blind = {r["profile"]: r for r in rows("blindspot.csv") if r["unit"] == "campaign" and r["weighting"] == "none"}
    parts = [("open", "Open", "#006B4F", ""), ("closed", "Closed", "#F6D5C3", "////"),
             ("unknown", "Unknown", "white", "....."), ("not_expressible", "Not expressible", "#CFE6F5", "xxxx")]
    for i, (key, _) in enumerate(PROFILES):
        x0 = 0.0
        for col, _, color, hatch in parts:
            w = float(blind[key][f"share_{col}"])
            ax.barh(i, w, left=x0, height=0.72, facecolor=color, edgecolor="black", linewidth=0.35, hatch=hatch)
            x0 += w
        opened = float(blind[key]["share_open"])
        ax.text(opened / 2, i, f"{100 * opened:.0f}%", ha="center", va="center_baseline", color="white",
                fontproperties=_font("LiberationSerif-Bold.ttf", 6))
    ax.set_yticks(range(len(PROFILES)), [lab for _, lab in PROFILES])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1], ["0", "25%", "50%", "75%", "100%"])
    ax.set_xlabel("Gated campaigns", fontproperties=small)
    handles = [Patch(facecolor=c, edgecolor="black", linewidth=0.35, hatch=h, label=n) for _, n, c, h in parts]
    fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False, prop=small, handlelength=1.6,
               columnspacing=0.9, handletextpad=0.35, bbox_to_anchor=(0.5, 0.0))
    ax.tick_params(length=2, width=0.4)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_linewidth(0.5)
    for t in ax.get_xticklabels() + ax.get_yticklabels():
        t.set_fontproperties(small)
    fig.tight_layout(pad=0.15, rect=(0, 0.12, 1, 1))
    save(fig, "blindspot")


ALL = {f.__name__: f for f in (pipeline, evidence, blindspot)}

if __name__ == "__main__":
    for name in sys.argv[1:] or list(ALL):
        if name not in ALL:
            sys.exit(f"unknown figure {name!r}, choose from {', '.join(ALL)}")
        ALL[name]()

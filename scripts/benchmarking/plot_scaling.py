#!/usr/bin/env python3
"""
Plot a tls_bench_ablation scaling sweep in USENIX figure style.

Reads CSV produced by:
    ./target/release/tls_bench_ablation \\
        --csv-header --all-backends \\
        --pairs-sweep "1,2,4,8,16,32" \\
        --batch-size 65536 --rounds 64 --warmup 1 --runs 3

Emits:
    - <basename>.pdf  (vector, for paper inclusion)
    - <basename>.png  (raster preview, useful as a CI artifact)

Usage (from repo root):
    uv run --project scripts/benchmarking \\
        python scripts/benchmarking/plot_scaling.py <csv> [<basename>]

If `<basename>` is omitted, the input CSV's stem is used.
"""

import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless / CI

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


# USENIX papers are typically two-column at ~7" wide; single-column figures are
# ~3.3". A four-line plot reads cleanly at single-column with sans-serif and
# minimal chartjunk.
plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 9,
        "axes.labelsize": 10,
        "axes.titlesize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8,
        "figure.dpi": 200,
        "axes.linewidth": 0.7,
        "lines.linewidth": 1.4,
        "lines.markersize": 5,
        "pdf.fonttype": 42,  # embed as TrueType so reviewers can edit if needed
        "ps.fonttype": 42,
    }
)


# Backend CSV name -> human-facing legend label, in the order requested.
LABELS = {
    "tcp": "TCP in Rust",
    "rustls": "TLS in Rust",
    "fizz_cpp": "Delegated TLS in C++ Fizz+Folly",
    "fizz": "Tahini in Rust",
}

# Distinct markers + linestyles + colors so the figure remains readable in
# black-and-white print.
STYLES = {
    "tcp": {"marker": "o", "linestyle": "-", "color": "#444444"},
    "rustls": {"marker": "s", "linestyle": "--", "color": "#1f77b4"},
    "fizz_cpp": {"marker": "^", "linestyle": "-.", "color": "#2ca02c"},
    "fizz": {"marker": "D", "linestyle": ":", "color": "#d62728"},
}

ORDER = ["rustls", "fizz_cpp", "fizz"]


def load(csv_path: Path):
    """Returns dict[backend] -> list of (pairs, mb_per_s) sorted by pairs."""
    data: dict[str, list[tuple[int, float]]] = {}
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            backend = row.get("backend", "").strip()
            mbps_str = row.get("mb_per_s", "").strip()
            pairs_str = row.get("pairs", "").strip()
            if not backend or not mbps_str or not pairs_str:
                continue
            try:
                pairs = int(pairs_str)
                mbps = float(mbps_str)
            except ValueError:
                # Error rows have empty mb_per_s; skip them.
                continue
            data.setdefault(backend, []).append((pairs, mbps))
    for k in data:
        data[k].sort()
    return data


def plot(data, base_path: Path):
    fig, ax = plt.subplots(figsize=(3.5, 2.6))

    plotted_any = False
    for backend in ORDER:
        if backend not in data or not data[backend]:
            continue
        xs = [p for p, _ in data[backend]]
        ys = [m for _, m in data[backend]]
        ax.plot(xs, ys, label=LABELS.get(backend, backend), **STYLES[backend])
        plotted_any = True

    if not plotted_any:
        sys.stderr.write("error: no plottable backend rows in CSV\n")
        sys.exit(1)

    all_pairs = sorted({p for series in data.values() for p, _ in series})
    if all_pairs:
        ax.set_xticks(all_pairs)

    # Both axes anchored at zero per spec; linear x so the origin is meaningful.
    ax.set_xlim(left=0)
    
    ax.set_ylim(bottom=0)

    ax.set_xlabel("Concurrent connections (N)")
    ax.set_ylabel("Throughput (MB/s)")

    ax.legend(loc="best", frameon=False, handlelength=2.5)
    ax.grid(True, axis="y", linestyle=":", linewidth=0.4, alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout(pad=0.3)

    pdf = base_path.with_suffix(".pdf")
    png = base_path.with_suffix(".png")
    fig.savefig(pdf, bbox_inches="tight", pad_inches=0.02)
    fig.savefig(png, bbox_inches="tight", pad_inches=0.02)
    sys.stderr.write(f"wrote {pdf}\nwrote {png}\n")


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__ or "")
        sys.exit(2)
    csv_path = Path(argv[1])
    if len(argv) > 2:
        base_path = Path(argv[2])
    else:
        base_path = csv_path.with_suffix("")
    plot(load(csv_path), base_path)


if __name__ == "__main__":
    main(sys.argv)

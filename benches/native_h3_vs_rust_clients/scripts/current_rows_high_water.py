#!/usr/bin/env python3
"""High-water comparison helpers for native H3 selected-row artifacts.

Scout stamps remain non-publishable; this module only makes the active GET
blocker math machine-readable so every iteration can report percent behind or
ahead without hand-maintained ledger arithmetic.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


WORKLOAD = "http3_streaming_get"
SPECTER = "specter_native"
REFERENCE = "quiche_direct"
RAW_THROUGHPUT = "bytes_per_sec"
LEDGER_THROUGHPUT = "ledger_paced_bytes_per_sec"
REQUIRED_HIGH_WATER_METRICS = (
    "p50_ttfb_ns",
    "p95_ttfb_ns",
    RAW_THROUGHPUT,
    LEDGER_THROUGHPUT,
)

# Historical portable-main n100 baseline, used only when no explicit high-water doc exists.
DEFAULT_HIGH_WATER = {
    "kind": "native_h3_get_high_water",
    "workload": WORKLOAD,
    "source": "historical portable-main n100 baseline (2026-06-07; iteration artifacts pruned 2026-06-09)",
    "specter_native": {
        "p50_ttfb_ns": 56_230.0,
        "p95_ttfb_ns": 68_117.0,
        "bytes_per_sec": 9.347 * 1024 * 1024,
        "ledger_paced_bytes_per_sec": 9.347 * 1024 * 1024,
    },
    "quiche_direct": {
        "p50_ttfb_ns": 47_415.0,
        "p95_ttfb_ns": 62_889.0,
        "bytes_per_sec": 9.300 * 1024 * 1024,
        "ledger_paced_bytes_per_sec": 9.300 * 1024 * 1024,
    },
}


def validate_high_water(doc: dict[str, Any], source: str) -> dict[str, Any]:
    if doc.get("kind") != "native_h3_get_high_water":
        raise ValueError(f"high-water document has invalid kind: {source}")
    if doc.get("workload") != WORKLOAD:
        raise ValueError(f"high-water document has invalid workload: {source}")
    if not isinstance(doc.get("source"), str) or not doc.get("source"):
        raise ValueError(f"high-water document is missing source: {source}")
    for client in (SPECTER, REFERENCE):
        block = doc.get(client)
        if not isinstance(block, dict):
            raise ValueError(f"high-water document missing {client}: {source}")
        for metric in REQUIRED_HIGH_WATER_METRICS:
            value = block.get(metric)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(
                    f"high-water document missing numeric {client}.{metric}: {source}"
                )
    return doc


def load_high_water(path: str | None) -> dict[str, Any]:
    if path:
        candidate = Path(path)
        if candidate.is_file():
            with candidate.open() as f:
                doc = json.load(f)
            if isinstance(doc, dict):
                return validate_high_water(doc, path)
            raise ValueError(f"high-water document is not an object: {path}")
        raise FileNotFoundError(f"explicit high-water path does not exist: {path}")
    return validate_high_water(DEFAULT_HIGH_WATER, "DEFAULT_HIGH_WATER")


def lower_is_better_percent_behind(specter: float, reference: float) -> float:
    if reference == 0:
        return 0.0
    return ((specter - reference) / reference) * 100.0


def higher_is_better_percent_behind(specter: float, reference: float) -> float:
    if reference == 0:
        return 0.0
    return ((reference - specter) / reference) * 100.0


def metric_delta(current: float, high_water: float) -> float:
    return current - high_water


def has_numeric_metric(row: dict[str, Any], key: str) -> bool:
    value = row.get(key)
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def choose_throughput_metric(
    specter: dict[str, Any], reference: dict[str, Any], preferred: str | None = None
) -> str:
    if (
        preferred
        and has_numeric_metric(specter, preferred)
        and has_numeric_metric(reference, preferred)
    ):
        return preferred
    if has_numeric_metric(specter, LEDGER_THROUGHPUT) and has_numeric_metric(
        reference, LEDGER_THROUGHPUT
    ):
        return LEDGER_THROUGHPUT
    return RAW_THROUGHPUT


def metric_value(row: dict[str, Any], key: str) -> float:
    return float(row[key])


def current_metric_block(row: dict[str, Any], throughput_metric: str) -> dict[str, float]:
    block = {
        "p50_ttfb_ns": float(row["p50_ttfb_ns"]),
        "p95_ttfb_ns": float(row["p95_ttfb_ns"]),
        throughput_metric: float(row[throughput_metric]),
    }
    if throughput_metric != RAW_THROUGHPUT and has_numeric_metric(row, RAW_THROUGHPUT):
        block[RAW_THROUGHPUT] = float(row[RAW_THROUGHPUT])
    if throughput_metric != LEDGER_THROUGHPUT and has_numeric_metric(row, LEDGER_THROUGHPUT):
        block[LEDGER_THROUGHPUT] = float(row[LEDGER_THROUGHPUT])
    return block


def strict_comparison(
    specter: dict[str, Any],
    reference: dict[str, Any],
    high_water: dict[str, Any],
    *,
    artifact_set_sha256: str | None = None,
    raw_samples_set_sha256: str | None = None,
    publication_eligible: bool,
    non_publishable: bool,
    throughput_metric: str | None = None,
) -> dict[str, Any]:
    throughput_metric = choose_throughput_metric(specter, reference, throughput_metric)
    current = {
        "specter_native": current_metric_block(specter, throughput_metric),
        "quiche_direct": current_metric_block(reference, throughput_metric),
    }
    hw_specter = high_water[SPECTER]
    hw_reference = high_water[REFERENCE]
    strict_percent_behind = {
        "p50_ttfb_ns": lower_is_better_percent_behind(
            current["specter_native"]["p50_ttfb_ns"],
            current["quiche_direct"]["p50_ttfb_ns"],
        ),
        "p95_ttfb_ns": lower_is_better_percent_behind(
            current["specter_native"]["p95_ttfb_ns"],
            current["quiche_direct"]["p95_ttfb_ns"],
        ),
        throughput_metric: higher_is_better_percent_behind(
            current["specter_native"][throughput_metric],
            current["quiche_direct"][throughput_metric],
        ),
    }
    if (
        throughput_metric != RAW_THROUGHPUT
        and RAW_THROUGHPUT in current["specter_native"]
        and RAW_THROUGHPUT in current["quiche_direct"]
    ):
        strict_percent_behind["raw_bytes_per_sec_diagnostic"] = higher_is_better_percent_behind(
            current["specter_native"][RAW_THROUGHPUT],
            current["quiche_direct"][RAW_THROUGHPUT],
        )
    delta_vs_high_water = {
        "specter_native": {
            "p50_ttfb_ns": metric_delta(
                current["specter_native"]["p50_ttfb_ns"], float(hw_specter["p50_ttfb_ns"])
            ),
            "p95_ttfb_ns": metric_delta(
                current["specter_native"]["p95_ttfb_ns"], float(hw_specter["p95_ttfb_ns"])
            ),
            throughput_metric: metric_delta(
                current["specter_native"][throughput_metric],
                metric_value(hw_specter, throughput_metric),
            ),
        },
        "quiche_direct": {
            "p50_ttfb_ns": metric_delta(
                current["quiche_direct"]["p50_ttfb_ns"], float(hw_reference["p50_ttfb_ns"])
            ),
            "p95_ttfb_ns": metric_delta(
                current["quiche_direct"]["p95_ttfb_ns"], float(hw_reference["p95_ttfb_ns"])
            ),
            throughput_metric: metric_delta(
                current["quiche_direct"][throughput_metric],
                metric_value(hw_reference, throughput_metric),
            ),
        },
    }
    return {
        "kind": "native_h3_get_high_water_comparison",
        "workload": WORKLOAD,
        "reference_client": REFERENCE,
        "candidate_client": SPECTER,
        "publication_eligible": publication_eligible,
        "non_publishable": non_publishable,
        "artifact_set_sha256": artifact_set_sha256,
        "raw_samples_set_sha256": raw_samples_set_sha256,
        "throughput_metric": throughput_metric,
        "high_water": high_water,
        "current": current,
        "strict_percent_behind": strict_percent_behind,
        "delta_vs_high_water": delta_vs_high_water,
    }


def attach_pair_high_water_comparison(doc: dict[str, Any], high_water_path: str | None = None) -> None:
    edges = doc.get("edges")
    if not isinstance(edges, dict) or not edges:
        return
    runs = doc.get("runs")
    artifact_set_sha256 = None
    raw_samples_set_sha256 = None
    if isinstance(runs, list) and runs:
        artifact_set_sha256 = ",".join(
            str(run.get("artifact_set_sha256")) for run in runs if isinstance(run, dict)
        )
        raw_samples_set_sha256 = ",".join(
            str(run.get("raw_samples_set_sha256")) for run in runs if isinstance(run, dict)
        )
    throughput_metric = str(edges.get("throughput_metric", RAW_THROUGHPUT))
    specter = {
        "p50_ttfb_ns": edges["specter_worst_p50_ttfb_ns"],
        "p95_ttfb_ns": edges["specter_worst_p95_ttfb_ns"],
        throughput_metric: edges["specter_worst_bytes_per_sec"],
    }
    reference = {
        "p50_ttfb_ns": edges["quiche_direct_best_p50_ttfb_ns"],
        "p95_ttfb_ns": edges["quiche_direct_best_p95_ttfb_ns"],
        throughput_metric: edges["quiche_direct_best_bytes_per_sec"],
    }
    comparison = strict_comparison(
        specter,
        reference,
        load_high_water(high_water_path),
        artifact_set_sha256=artifact_set_sha256,
        raw_samples_set_sha256=raw_samples_set_sha256,
        publication_eligible=bool(doc.get("publication_eligible")),
        non_publishable=bool(doc.get("non_publishable")),
        throughput_metric=throughput_metric,
    )
    doc["high_water_comparison"] = comparison


def attach_selected_rows_high_water_comparison(
    doc: dict[str, Any], high_water_path: str | None = None
) -> None:
    rows = doc.get("selected_rows")
    if not isinstance(rows, list):
        return
    by_id = {
        row.get("competitor_id"): row
        for row in rows
        if isinstance(row, dict) and row.get("workload") == WORKLOAD
    }
    specter = by_id.get(SPECTER)
    reference = by_id.get(REFERENCE)
    if not isinstance(specter, dict) or not isinstance(reference, dict):
        return
    artifact_sha256 = doc.get("artifact_sha256")
    artifact_set_sha256 = None
    if isinstance(artifact_sha256, dict):
        artifact_set_sha256 = ",".join(
            str(artifact_sha256.get(client)) for client in (SPECTER, REFERENCE)
        )
    raw_samples_set_sha256 = ",".join(
        str(row.get("raw_samples_sha256")) for row in (specter, reference)
    )
    comparison = strict_comparison(
        specter,
        reference,
        load_high_water(high_water_path),
        artifact_set_sha256=artifact_set_sha256,
        raw_samples_set_sha256=raw_samples_set_sha256,
        publication_eligible=bool(doc.get("publication_eligible")),
        non_publishable=bool(doc.get("non_publishable")),
    )
    doc["high_water_comparison"] = comparison


def summary_from_stamp(path: Path) -> dict[str, Any]:
    with path.open() as f:
        stamp = json.load(f)
    recomputed = {
        "publication_eligible": stamp.get("publication_eligible"),
        "non_publishable": stamp.get("non_publishable"),
        "artifact_sha256": stamp.get("artifact_sha256"),
        "selected_rows": stamp.get("selected_rows"),
    }
    high_water_path = stamp.get("high_water_path")
    attach_selected_rows_high_water_comparison(
        recomputed,
        high_water_path if isinstance(high_water_path, str) and high_water_path else None,
    )
    if stamp.get("high_water_comparison") != recomputed.get("high_water_comparison"):
        return {
            "has_high_water_comparison": False,
            "stamp": str(path),
            "error": "high_water_comparison_mismatch",
        }
    comparison = stamp.get("high_water_comparison")
    if not isinstance(comparison, dict):
        return {"has_high_water_comparison": False, "stamp": str(path)}
    return {
        "has_high_water_comparison": True,
        "stamp": str(path),
        "publication_eligible": comparison.get("publication_eligible"),
        "non_publishable": comparison.get("non_publishable"),
        "strict_percent_behind": comparison.get("strict_percent_behind"),
        "delta_vs_high_water": comparison.get("delta_vs_high_water"),
        "throughput_metric": comparison.get("throughput_metric"),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stamp", required=True, help="stamp JSON to summarize")
    parser.add_argument("--high-water", help="optional high-water JSON override")
    args = parser.parse_args(argv)
    # --high-water is accepted by the runner so a future file can override the
    # default baseline. Stamp comparison is written by the parsers.
    _ = load_high_water(args.high_water)
    print(json.dumps(summary_from_stamp(Path(args.stamp)), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

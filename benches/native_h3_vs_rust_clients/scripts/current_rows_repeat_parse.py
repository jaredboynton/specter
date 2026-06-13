#!/usr/bin/env python3
"""Repeat/worst-of-N gate for native_h3 selected-row artifacts.

Each input must be either a selected-row archive directory or its manifest JSON
file. Every run is first validated with the same structural contract as
current_rows_parse.py: manifest, provenance, selected clients, sample/warmup
counts, payload sizes, and measured rows. Only then does this script compare
metrics across repeats.

The repeat pass is intentionally stricter than one-run comparison: Specter's
worst latency and workload-specific completion metric across all repeats must
still meet or beat each comparator's best corresponding metric across all
repeats.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import current_rows_parse as one


def _canonical_path(value: Any) -> Any:
    """Resolve symlinks so a raw temp path and its resolved form compare equal.

    macOS symlinks /var -> /private/var, so the raw path the stamp records at
    generation and the resolved path replay derives name the same file yet differ
    as strings. Linux has no such symlink, so this is a no-op there.
    """
    if isinstance(value, str) and value:
        try:
            return str(Path(value).resolve())
        except OSError:
            return value
    return value


SPECTER_BY_WORKLOAD = {
    "http3_streaming_get": "specter_native",
    "websocket_over_h3_raw_tunnel_echo": "specter_native_rfc9220_tunnel",
    "websocket_over_h3_raw_tunnel_close_fin": "specter_native_rfc9220_tunnel_close",
    "slow_consumer_tunnel_plus_http3_streaming": "specter_native_rfc9220_tunnel_mixed",
}


def manifest_for_input(raw: str) -> tuple[Path | None, list[str]]:
    path = Path(raw)
    failures: list[str] = []
    if path.is_dir():
        manifests = sorted(path.glob("*.manifest.json"))
        if len(manifests) != 1:
            failures.append(
                f"FAIL repeat_manifest_count input={path} count={len(manifests)}"
            )
            return None, failures
        return manifests[0], failures
    if path.is_file() and path.name.endswith(".manifest.json"):
        return path, failures
    failures.append(f"FAIL repeat_input_not_archive_or_manifest input={raw}")
    return None, failures


def artifact_paths_for_manifest(
    manifest_path: Path, required_rows: tuple[str, ...] = one.REQUIRED_ROWS
) -> list[str]:
    prefix = str(manifest_path)[: -len(".manifest.json")]
    return [f"{prefix}.{client}.json" for client in required_rows]


def artifact_set_sha256(artifact_paths: list[str]) -> str:
    h = hashlib.sha256()
    for raw_path in sorted(artifact_paths):
        path = Path(raw_path)
        h.update(str(path.name).encode())
        h.update(b"\0")
        if path.is_file():
            h.update(one.file_sha256(path).encode())
        else:
            h.update(b"MISSING")
        h.update(b"\0")
    return h.hexdigest()


def raw_samples_set_sha256(rows: dict[str, dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for competitor_id in sorted(rows):
        h.update(competitor_id.encode())
        h.update(b"\0")
        h.update(str(one.raw_samples_sha256(rows[competitor_id])).encode())
        h.update(b"\0")
    return h.hexdigest()


def load_valid_run(
    raw: str, min_samples: int, *, get_only: bool = False
) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    manifest_path, manifest_failures = manifest_for_input(raw)
    failures.extend(manifest_failures)
    if manifest_path is None:
        return None, failures

    required_rows = one.GET_REQUIRED if get_only else one.REQUIRED_ROWS
    workloads = one.GET_ONLY_WORKLOADS if get_only else one.WORKLOADS
    artifact_paths = artifact_paths_for_manifest(manifest_path, required_rows)
    run_failures, _expected_artifact_by_client, manifest_info, measured_required = (
        one.evaluate_selected_rows(
            artifact_paths,
            str(manifest_path),
            min_samples,
            emit_rows=False,
            required_rows=required_rows,
            workloads=workloads,
            publication_eligible=not get_only,
            get_only_gate=get_only,
            compare_metrics=False,
        )
    )
    failures.extend(run_failures)

    if failures:
        return None, failures

    return {
        "input": raw,
        "manifest": manifest_info,
        "manifest_resolved_path": str(manifest_path.resolve()),
        "artifact_set_sha256": artifact_set_sha256(artifact_paths),
        "raw_samples_set_sha256": raw_samples_set_sha256(measured_required),
        "rows": measured_required,
    }, failures


def duplicate_identity_failures(runs: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    identity_groups: dict[str, dict[str, list[int]]] = {
        "manifest_path": defaultdict(list),
        "manifest_sha256": defaultdict(list),
        "artifact_set_sha256": defaultdict(list),
        "raw_samples_set_sha256": defaultdict(list),
    }
    for run_index, run in enumerate(runs, start=1):
        manifest = run["manifest"]
        identity_groups["manifest_path"][str(run.get("manifest_resolved_path"))].append(run_index)
        identity_groups["manifest_sha256"][str(manifest.get("sha256"))].append(run_index)
        identity_groups["artifact_set_sha256"][str(run.get("artifact_set_sha256"))].append(run_index)
        identity_groups["raw_samples_set_sha256"][str(run.get("raw_samples_set_sha256"))].append(run_index)

    for label, groups in identity_groups.items():
        for value, run_indexes in groups.items():
            if len(run_indexes) > 1:
                runs_csv = ",".join(str(index) for index in run_indexes)
                failures.append(f"FAIL repeat_duplicate_{label} value={value} runs={runs_csv}")
    return failures


def cohort_identity_failures(runs: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    if not runs:
        return failures
    def normalized_runtime_env(manifest: dict[str, Any]) -> str:
        runtime_env = dict(manifest.get("runtime_env") or {})
        if runtime_env.get("FIXTURE_LEDGER_GATE") == "1":
            runtime_env["SPECTER_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR"] = "<per-repeat>"
        return json.dumps(runtime_env, sort_keys=True, separators=(",", ":"))

    keys = (
        "binary_sha256",
        "git_head",
        "git_dirty",
        "target",
        "profile",
        "features",
        "runtime_profile",
        "samples",
        "warmups",
        "selected_clients_sha256",
        "scout_gate",
        "publication_eligible",
        "get_only_gate",
    )
    baseline = runs[0]["manifest"]
    for run_index, run in enumerate(runs[1:], start=2):
        manifest = run["manifest"]
        for key in keys:
            if manifest.get(key) != baseline.get(key):
                failures.append(
                    f"FAIL repeat_cohort_identity run={run_index} {key} "
                    f"expected={baseline.get(key)} actual={manifest.get(key)}"
                )
        expected_runtime_env = normalized_runtime_env(baseline)
        actual_runtime_env = normalized_runtime_env(manifest)
        if actual_runtime_env != expected_runtime_env:
            failures.append(
                "FAIL repeat_cohort_identity "
                f"run={run_index} runtime_env expected={expected_runtime_env} actual={actual_runtime_env}"
            )
    return failures


def get_abba_order_failures(runs: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    if not runs:
        return failures
    if len(runs) % 4 != 0:
        failures.append(f"FAIL repeat_abba_run_count count={len(runs)} multiple=4")
    canonical = list(one.GET_REQUIRED)
    reverse = list(reversed(canonical))
    expected_cycle = (canonical, reverse, reverse, canonical)
    for run_index, run in enumerate(runs, start=1):
        expected = expected_cycle[(run_index - 1) % 4]
        actual = run["manifest"].get("run_order")
        if actual != expected:
            failures.append(
                "FAIL repeat_abba_run_order "
                f"run={run_index} expected={','.join(expected)} actual={','.join(actual or [])}"
            )
    return failures


def collect_by_workload(runs: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    by_workload: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for run_index, run in enumerate(runs, start=1):
        for competitor_id, row in run["rows"].items():
            row = dict(row)
            row["_run_index"] = run_index
            workload = row.get("workload")
            if isinstance(workload, str):
                by_workload[workload][competitor_id].append(row)
    return {workload: dict(rows) for workload, rows in by_workload.items()}


def worst_latency(rows: list[dict[str, Any]], metric: str) -> float:
    return max(float(row[metric]) for row in rows)


def best_latency(rows: list[dict[str, Any]], metric: str) -> float:
    return min(float(row[metric]) for row in rows)


def worst_throughput(rows: list[dict[str, Any]], metric: str) -> float:
    return min(float(row[metric]) for row in rows)


def best_throughput(rows: list[dict[str, Any]], metric: str) -> float:
    return max(float(row[metric]) for row in rows)


def worst_paced_overhead(rows: list[dict[str, Any]], metric: str) -> float:
    return max(float(row[metric]) for row in rows)


def best_paced_overhead(rows: list[dict[str, Any]], metric: str) -> float:
    return min(float(row[metric]) for row in rows)


def ms(ns: float) -> str:
    return f"{ns / 1_000_000:.6f}ms"


def mibps(bps: float) -> str:
    return f"{bps / 1_048_576:.6f}MiB/s"


def compare_repeats(
    runs: list[dict[str, Any]],
    *,
    workloads: dict[str, tuple[str, ...]] = one.WORKLOADS,
) -> tuple[list[str], list[dict[str, Any]]]:
    failures: list[str] = []
    edges: list[dict[str, Any]] = []
    by_workload = collect_by_workload(runs)
    for workload, competitor_ids in workloads.items():
        specter_id = SPECTER_BY_WORKLOAD[workload]
        specter_rows = by_workload.get(workload, {}).get(specter_id, [])
        if len(specter_rows) != len(runs):
            failures.append(
                f"FAIL repeat_missing_specter workload={workload} count={len(specter_rows)}"
            )
            continue
        is_get = workload == "http3_streaming_get"
        ledger_gate = is_get and (
            one.fixture_ledger_gate_enabled(runs[0]["manifest"])
            or one.fixture_ledger_required(runs[0]["manifest"])
        )
        throughput_metric = (
            "ledger_paced_bytes_per_sec" if ledger_gate else "bytes_per_sec"
        )
        throughput_label = (
            "ledger_paced_MiB/s" if ledger_gate else "MiB/s"
        )
        throughput_failure_label = (
            "ledger_paced_throughput" if ledger_gate else "throughput"
        )
        sp_p50_worst = worst_latency(specter_rows, "p50_ttfb_ns")
        sp_p95_worst = worst_latency(specter_rows, "p95_ttfb_ns")
        sp_tput_worst = worst_throughput(specter_rows, throughput_metric)
        if is_get:
            p50_tail_metric = (
                "p50_ledger_paced_tail_overhead_ns"
                if ledger_gate
                else "p50_paced_tail_overhead_ns"
            )
            p95_tail_metric = (
                "p95_ledger_paced_tail_overhead_ns"
                if ledger_gate
                else "p95_paced_tail_overhead_ns"
            )
            sp_p50_tail_worst = worst_paced_overhead(
                specter_rows, p50_tail_metric
            )
            sp_p95_tail_worst = worst_paced_overhead(
                specter_rows, p95_tail_metric
            )
        print(
            f"=== {workload} {specter_id} worst "
            f"p50={ms(sp_p50_worst)} p95={ms(sp_p95_worst)} "
            f"{throughput_label}={mibps(sp_tput_worst)}"
        )
        if is_get:
            print(
                f"    paced_tail_overhead p50={ms(sp_p50_tail_worst)} "
                f"p95={ms(sp_p95_tail_worst)}"
            )
        for competitor_id in competitor_ids:
            if competitor_id == specter_id:
                continue
            comp_rows = by_workload.get(workload, {}).get(competitor_id, [])
            if len(comp_rows) != len(runs):
                failures.append(
                    f"FAIL repeat_missing_comparator workload={workload} "
                    f"competitor={competitor_id} count={len(comp_rows)}"
                )
                continue
            comp_p50_best = best_latency(comp_rows, "p50_ttfb_ns")
            comp_p95_best = best_latency(comp_rows, "p95_ttfb_ns")
            comp_tput_best = best_throughput(comp_rows, throughput_metric)
            if is_get:
                comp_p50_tail_best = best_paced_overhead(
                    comp_rows, p50_tail_metric
                )
                comp_p95_tail_best = best_paced_overhead(
                    comp_rows, p95_tail_metric
                )
            edge = {
                "workload": workload,
                "specter_id": specter_id,
                "competitor_id": competitor_id,
                "specter_worst_p50_ttfb_ns": sp_p50_worst,
                "competitor_best_p50_ttfb_ns": comp_p50_best,
                "specter_worst_p95_ttfb_ns": sp_p95_worst,
                "competitor_best_p95_ttfb_ns": comp_p95_best,
                "throughput_metric": throughput_metric,
                "specter_worst_bytes_per_sec": sp_tput_worst,
                "competitor_best_bytes_per_sec": comp_tput_best,
            }
            if is_get:
                p50_tail_edge_key = f"specter_worst_{p50_tail_metric}"
                comp_p50_tail_edge_key = f"competitor_best_{p50_tail_metric}"
                p95_tail_edge_key = f"specter_worst_{p95_tail_metric}"
                comp_p95_tail_edge_key = f"competitor_best_{p95_tail_metric}"
                edge.update(
                    {
                        p50_tail_edge_key: sp_p50_tail_worst,
                        comp_p50_tail_edge_key: comp_p50_tail_best,
                        p95_tail_edge_key: sp_p95_tail_worst,
                        comp_p95_tail_edge_key: comp_p95_tail_best,
                    }
                )
            edges.append(edge)
            print(
                f"  vs {competitor_id:38s} "
                f"best_p50={ms(comp_p50_best)} best_p95={ms(comp_p95_best)} "
                f"best_{throughput_label}={mibps(comp_tput_best)}"
            )
            if is_get:
                print(
                    f"      best_paced_tail_overhead p50={ms(comp_p50_tail_best)} "
                    f"p95={ms(comp_p95_tail_best)}"
                )
            if sp_p50_worst > comp_p50_best:
                failures.append(
                    f"FAIL_REPEAT {workload} {specter_id} worst_p50 "
                    f"{sp_p50_worst:.0f} > {competitor_id} best_p50 {comp_p50_best:.0f}"
                )
            if sp_p95_worst > comp_p95_best:
                failures.append(
                    f"FAIL_REPEAT {workload} {specter_id} worst_p95 "
                    f"{sp_p95_worst:.0f} > {competitor_id} best_p95 {comp_p95_best:.0f}"
                )
            if is_get:
                if sp_p50_tail_worst > comp_p50_tail_best:
                    failures.append(
                        f"FAIL_REPEAT {workload} {specter_id} worst_{p50_tail_metric.removesuffix('_ns')} "
                        f"{sp_p50_tail_worst:.0f} > {competitor_id} "
                        f"best_{p50_tail_metric.removesuffix('_ns')} {comp_p50_tail_best:.0f}"
                    )
                if sp_p95_tail_worst > comp_p95_tail_best:
                    failures.append(
                        f"FAIL_REPEAT {workload} {specter_id} worst_{p95_tail_metric.removesuffix('_ns')} "
                        f"{sp_p95_tail_worst:.0f} > {competitor_id} "
                        f"best_{p95_tail_metric.removesuffix('_ns')} {comp_p95_tail_best:.0f}"
                    )
            if sp_tput_worst < comp_tput_best:
                failures.append(
                    f"FAIL_REPEAT {workload} {specter_id} worst_{throughput_failure_label} "
                    f"{sp_tput_worst:.0f} < {competitor_id} best_{throughput_failure_label} {comp_tput_best:.0f}"
                )
    return failures, edges


def remove_truth_stamp(path: str | None) -> None:
    if not path:
        return
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return


def write_truth_stamp(
    path: str,
    runs: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    get_only: bool = False,
) -> None:
    stamp_path = Path(path)
    if stamp_path.parent != Path("."):
        stamp_path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "kind": (
            "native_h3_get_rows_repeat_truth_pass"
            if get_only
            else "native_h3_selected_rows_repeat_truth_pass"
        ),
        "non_publishable": get_only,
        "publication_eligible": not get_only,
        "scout_gate": False,
        "get_only_gate": get_only,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser_path": str(Path(__file__)),
        "parser_sha256": one.file_sha256(Path(__file__)),
        "single_run_parser_path": str(Path(one.__file__)),
        "single_run_parser_sha256": one.file_sha256(Path(one.__file__)),
        "run_count": len(runs),
        "run_identities": [
            {
                "input": run.get("input"),
                "manifest_resolved_path": run.get("manifest_resolved_path"),
                "manifest": run["manifest"],
                "artifact_set_sha256": run.get("artifact_set_sha256"),
                "raw_samples_set_sha256": run.get("raw_samples_set_sha256"),
            }
            for run in runs
        ],
        "aggregate_edges": edges,
        "exit_code": 0,
    }
    with stamp_path.open("w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def verify_truth_stamp(path: str, min_runs: int, min_samples: int) -> list[str]:
    stamp_path = Path(path)
    try:
        stamp = one.load_json_strict(stamp_path)
    except FileNotFoundError:
        return [f"FAIL missing_repeat_truth_stamp: {path}"]
    except json.JSONDecodeError as exc:
        return [
            f"FAIL invalid_repeat_truth_stamp_json: {path} line={exc.lineno} "
            f"column={exc.colno} msg={exc.msg}"
        ]
    except ValueError as exc:
        return [f"FAIL invalid_repeat_truth_stamp_json: {path} msg={exc}"]
    except OSError as exc:
        return [f"FAIL unreadable_repeat_truth_stamp: {path} error={exc}"]
    if not isinstance(stamp, dict):
        return [f"FAIL invalid_repeat_truth_stamp document_type={type(stamp).__name__}"]

    failures: list[str] = []
    kind = stamp.get("kind")
    if kind == "native_h3_get_rows_repeat_truth_pass":
        get_only = True
        workloads = one.GET_ONLY_WORKLOADS
        publication_eligible = False
    else:
        get_only = False
        workloads = one.WORKLOADS
        publication_eligible = True
    if kind not in (
        "native_h3_selected_rows_repeat_truth_pass",
        "native_h3_get_rows_repeat_truth_pass",
    ):
        failures.append(f"FAIL repeat_truth_stamp_kind kind={stamp.get('kind')}")
    if stamp.get("publication_eligible") is not publication_eligible:
        failures.append(
            "FAIL repeat_truth_stamp_publication_eligible "
            f"publication_eligible={one.json_value(stamp.get('publication_eligible'))}"
        )
    if stamp.get("scout_gate") is not False:
        failures.append(
            "FAIL repeat_truth_stamp_scout_gate "
            f"scout_gate={one.json_value(stamp.get('scout_gate'))}"
        )
    if stamp.get("get_only_gate", False) is not get_only:
        failures.append(
            "FAIL repeat_truth_stamp_get_only_gate "
            f"get_only_gate={one.json_value(stamp.get('get_only_gate'))}"
        )
    if stamp.get("exit_code") != 0:
        failures.append(f"FAIL repeat_truth_stamp_exit_code exit_code={stamp.get('exit_code')}")

    current_parser_sha256 = one.file_sha256(Path(__file__))
    if stamp.get("parser_sha256") != current_parser_sha256:
        failures.append(
            "FAIL repeat_truth_stamp_parser_sha256 "
            f"expected={current_parser_sha256} actual={stamp.get('parser_sha256')}"
        )
    current_single_parser_sha256 = one.file_sha256(Path(one.__file__))
    if stamp.get("single_run_parser_sha256") != current_single_parser_sha256:
        failures.append(
            "FAIL repeat_truth_stamp_single_run_parser_sha256 "
            f"expected={current_single_parser_sha256} "
            f"actual={stamp.get('single_run_parser_sha256')}"
        )

    run_identities = stamp.get("run_identities")
    if not isinstance(run_identities, list):
        failures.append("FAIL repeat_truth_stamp_run_identities type=non_list")
        run_identities = []
    stamped_run_count = stamp.get("run_count")
    if stamped_run_count != len(run_identities):
        failures.append(
            "FAIL repeat_truth_stamp_run_count "
            f"expected={len(run_identities)} actual={stamped_run_count}"
        )
    if len(run_identities) < min_runs:
        failures.append(
            f"FAIL repeat_truth_stamp_min_runs count={len(run_identities)} min_runs={min_runs}"
        )

    replayed_runs: list[dict[str, Any]] = []
    for index, identity in enumerate(run_identities, start=1):
        if not isinstance(identity, dict):
            failures.append(f"FAIL repeat_truth_stamp_run_identity_type run={index}")
            continue
        manifest_path = identity.get("manifest_resolved_path")
        if not isinstance(manifest_path, str) or not manifest_path:
            failures.append(
                f"FAIL repeat_truth_stamp_manifest_path run={index} actual={manifest_path}"
            )
            continue
        run, run_failures = load_valid_run(manifest_path, min_samples, get_only=get_only)
        failures.extend(
            f"REPEAT_TRUTH_STAMP_REPLAY run={index} {failure}"
            for failure in run_failures
        )
        if run is None:
            continue
        replayed_runs.append(run)
        checks = {
            "manifest_resolved_path": run.get("manifest_resolved_path"),
            "artifact_set_sha256": run.get("artifact_set_sha256"),
            "raw_samples_set_sha256": run.get("raw_samples_set_sha256"),
        }
        for key, expected in checks.items():
            if identity.get(key) != expected:
                failures.append(
                    f"FAIL repeat_truth_stamp_run_identity run={index} {key} "
                    f"expected={expected} actual={identity.get(key)}"
                )
        stamped_manifest = identity.get("manifest")
        if not isinstance(stamped_manifest, dict):
            failures.append(f"FAIL repeat_truth_stamp_manifest run={index} type=non_object")
        else:
            for key in (
                "path",
                "sha256",
                "binary_sha256",
                "selected_clients_sha256",
                "run_order",
                "run_order_sha256",
                "run_order_declared",
                "git_head",
                "git_dirty",
                "target",
                "profile",
                "features",
                "runtime_profile",
                "runtime_env_sha256",
                "samples",
                "warmups",
                "scout_gate",
                "publication_eligible",
                "get_only_gate",
            ):
                expected = run["manifest"].get(key)
                actual = stamped_manifest.get(key)
                if key == "path":
                    if _canonical_path(expected) != _canonical_path(actual):
                        failures.append(
                            f"FAIL repeat_truth_stamp_manifest run={index} {key} "
                            f"expected={expected} actual={actual}"
                        )
                    continue
                if actual != expected:
                    failures.append(
                        f"FAIL repeat_truth_stamp_manifest run={index} {key} "
                        f"expected={expected} actual={actual}"
                    )

    failures.extend(duplicate_identity_failures(replayed_runs))
    failures.extend(cohort_identity_failures(replayed_runs))
    if get_only:
        failures.extend(get_abba_order_failures(replayed_runs))
    if len(replayed_runs) == len(run_identities) and replayed_runs:
        metric_failures, edges = compare_repeats(replayed_runs, workloads=workloads)
        failures.extend(f"REPEAT_TRUTH_STAMP_REPLAY {failure}" for failure in metric_failures)
        if stamp.get("aggregate_edges") != edges:
            failures.append("FAIL repeat_truth_stamp_aggregate_edges_mismatch")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="*", help="selected-row archive dirs or manifest files")
    parser.add_argument(
        "--min-runs",
        type=int,
        default=3,
        help="minimum independent runs required for repeat pass claims",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=one.HARD_MIN_SAMPLES,
        help="minimum samples per selected row; never lower than 100",
    )
    parser.add_argument(
        "--truth-stamp",
        help="write this JSON stamp only when every repeat and worst-of-N comparison passes",
    )
    parser.add_argument(
        "--verify-truth-stamp",
        help="verify an existing repeat truth-pass stamp by replaying every run and aggregate edge",
    )
    parser.add_argument(
        "--get-only",
        action="store_true",
        help="validate non-publishable repeated GET-only runs instead of the full publication row set",
    )
    args = parser.parse_args(argv)
    min_samples = max(args.min_samples, one.HARD_MIN_SAMPLES)
    workloads = one.GET_ONLY_WORKLOADS if args.get_only else one.WORKLOADS

    if args.verify_truth_stamp:
        if args.truth_stamp or args.runs or args.get_only:
            print(
                "FAIL repeat_verify_truth_stamp_exclusive: pass only "
                "--verify-truth-stamp, --min-runs, and --min-samples"
            )
            return 1
        failures = verify_truth_stamp(args.verify_truth_stamp, args.min_runs, min_samples)
        print("=== REPEAT TRUTH STAMP")
        if failures:
            for failure in failures:
                print(failure)
            return 1
        print("PASS")
        return 0

    failures: list[str] = []
    if len(args.runs) < args.min_runs:
        failures.append(f"FAIL repeat_run_count count={len(args.runs)} min_runs={args.min_runs}")

    valid_runs: list[dict[str, Any]] = []
    for raw in args.runs:
        run, run_failures = load_valid_run(raw, min_samples, get_only=args.get_only)
        failures.extend(run_failures)
        if run is not None:
            valid_runs.append(run)

    failures.extend(duplicate_identity_failures(valid_runs))
    failures.extend(cohort_identity_failures(valid_runs))
    if args.get_only:
        failures.extend(get_abba_order_failures(valid_runs))

    if len(valid_runs) == len(args.runs):
        metric_failures, edges = compare_repeats(valid_runs, workloads=workloads)
        failures.extend(metric_failures)
    else:
        edges = []

    if failures:
        remove_truth_stamp(args.truth_stamp)
        for failure in failures:
            print(failure)
        return 1

    if args.truth_stamp:
        write_truth_stamp(args.truth_stamp, valid_runs, edges, get_only=args.get_only)
    print("PASS repeat selected-row worst-of-N gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

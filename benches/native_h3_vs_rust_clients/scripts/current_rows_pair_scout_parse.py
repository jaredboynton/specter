#!/usr/bin/env python3
"""Non-publishable paired-repeat scout for the native H3 GET bottleneck.

This parser is intentionally stricter than the one-shot SCOUT_GATE stamp:
Specter's worst repeat must meet or beat quiche_direct's best repeat on p50,
p95, and ledger-paced throughput. It is also intentionally non-publishable; a candidate
stamp only authorizes a full selected-row publication gate run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import current_rows_parse as one
import current_rows_high_water as high_water


def _canonical_path(value: Any) -> Any:
    """Resolve symlinks so a raw temp path and its resolved form compare equal.

    Generation passes raw manifest paths; verify replays via manifest_resolved_path.
    macOS symlinks /var -> /private/var, so those name the same file yet differ as
    strings, producing a spurious provenance mismatch on macOS only. No-op on Linux.
    """
    if isinstance(value, str) and value:
        try:
            return str(Path(value).resolve())
        except OSError:
            return value
    return value


PAIR_CLIENTS = ("specter_native", "quiche_direct")
WORKLOAD = "http3_streaming_get"


def artifact_set_sha256(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.name):
        h.update(path.name.encode())
        h.update(b"\0")
        if path.is_file():
            h.update(one.file_sha256(path).encode())
        else:
            h.update(b"MISSING")
        h.update(b"\0")
    return h.hexdigest()


def raw_samples_set_sha256(rows: dict[str, dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for client in sorted(rows):
        h.update(client.encode())
        h.update(b"\0")
        h.update(str(one.raw_samples_sha256(rows[client])).encode())
        h.update(b"\0")
    return h.hexdigest()


def load_manifest(path: Path, repeat_index: int, repeat_count: int, min_samples: int) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    try:
        manifest = one.load_json_strict(path)
    except FileNotFoundError:
        return None, [f"FAIL missing_manifest path={path}"]
    except json.JSONDecodeError as exc:
        return None, [f"FAIL invalid_manifest_json path={path} line={exc.lineno} column={exc.colno} msg={exc.msg}"]
    except ValueError as exc:
        return None, [f"FAIL invalid_manifest_json path={path} msg={exc}"]
    except OSError as exc:
        return None, [f"FAIL unreadable_manifest path={path} error={exc}"]
    if not isinstance(manifest, dict):
        return None, [f"FAIL invalid_manifest_root path={path}"]

    expected_order = list(PAIR_CLIENTS if repeat_index % 2 == 1 else reversed(PAIR_CLIENTS))
    selected_clients = manifest.get("selected_clients")
    if selected_clients != expected_order:
        failures.append(
            f"FAIL pair_selected_clients repeat={repeat_index} expected={expected_order} actual={selected_clients}"
        )
    if manifest.get("kind") != "native_h3_selected_rows_manifest":
        failures.append(f"FAIL pair_manifest_kind repeat={repeat_index} kind={manifest.get('kind')}")
    if manifest.get("scout_gate") is not True:
        failures.append(f"FAIL pair_manifest_scout_gate repeat={repeat_index} value={manifest.get('scout_gate')}")
    if manifest.get("publication_eligible") is not False:
        failures.append(
            f"FAIL pair_manifest_publication_eligible repeat={repeat_index} value={manifest.get('publication_eligible')}"
        )
    if manifest.get("paired_scout") is not True:
        failures.append(f"FAIL pair_manifest_paired_scout repeat={repeat_index} value={manifest.get('paired_scout')}")
    if manifest.get("scout_repeat_index") != repeat_index:
        failures.append(
            f"FAIL pair_manifest_repeat_index repeat={repeat_index} value={manifest.get('scout_repeat_index')}"
        )
    if manifest.get("scout_repeat_count") != repeat_count:
        failures.append(
            f"FAIL pair_manifest_repeat_count repeat={repeat_index} value={manifest.get('scout_repeat_count')}"
        )
    if manifest.get("run_order") != expected_order:
        failures.append(f"FAIL pair_manifest_run_order repeat={repeat_index} value={manifest.get('run_order')}")

    actual_sha = one.selected_clients_sha256(selected_clients if isinstance(selected_clients, list) else [])
    if manifest.get("selected_clients_sha256") != actual_sha:
        failures.append(
            f"FAIL pair_manifest_selected_clients_sha256 repeat={repeat_index} expected={actual_sha} actual={manifest.get('selected_clients_sha256')}"
        )
    samples = manifest.get("samples")
    if not isinstance(samples, int) or samples < min_samples:
        failures.append(f"FAIL pair_manifest_samples repeat={repeat_index} samples={samples} min={min_samples}")
    warmups = manifest.get("warmups")
    if not isinstance(warmups, int):
        failures.append(f"FAIL pair_manifest_warmups repeat={repeat_index} warmups={warmups}")
    for key in ("binary_sha256", "git_head", "target", "profile", "features"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            failures.append(f"FAIL pair_manifest_{key} repeat={repeat_index}")
    if not isinstance(manifest.get("git_head"), str) or not one.GIT_HEAD_RE.fullmatch(manifest.get("git_head", "")):
        failures.append(f"FAIL pair_manifest_git_head repeat={repeat_index} value={manifest.get('git_head')}")
    if not isinstance(manifest.get("git_dirty"), bool):
        failures.append(f"FAIL pair_manifest_git_dirty repeat={repeat_index} value={manifest.get('git_dirty')}")
    elif manifest.get("git_dirty"):
        failures.append(f"FAIL pair_manifest_git_dirty_true repeat={repeat_index}")

    info = {
        "path": str(path),
        "provenance_manifest_path": one.canonical_manifest_provenance_path(path),
        "sha256": one.file_sha256(path) if path.is_file() else None,
        "binary_sha256": manifest.get("binary_sha256"),
        "selected_clients_sha256": actual_sha,
        "samples": samples,
        "warmups": warmups,
        "git_head": manifest.get("git_head"),
        "git_dirty": manifest.get("git_dirty"),
        "target": manifest.get("target"),
        "profile": manifest.get("profile"),
        "features": manifest.get("features"),
        "scout_gate": True,
        "publication_eligible": False,
        "paired_scout": True,
        "scout_repeat_index": repeat_index,
        "scout_repeat_count": repeat_count,
        "run_order": expected_order,
    }
    return info, failures


def validate_repeat(path: Path, repeat_index: int, repeat_count: int, min_samples: int) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    manifest_info, manifest_failures = load_manifest(path, repeat_index, repeat_count, min_samples)
    failures.extend(manifest_failures)
    if manifest_info is None:
        return None, failures

    prefix = str(path)[: -len(".manifest.json")]
    expected_artifact_by_client = {
        client: Path(f"{prefix}.{client}.json") for client in PAIR_CLIENTS
    }
    artifact_paths = list(expected_artifact_by_client.values())
    for client, artifact_path in expected_artifact_by_client.items():
        if not artifact_path.is_file():
            failures.append(f"FAIL pair_missing_artifact repeat={repeat_index} client={client} path={artifact_path}")

    existing_paths = [path for path in artifact_paths if path.is_file()]
    docs, load_failures = one.load_docs([str(path) for path in existing_paths])
    failures.extend(load_failures)
    failures.extend(one.reject_phase_trace_artifacts(docs))
    failures.extend(one.validate_run_provenance(docs, expected_artifact_by_client, manifest_info))

    docs_by_path = {doc_path.resolve(): doc for doc_path, doc in docs}
    sequence_by_index: dict[int, tuple[str, int, int]] = {}
    for client, artifact_path in expected_artifact_by_client.items():
        doc = docs_by_path.get(artifact_path.resolve())
        if not isinstance(doc, dict):
            continue
        provenance = doc.get("run_provenance")
        if not isinstance(provenance, dict):
            continue
        extra_checks = {
            "paired_scout": True,
            "scout_repeat_index": repeat_index,
            "scout_repeat_count": repeat_count,
            "run_order": manifest_info["run_order"],
        }
        for key, expected in extra_checks.items():
            if provenance.get(key) != expected:
                failures.append(
                    f"FAIL pair_provenance_{key} repeat={repeat_index} client={client} expected={expected} actual={provenance.get(key)}"
                )
        if _canonical_path(provenance.get("manifest_path")) != _canonical_path(str(path)):
            failures.append(
                f"FAIL pair_provenance_manifest_path repeat={repeat_index} client={client} expected={path} actual={provenance.get('manifest_path')}"
            )
        sequence_index = provenance.get("paired_run_sequence_index")
        started_at = provenance.get("paired_run_started_at_unix_ns")
        finished_at = provenance.get("paired_run_finished_at_unix_ns")
        if not isinstance(sequence_index, int):
            failures.append(
                f"FAIL pair_provenance_sequence_index repeat={repeat_index} client={client} actual={sequence_index}"
            )
            continue
        if not 1 <= sequence_index <= len(PAIR_CLIENTS):
            failures.append(
                f"FAIL pair_provenance_sequence_range repeat={repeat_index} client={client} actual={sequence_index}"
            )
            continue
        expected_client = manifest_info["run_order"][sequence_index - 1]
        if client != expected_client or provenance.get("selected_client") != expected_client:
            failures.append(
                f"FAIL pair_provenance_sequence_client repeat={repeat_index} sequence={sequence_index} expected={expected_client} actual={client}/{provenance.get('selected_client')}"
            )
        if not isinstance(started_at, int) or not isinstance(finished_at, int):
            failures.append(
                f"FAIL pair_provenance_sequence_timestamp repeat={repeat_index} client={client} start={started_at} finish={finished_at}"
            )
            continue
        if finished_at < started_at:
            failures.append(
                f"FAIL pair_provenance_sequence_timestamp_order repeat={repeat_index} client={client} start={started_at} finish={finished_at}"
            )
        if sequence_index in sequence_by_index:
            previous_client, _, _ = sequence_by_index[sequence_index]
            failures.append(
                f"FAIL pair_provenance_duplicate_sequence repeat={repeat_index} sequence={sequence_index} clients={previous_client},{client}"
            )
        sequence_by_index[sequence_index] = (client, started_at, finished_at)
    if len(sequence_by_index) == len(PAIR_CLIENTS):
        previous_finish = None
        for sequence_index in range(1, len(PAIR_CLIENTS) + 1):
            client, started_at, finished_at = sequence_by_index[sequence_index]
            if previous_finish is not None and started_at < previous_finish:
                failures.append(
                    f"FAIL pair_provenance_sequence_monotonic repeat={repeat_index} sequence={sequence_index} client={client} start={started_at} previous_finish={previous_finish}"
                )
            previous_finish = finished_at

    rows = one.load_rows(docs)
    measured_multi = one.measured_rows_by_id(rows)
    measured: dict[str, dict[str, Any]] = {}
    for client in PAIR_CLIENTS:
        expected_artifact = expected_artifact_by_client[client].resolve()
        required_matches = [
            row
            for row in rows
            if row.get("competitor_id") == client
            and Path(str(row.get("_artifact"))).resolve() == expected_artifact
        ]
        if len(required_matches) == 0:
            failures.append(
                f"FAIL pair_missing_required_row repeat={repeat_index} client={client} artifact={expected_artifact}"
            )
        elif len(required_matches) > 1:
            statuses = ",".join(str(row.get("status")) for row in required_matches)
            failures.append(
                f"FAIL pair_duplicate_required_row repeat={repeat_index} client={client} count={len(required_matches)} statuses={statuses} artifact={expected_artifact}"
            )
        matches = [
            row
            for row in measured_multi.get(client, [])
            if Path(str(row.get("_artifact"))).resolve() == expected_artifact
        ]
        unexpected = [
            row
            for row in measured_multi.get(client, [])
            if Path(str(row.get("_artifact"))).resolve() != expected_artifact
        ]
        for row in unexpected:
            failures.append(
                f"FAIL pair_unexpected_measured_row repeat={repeat_index} client={client} artifact={row.get('_artifact')}"
            )
        if len(matches) != 1:
            failures.append(f"FAIL pair_measured_row_count repeat={repeat_index} client={client} count={len(matches)}")
            continue
        if len(required_matches) != 1:
            continue
        row = required_matches[0]
        row_failures = one.row_complete(row, min_samples, manifest_info)
        if row.get("workload") != WORKLOAD:
            row_failures.append(f"workload={row.get('workload')} expected={WORKLOAD}")
        if row_failures:
            failures.append(
                f"FAIL pair_invalid_row repeat={repeat_index} client={client} {';'.join(row_failures)} artifact={row.get('_artifact')}"
            )
            continue
        measured[client] = row

    if failures:
        return None, failures

    return {
        "repeat_index": repeat_index,
        "manifest": manifest_info,
        "manifest_resolved_path": str(path.resolve()),
        "artifact_set_sha256": artifact_set_sha256(artifact_paths),
        "raw_samples_set_sha256": raw_samples_set_sha256(measured),
        "rows": measured,
        "artifact_paths": {client: str(path) for client, path in expected_artifact_by_client.items()},
    }, failures


def stamp_runs(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stamped: list[dict[str, Any]] = []
    for run in runs:
        row_doc = {
            "repeat_index": run["repeat_index"],
            "manifest_path": run["manifest"]["path"],
            "manifest_resolved_path": run["manifest_resolved_path"],
            "manifest_sha256": run["manifest"]["sha256"],
            "manifest": run["manifest"],
            "artifact_set_sha256": run["artifact_set_sha256"],
            "raw_samples_set_sha256": run["raw_samples_set_sha256"],
            "rows": {},
        }
        for client, row in run["rows"].items():
            row_doc["rows"][client] = {
                "artifact": row.get("_artifact"),
                "artifact_sha256": one.file_sha256(Path(str(row.get("_artifact")))),
                "p50_ttfb_ns": row.get("p50_ttfb_ns"),
                "p95_ttfb_ns": row.get("p95_ttfb_ns"),
                "bytes_per_sec": row.get("bytes_per_sec"),
                "ledger_paced_bytes_per_sec": row.get("ledger_paced_bytes_per_sec"),
                "sample_count": row.get("sample_count"),
                "raw_samples_sha256": one.raw_samples_sha256(row),
            }
        stamped.append(row_doc)
    return stamped


def evaluate_manifests(
    manifest_paths: list[Path],
    min_repeats: int,
    min_samples: int,
) -> tuple[list[str], list[dict[str, Any]], dict[str, Any], bool]:
    failures: list[str] = []
    if len(manifest_paths) < min_repeats:
        failures.append(f"FAIL pair_repeat_count count={len(manifest_paths)} min={min_repeats}")

    runs: list[dict[str, Any]] = []
    seen_manifest_sha: dict[str, int] = {}
    seen_artifact_set_sha: dict[str, int] = {}
    seen_raw_samples_set_sha: dict[str, int] = {}
    common: dict[str, Any] = {}
    for index, manifest_path in enumerate(manifest_paths, start=1):
        run, run_failures = validate_repeat(manifest_path, index, len(manifest_paths), min_samples)
        failures.extend(run_failures)
        if run is None:
            continue
        runs.append(run)
        manifest_sha = str(run["manifest"]["sha256"])
        if manifest_sha in seen_manifest_sha:
            failures.append(f"FAIL pair_duplicate_manifest_sha sha={manifest_sha} repeats={seen_manifest_sha[manifest_sha]},{index}")
        seen_manifest_sha[manifest_sha] = index
        artifact_set = str(run["artifact_set_sha256"])
        if artifact_set in seen_artifact_set_sha:
            failures.append(f"FAIL pair_duplicate_artifact_set sha={artifact_set} repeats={seen_artifact_set_sha[artifact_set]},{index}")
        seen_artifact_set_sha[artifact_set] = index
        raw_samples_set = str(run["raw_samples_set_sha256"])
        if raw_samples_set in seen_raw_samples_set_sha:
            failures.append(f"FAIL pair_duplicate_raw_samples sha={raw_samples_set} repeats={seen_raw_samples_set_sha[raw_samples_set]},{index}")
        seen_raw_samples_set_sha[raw_samples_set] = index
        for key in ("binary_sha256", "git_head", "git_dirty", "target", "profile", "features", "samples", "warmups"):
            value = run["manifest"].get(key)
            if key in common and common[key] != value:
                failures.append(f"FAIL pair_common_{key} repeat={index} expected={common[key]} actual={value}")
            common.setdefault(key, value)

    edges: dict[str, Any] = {}
    if not failures and len(runs) == len(manifest_paths):
        specter_rows = [run["rows"]["specter_native"] for run in runs]
        quiche_rows = [run["rows"]["quiche_direct"] for run in runs]
        ledger_gate = one.fixture_ledger_gate_enabled(runs[0]["manifest"]) or one.fixture_ledger_required(
            runs[0]["manifest"]
        )
        throughput_metric = "ledger_paced_bytes_per_sec" if ledger_gate else "bytes_per_sec"
        throughput_label = "ledger_paced_throughput" if ledger_gate else "throughput"
        sp_p50 = max(float(row["p50_ttfb_ns"]) for row in specter_rows)
        sp_p95 = max(float(row["p95_ttfb_ns"]) for row in specter_rows)
        sp_tput = min(float(row[throughput_metric]) for row in specter_rows)
        q_p50 = min(float(row["p50_ttfb_ns"]) for row in quiche_rows)
        q_p95 = min(float(row["p95_ttfb_ns"]) for row in quiche_rows)
        q_tput = max(float(row[throughput_metric]) for row in quiche_rows)
        edges = {
            "specter_worst_p50_ttfb_ns": sp_p50,
            "quiche_direct_best_p50_ttfb_ns": q_p50,
            "specter_worst_p95_ttfb_ns": sp_p95,
            "quiche_direct_best_p95_ttfb_ns": q_p95,
            "throughput_metric": throughput_metric,
            "specter_worst_bytes_per_sec": sp_tput,
            "quiche_direct_best_bytes_per_sec": q_tput,
            "p50_margin_ns": q_p50 - sp_p50,
            "p95_margin_ns": q_p95 - sp_p95,
            "throughput_margin_bytes_per_sec": sp_tput - q_tput,
        }
        if sp_p50 > q_p50:
            failures.append(f"FAIL_PAIR p50 specter_worst={sp_p50:.0f} quiche_best={q_p50:.0f}")
        if sp_p95 > q_p95:
            failures.append(f"FAIL_PAIR p95 specter_worst={sp_p95:.0f} quiche_best={q_p95:.0f}")
        if sp_tput < q_tput:
            failures.append(f"FAIL_PAIR {throughput_label} specter_worst={sp_tput:.6f} quiche_best={q_tput:.6f}")

    candidate = not failures
    return failures, runs, edges, candidate


def canonical_for_stamp(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def write_stamp(
    path: Path,
    failures: list[str],
    runs: list[dict[str, Any]],
    edges: dict[str, Any],
    candidate: bool,
    min_repeats: int,
    min_samples: int,
    manifest_paths: list[Path],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parser_path = Path(__file__)
    doc = {
        "kind": "native_h3_pair_repeat_scout",
        "non_publishable": True,
        "publication_eligible": False,
        "scout_gate": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser_path": str(parser_path),
        "parser_sha256": one.file_sha256(parser_path),
        "exit_code": 0 if candidate else 1,
        "run_count": len(runs),
        "min_repeats": min_repeats,
        "min_samples": min_samples,
        "manifest_paths": [str(path.resolve()) for path in manifest_paths],
        "candidate": candidate,
        "failures": failures,
        "edges": edges,
        "runs": stamp_runs(runs),
    }
    # Stamps high_water_comparison.strict_percent_behind for automatic
    # p50_ttfb_ns / p95_ttfb_ns / bytes_per_sec gap reporting after scouts.
    high_water.attach_pair_high_water_comparison(doc, os.environ.get("HIGH_WATER_PATH"))
    path.write_text(json.dumps(doc, indent=2) + "\n")


def verify_stamp(path: Path, min_repeats: int, min_samples: int) -> list[str]:
    failures: list[str] = []
    try:
        stamp = one.load_json_strict(path)
    except FileNotFoundError:
        return [f"FAIL pair_stamp_missing path={path}"]
    except json.JSONDecodeError as exc:
        return [f"FAIL pair_stamp_invalid_json path={path} line={exc.lineno} column={exc.colno} msg={exc.msg}"]
    except ValueError as exc:
        return [f"FAIL pair_stamp_invalid_json path={path} msg={exc}"]
    except OSError as exc:
        return [f"FAIL pair_stamp_unreadable path={path} error={exc}"]
    if not isinstance(stamp, dict):
        return [f"FAIL pair_stamp_invalid_root path={path}"]

    parser_path = Path(__file__)
    required = {
        "kind": "native_h3_pair_repeat_scout",
        "non_publishable": True,
        "publication_eligible": False,
        "scout_gate": True,
    }
    for key, expected in required.items():
        if stamp.get(key) != expected:
            failures.append(f"FAIL pair_stamp_{key} expected={expected} actual={stamp.get(key)}")
    if stamp.get("parser_sha256") != one.file_sha256(parser_path):
        failures.append("FAIL pair_stamp_parser_sha256")
    if not isinstance(stamp.get("runs"), list):
        failures.append("FAIL pair_stamp_runs_missing")
        return failures

    stamp_min_repeats = max(min_repeats, int(stamp.get("min_repeats") or 0), 3)
    stamp_min_samples = max(min_samples, int(stamp.get("min_samples") or 0), one.HARD_MIN_SAMPLES)
    manifest_paths: list[Path] = []
    stamped_manifest_paths = stamp.get("manifest_paths")
    if isinstance(stamped_manifest_paths, list):
        for index, manifest_path in enumerate(stamped_manifest_paths, start=1):
            if not isinstance(manifest_path, str) or not manifest_path:
                failures.append(f"FAIL pair_stamp_manifest_path_missing index={index}")
                continue
            manifest_paths.append(Path(manifest_path))
    else:
        for index, run in enumerate(stamp["runs"], start=1):
            if not isinstance(run, dict):
                failures.append(f"FAIL pair_stamp_run_invalid index={index}")
                continue
            manifest_path = run.get("manifest_resolved_path") or run.get("manifest_path")
            if not isinstance(manifest_path, str) or not manifest_path:
                failures.append(f"FAIL pair_stamp_manifest_path_missing index={index}")
                continue
            manifest_paths.append(Path(manifest_path))

    replay_failures, replay_runs, replay_edges, replay_candidate = evaluate_manifests(
        manifest_paths,
        stamp_min_repeats,
        stamp_min_samples,
    )
    expected_exit_code = 0 if replay_candidate else 1
    if stamp.get("exit_code") != expected_exit_code:
        failures.append(
            f"FAIL pair_stamp_exit_code expected={expected_exit_code} actual={stamp.get('exit_code')}"
        )
    if stamp.get("run_count") != len(replay_runs):
        failures.append(
            f"FAIL pair_stamp_run_count expected={len(replay_runs)} actual={stamp.get('run_count')}"
        )
    if stamp.get("candidate") != replay_candidate:
        failures.append(
            f"FAIL pair_stamp_candidate expected={replay_candidate} actual={stamp.get('candidate')}"
        )
    if canonical_for_stamp(stamp.get("failures")) != canonical_for_stamp(replay_failures):
        failures.append("FAIL pair_stamp_failures_mismatch")
    if canonical_for_stamp(stamp.get("edges")) != canonical_for_stamp(replay_edges):
        failures.append("FAIL pair_stamp_edges_mismatch")
    if canonical_for_stamp(stamp.get("runs")) != canonical_for_stamp(stamp_runs(replay_runs)):
        failures.append("FAIL pair_stamp_runs_mismatch")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="*", help="per-repeat manifest JSON files")
    parser.add_argument("--stamp", help="write paired scout JSON stamp here")
    parser.add_argument("--verify-stamp", help="replay and verify an existing paired scout JSON stamp")
    parser.add_argument("--min-repeats", type=int, default=3)
    parser.add_argument("--min-samples", type=int, default=one.HARD_MIN_SAMPLES)
    args = parser.parse_args(argv)

    min_repeats = max(args.min_repeats, 3)
    min_samples = max(args.min_samples, one.HARD_MIN_SAMPLES)
    if args.verify_stamp:
        if args.stamp or args.manifests:
            parser.error("--verify-stamp cannot be combined with --stamp or manifest arguments")
        failures = verify_stamp(Path(args.verify_stamp), min_repeats, min_samples)
        if failures:
            print("PAIR_SCOUT_STAMP_REJECT " + "; ".join(failures))
            return 1
        print("PAIR_SCOUT_STAMP_VERIFIED")
        return 0

    if not args.stamp:
        parser.error("--stamp is required unless --verify-stamp is used")
    if not args.manifests:
        parser.error("at least one manifest is required unless --verify-stamp is used")

    # Resolve symlinks up front so generation parses the same canonical paths the
    # stamp records (manifest_paths is stored resolved) and verify replays. On macOS
    # /var -> /private/var would otherwise make every artifact= path in the recorded
    # failures diverge from replay. No-op on Linux where /var is not a symlink.
    manifest_paths = [Path(path).resolve() for path in args.manifests]
    failures, runs, edges, candidate = evaluate_manifests(
        manifest_paths,
        min_repeats,
        min_samples,
    )

    write_stamp(
        Path(args.stamp),
        failures,
        runs,
        edges,
        candidate,
        min_repeats,
        min_samples,
        manifest_paths,
    )
    if candidate:
        print("PAIR_SCOUT_CANDIDATE")
        return 0
    print("PAIR_SCOUT_REJECT " + "; ".join(failures))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Strict selected-row gate for native_h3_vs_rust_clients artifacts.

The per-client selected-row runner emits one full benchmark artifact per selected
client. Every artifact contains placeholders for unmeasured rows, so a naive
"compare measured rows only" parser can silently ignore a missing required
artifact. This parser makes the required row set explicit and fails before
metric comparison when any required row is absent, under-sampled, or missing a
metric.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import current_rows_high_water as high_water

GET_REQUIRED = (
    "warpsock_native",
    "quiche_direct",
    "tokio_quiche",
    "h3_quinn",
    "reqwest_h3",
)

RFC9220_REQUIRED = (
    "warpsock_native_rfc9220_tunnel",
    "quiche_direct_rfc9220_tunnel",
    "tokio_quiche_rfc9220_tunnel",
    "warpsock_native_rfc9220_tunnel_close",
    "quiche_direct_rfc9220_tunnel_close",
    "tokio_quiche_rfc9220_tunnel_close",
    "warpsock_native_rfc9220_tunnel_mixed",
    "quiche_direct_rfc9220_tunnel_mixed",
    "tokio_quiche_rfc9220_tunnel_mixed",
)

REQUIRED_ROWS = GET_REQUIRED + RFC9220_REQUIRED
GET_ONLY_WORKLOADS = {
    "http3_streaming_get": GET_REQUIRED,
}

REQUIRED_RUNTIME_PROFILE = "direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed"
REQUIRED_IO_EPOCH_RUNTIME_PROFILE = "direct-get-io-epoch-rfc9220-fused-echo-close-epoch-mixed"
REQUIRED_BENCHMARK = "native_h3_vs_rust_clients"
REQUIRED_BENCHMARK_VERSION = "matrix-1"
REQUIRED_TARGET = "aarch64-unknown-linux-gnu"
REQUIRED_PROFILE = "release"
REQUIRED_FEATURES = "reqwest-h3"

REQUIRED_RUNTIME_ENV = {
    "BENCH_TUNNEL_STEADYSTATE": "1",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_MODE": "process",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_TASKSET_CORE": "2",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_PUMP": "inline-first-chunk-v1",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_EPOCH": "1",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH": "0",
    "WARPSOCK_NATIVE_H3_DIRECT_IDLE_GET": "1",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_READY_SPIN_US": "25",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_BODY_SPIN_US": "25",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_CLOSE_EPOCH": "1",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_FUSED_ECHO": "1",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_MIXED": "1",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_TUNNEL": "1",
    "FIXTURE_LEDGER_GATE": "0",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR": "",
}

RUNTIME_PROFILE_ENV_OVERRIDES = {
    REQUIRED_RUNTIME_PROFILE: {},
    REQUIRED_IO_EPOCH_RUNTIME_PROFILE: {
        "WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH": "1",
    },
}


def required_runtime_env_for_profile(runtime_profile: str | None) -> dict[str, str] | None:
    overrides = RUNTIME_PROFILE_ENV_OVERRIDES.get(runtime_profile or "")
    if overrides is None:
        return None
    expected = dict(REQUIRED_RUNTIME_ENV)
    expected.update(overrides)
    return expected

WORKLOADS = {
    "http3_streaming_get": GET_REQUIRED,
    "websocket_over_h3_raw_tunnel_echo": (
        "warpsock_native_rfc9220_tunnel",
        "quiche_direct_rfc9220_tunnel",
        "tokio_quiche_rfc9220_tunnel",
    ),
    "websocket_over_h3_raw_tunnel_close_fin": (
        "warpsock_native_rfc9220_tunnel_close",
        "quiche_direct_rfc9220_tunnel_close",
        "tokio_quiche_rfc9220_tunnel_close",
    ),
    "slow_consumer_tunnel_plus_http3_streaming": (
        "warpsock_native_rfc9220_tunnel_mixed",
        "quiche_direct_rfc9220_tunnel_mixed",
        "tokio_quiche_rfc9220_tunnel_mixed",
    ),
}

EXPECTED_PAYLOAD_BYTES = {
    "http3_streaming_get": 16 * 1024 * 5,
    "websocket_over_h3_raw_tunnel_echo": 1024,
    "websocket_over_h3_raw_tunnel_close_fin": 1024,
    "slow_consumer_tunnel_plus_http3_streaming": 1024 * 40 + 16 * 1024 * 5,
}

EXPECTED_WORKLOAD_BY_ID = {
    competitor_id: workload
    for workload, competitor_ids in WORKLOADS.items()
    for competitor_id in competitor_ids
}

EXPECTED_SOURCE_BY_ID = {
    competitor_id: f"{competitor_id}_adapter" for competitor_id in REQUIRED_ROWS
}

METRICS = ("p50_ttfb_ns", "p95_ttfb_ns", "bytes_per_sec")
GET_PACED_METRICS = (
    "p50_paced_body_overhead_ns",
    "p95_paced_body_overhead_ns",
    "p50_paced_tail_overhead_ns",
    "p95_paced_tail_overhead_ns",
)
GET_LEDGER_METRICS = (
    "p50_fixture_emission_span_ns",
    "p95_fixture_emission_span_ns",
    "p50_ledger_paced_tail_overhead_ns",
    "p95_ledger_paced_tail_overhead_ns",
    "ledger_paced_bytes_per_sec",
)
GET_LEDGER_PROOF_FIELDS = (
    "fixture_ledger_sha256",
    "fixture_ledger_response_count",
    "fixture_ledger_required_response_count",
    "fixture_ledger_sample_offset",
)
LOCAL_FIXTURE_CHUNK_COUNT = 5
LOCAL_FIXTURE_CHUNK_SIZE = 16 * 1024
LOCAL_FIXTURE_CHUNK_DELAY_NS = 1_000_000
GET_FIXTURE_PACE_SPAN_NS = (LOCAL_FIXTURE_CHUNK_COUNT - 1) * float(
    LOCAL_FIXTURE_CHUNK_DELAY_NS
)
HARD_MIN_SAMPLES = 100
FLOAT_TOLERANCE = 1e-6
GIT_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
DOCS_BENCHMARKS_PREFIX = Path("docs/benchmarks/native-h3-vs-rust-clients")


def ms(value: Any) -> float | None:
    return value / 1_000_000 if isinstance(value, (int, float)) else None


def json_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def fixture_ledger_gate_enabled(manifest_info: dict[str, Any]) -> bool:
    runtime_env = manifest_info.get("runtime_env")
    return isinstance(runtime_env, dict) and runtime_env.get("FIXTURE_LEDGER_GATE") == "1"


def fixture_ledger_required(manifest_info: dict[str, Any]) -> bool:
    return bool(manifest_info.get("requires_fixture_ledger"))


def workloads_for_required_rows(required_rows: tuple[str, ...]) -> set[str]:
    return {
        workload
        for competitor_id in required_rows
        if isinstance((workload := EXPECTED_WORKLOAD_BY_ID.get(competitor_id)), str)
    }


def mib(value: Any) -> float | None:
    return value / 1_048_576 if isinstance(value, (int, float)) else None


def status_rank(row: dict[str, Any]) -> int:
    status = row.get("status")
    if status == "measured_pass":
        return 3
    if status == "measured_fail":
        return 2
    if status in {"pending_adapter", "pending_measurement"}:
        return 0
    return 1


def is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def is_non_bool_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non_finite_json_number={value}")


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError(f"duplicate_json_key={key}")
        doc[key] = value
    return doc


def load_json_strict(path: Path) -> Any:
    with path.open() as f:
        return json.load(
            f,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_json_constant,
        )


def percentile(sorted_samples: list[float], percentile_value: float) -> float | None:
    if not sorted_samples:
        return None
    rank = math.ceil(percentile_value * len(sorted_samples))
    index = max(rank - 1, 0)
    index = min(index, len(sorted_samples) - 1)
    return sorted_samples[index]


def values_close(actual: Any, expected: float | int | None) -> bool:
    if expected is None:
        return actual is None
    if not is_number(actual):
        return False
    tolerance = max(FLOAT_TOLERANCE, abs(float(expected)) * FLOAT_TOLERANCE)
    return abs(float(actual) - float(expected)) <= tolerance


def recompute_raw_sample_metrics(row: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    samples = row.get("raw_samples")
    if not isinstance(samples, list) or not samples:
        return {}, [f"raw_samples={type(samples).__name__ if samples is not None else None}"]

    ttfb_samples: list[float] = []
    paced_body_overhead_samples: list[float] = []
    paced_tail_overhead_samples: list[float] = []
    total_ns = 0.0
    total_bytes = 0
    payload_bytes: int | None = None
    is_get = row.get("workload") == "http3_streaming_get"
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            failures.append(f"raw_sample[{index}]=non_object")
            continue
        ttfb_ns = sample.get("ttfb_ns")
        sample_total_ns = sample.get("total_ns")
        sample_bytes = sample.get("bytes")
        if not is_number(ttfb_ns):
            failures.append(f"raw_sample[{index}].missing_ttfb_ns")
        else:
            ttfb_samples.append(float(ttfb_ns))
        if not is_number(sample_total_ns):
            failures.append(f"raw_sample[{index}].missing_total_ns")
        else:
            total_ns += float(sample_total_ns)
        if is_get:
            first_body_ns = sample.get("first_body_ns")
            if not is_number(first_body_ns):
                failures.append(f"raw_sample[{index}].missing_first_body_ns")
            elif is_number(sample_total_ns):
                body_drain_ns = max(0.0, float(sample_total_ns) - float(first_body_ns))
                paced_body_overhead_samples.append(
                    max(0.0, body_drain_ns - GET_FIXTURE_PACE_SPAN_NS)
                )
            if is_number(ttfb_ns) and is_number(sample_total_ns):
                tail_ns = max(0.0, float(sample_total_ns) - float(ttfb_ns))
                paced_tail_overhead_samples.append(
                    max(0.0, tail_ns - GET_FIXTURE_PACE_SPAN_NS)
                )
        if not isinstance(sample_bytes, int) or isinstance(sample_bytes, bool):
            failures.append(f"raw_sample[{index}].missing_bytes")
        else:
            total_bytes += sample_bytes
            if payload_bytes is None:
                payload_bytes = sample_bytes
            elif payload_bytes != sample_bytes:
                payload_bytes = -1

    if failures:
        return {}, failures

    ttfb_samples.sort()
    recomputed = {
        "sample_count": len(samples),
        "p50_ttfb_ns": percentile(ttfb_samples, 0.50),
        "p95_ttfb_ns": percentile(ttfb_samples, 0.95),
        "bytes_per_sec": (
            (total_bytes * 1_000_000_000.0 / total_ns) if total_ns > 0 else None
        ),
    }
    if payload_bytes is not None and payload_bytes >= 0:
        recomputed["payload_bytes"] = payload_bytes
    if is_get:
        paced_body_overhead_samples.sort()
        paced_tail_overhead_samples.sort()
        recomputed["fixture_pace_span_ns"] = GET_FIXTURE_PACE_SPAN_NS
        recomputed["p50_paced_body_overhead_ns"] = percentile(
            paced_body_overhead_samples, 0.50
        )
        recomputed["p95_paced_body_overhead_ns"] = percentile(
            paced_body_overhead_samples, 0.95
        )
        recomputed["p50_paced_tail_overhead_ns"] = percentile(
            paced_tail_overhead_samples, 0.50
        )
        recomputed["p95_paced_tail_overhead_ns"] = percentile(
            paced_tail_overhead_samples, 0.95
        )
    return recomputed, failures


def validate_raw_sample_metrics(row: dict[str, Any]) -> list[str]:
    recomputed, failures = recompute_raw_sample_metrics(row)
    if failures:
        return failures
    for key in (
        "sample_count",
        "payload_bytes",
        *METRICS,
        *GET_PACED_METRICS,
        "fixture_pace_span_ns",
    ):
        if key in recomputed and not values_close(row.get(key), recomputed.get(key)):
            failures.append(
                f"{key}={row.get(key)} raw_expected={recomputed.get(key)}"
            )
    return failures


def load_docs(paths: list[str]) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    docs: list[tuple[Path, dict[str, Any]]] = []
    failures: list[str] = []
    for raw_path in sorted(paths):
        path = Path(raw_path)
        try:
            doc = load_json_strict(path)
        except json.JSONDecodeError as exc:
            failures.append(
                f"FAIL invalid_json_artifact: {path} line={exc.lineno} column={exc.colno} msg={exc.msg}"
            )
            continue
        except ValueError as exc:
            failures.append(f"FAIL invalid_json_artifact: {path} msg={exc}")
            continue
        except OSError as exc:
            failures.append(f"FAIL unreadable_artifact: {path} error={exc}")
            continue
        if not isinstance(doc, dict):
            failures.append(f"FAIL invalid_artifact_root: {path} expected=json_object")
            continue
        docs.append((path, doc))
    return docs, failures


def load_rows(docs: list[tuple[Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, doc in docs:
        for row in doc.get("rows", []):
            if not isinstance(row, dict):
                continue
            row = dict(row)
            row["_artifact"] = str(path)
            rows.append(row)
    return rows


def expand_input_paths(paths: list[str]) -> list[str]:
    expanded: list[str] = []
    for path in paths:
        matches = glob.glob(path)
        if matches:
            expanded.extend(matches)
        else:
            expanded.append(path)
    return sorted(expanded)


def canonical_manifest_provenance_path(path: Path) -> str:
    """Return the manifest path artifacts should stamp in run_provenance.

    Archives under docs/benchmarks must be replayable after copying the repo, so
    they stamp the repo-relative docs path. Temp/scout prefixes remain exact.
    """

    prefix = DOCS_BENCHMARKS_PREFIX.parts
    parts = path.parts
    for index in range(0, len(parts) - len(prefix) + 1):
        if parts[index : index + len(prefix)] == prefix:
            return str(Path(*parts[index:]))
    return str(path)


def best_rows_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        competitor_id = row.get("competitor_id")
        if not isinstance(competitor_id, str):
            continue
        current = best.get(competitor_id)
        if current is None or status_rank(row) > status_rank(current):
            best[competitor_id] = row
    return best


def measured_row_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    measured: dict[str, dict[str, Any]] = {}
    for row in rows:
        competitor_id = row.get("competitor_id")
        if isinstance(competitor_id, str) and row.get("status") == "measured_pass":
            measured[competitor_id] = row
    return measured


def measured_rows_by_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    measured: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        competitor_id = row.get("competitor_id")
        if isinstance(competitor_id, str) and row.get("status") == "measured_pass":
            measured[competitor_id].append(row)
    return dict(measured)


def row_complete(
    row: dict[str, Any], min_samples: int, manifest_info: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if row.get("status") != "measured_pass":
        failures.append(f"status={row.get('status')}")
    competitor_id = str(row.get("competitor_id"))
    expected_source = EXPECTED_SOURCE_BY_ID.get(competitor_id)
    if expected_source is not None and row.get("source") != expected_source:
        failures.append(f"source={row.get('source')} expected={expected_source}")
    sample_count = row.get("sample_count")
    if not isinstance(sample_count, int) or sample_count < min_samples:
        failures.append(f"sample_count={sample_count} < {min_samples}")
    expected_samples = manifest_info.get("samples")
    if isinstance(expected_samples, int):
        if sample_count != expected_samples:
            failures.append(
                f"sample_count={sample_count} expected_samples={expected_samples}"
            )
        for key in ("requested_samples", "completed_samples"):
            value = row.get(key)
            if value != expected_samples:
                failures.append(f"{key}={value} expected={expected_samples}")
    expected_warmups = manifest_info.get("warmups")
    if isinstance(expected_warmups, int):
        for key in ("requested_warmups", "completed_warmups"):
            value = row.get(key)
            if value != expected_warmups:
                failures.append(f"{key}={value} expected={expected_warmups}")
    for metric in METRICS:
        if not is_number(row.get(metric)):
            failures.append(f"missing_{metric}")
    if not isinstance(row.get("workload"), str):
        failures.append("missing_workload")
    else:
        expected_workload = EXPECTED_WORKLOAD_BY_ID.get(str(row.get("competitor_id")))
        if expected_workload is not None and row.get("workload") != expected_workload:
            failures.append(f"workload={row.get('workload')} expected={expected_workload}")
        expected_payload_bytes = EXPECTED_PAYLOAD_BYTES.get(row.get("workload"))
        if expected_payload_bytes is not None and row.get("payload_bytes") != expected_payload_bytes:
            failures.append(
                f"payload_bytes={row.get('payload_bytes')} expected={expected_payload_bytes}"
            )
        if row.get("workload") == "http3_streaming_get":
            for metric in GET_PACED_METRICS:
                if not is_number(row.get(metric)):
                    failures.append(f"missing_{metric}")
            if fixture_ledger_gate_enabled(manifest_info) or fixture_ledger_required(manifest_info):
                if not isinstance(row.get("fixture_ledger_path"), str) or not row.get("fixture_ledger_path"):
                    failures.append("missing_fixture_ledger_path")
                for metric in GET_LEDGER_METRICS:
                    if not is_number(row.get(metric)):
                        failures.append(f"missing_{metric}")
                if not isinstance(row.get("fixture_ledger_sha256"), str) or not re.fullmatch(
                    r"[0-9a-f]{64}", str(row.get("fixture_ledger_sha256", ""))
                ):
                    failures.append("missing_fixture_ledger_sha256")
                expected_ledger_responses = None
                if isinstance(sample_count, int) and isinstance(expected_warmups, int):
                    expected_ledger_responses = sample_count + expected_warmups
                if row.get("fixture_ledger_response_count") != expected_ledger_responses:
                    failures.append(
                        "fixture_ledger_response_count="
                        f"{row.get('fixture_ledger_response_count')} expected={expected_ledger_responses}"
                    )
                if row.get("fixture_ledger_required_response_count") != expected_ledger_responses:
                    failures.append(
                        "fixture_ledger_required_response_count="
                        f"{row.get('fixture_ledger_required_response_count')} expected={expected_ledger_responses}"
                    )
                if row.get("fixture_ledger_sample_offset") != expected_warmups:
                    failures.append(
                        f"fixture_ledger_sample_offset={row.get('fixture_ledger_sample_offset')} "
                        f"expected={expected_warmups}"
                    )
                failures.extend(validate_fixture_ledger_metrics(row, manifest_info))
            if not values_close(row.get("fixture_pace_span_ns"), GET_FIXTURE_PACE_SPAN_NS):
                failures.append(
                    f"fixture_pace_span_ns={row.get('fixture_pace_span_ns')} "
                    f"expected={GET_FIXTURE_PACE_SPAN_NS}"
                )
    failures.extend(validate_raw_sample_metrics(row))
    return failures


def artifact_matches_client(path: Path, client: str) -> bool:
    return path.name.endswith(f".{client}.json")


def is_selected_row_auxiliary_json(path: Path, prefix_name: str) -> bool:
    name = path.name
    if not name.startswith(f"{prefix_name}."):
        return False
    return (
        name.endswith(".manifest.json")
        or name.endswith("truth-pass.json")
        or name.endswith(".current_rows_scout.json")
        or name.endswith(".current_rows_pair_scout.json")
    )


def unexpected_prefix_sibling_artifacts(
    manifest_path: Path,
    expected_artifact_by_client: dict[str, Path],
) -> list[str]:
    if not manifest_path.name.endswith(".manifest.json"):
        return []
    prefix_name = manifest_path.name[: -len(".manifest.json")]
    expected_paths = {
        artifact_path.resolve() for artifact_path in expected_artifact_by_client.values()
    }
    failures: list[str] = []
    for sibling in sorted(manifest_path.parent.glob(f"{prefix_name}.*.json")):
        resolved = sibling.resolve()
        if resolved == manifest_path.resolve() or resolved in expected_paths:
            continue
        if is_selected_row_auxiliary_json(sibling, prefix_name):
            continue
        failures.append(
            f"FAIL unexpected_sibling_artifact path={sibling} manifest={manifest_path}"
        )
    return failures


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def selected_clients_sha256(selected_clients: list[str]) -> str:
    return hashlib.sha256(",".join(selected_clients).encode()).hexdigest()


def raw_samples_sha256(row: dict[str, Any]) -> str | None:
    samples = row.get("raw_samples")
    if not isinstance(samples, list):
        return None
    encoded = json.dumps(samples, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def expected_fixture_ledger_path(row: dict[str, Any]) -> Path | None:
    artifact = row.get("_artifact")
    competitor_id = row.get("competitor_id")
    if not isinstance(artifact, str) or not isinstance(competitor_id, str):
        return None
    artifact_path = Path(artifact)
    suffix = f".{competitor_id}.json"
    if not artifact_path.name.endswith(suffix):
        return None
    prefix = artifact_path.name[: -len(suffix)]
    return (
        artifact_path.parent
        / f"{prefix}.fixture-ledgers"
        / f"fixture-ledger.{competitor_id}.jsonl"
    )


def resolve_fixture_ledger_path(row: dict[str, Any]) -> tuple[Path | None, str | None]:
    raw_path = row.get("fixture_ledger_path")
    if not isinstance(raw_path, str) or not raw_path:
        return None, "missing_fixture_ledger_path"
    expected = expected_fixture_ledger_path(row)
    if expected is None:
        return None, "missing_fixture_ledger_artifact_scope"
    direct = Path(raw_path)
    try:
        direct_matches_expected = direct.resolve() == expected.resolve()
        direct_is_expected_suffix = (
            not direct.is_absolute()
            and expected.as_posix().endswith(direct.as_posix())
        )
        if not direct_matches_expected and not direct_is_expected_suffix:
            return None, (
                "fixture_ledger_path_outside_artifact_scope="
                f"{raw_path} expected={expected}"
            )
    except OSError as exc:
        return None, f"unreadable_fixture_ledger_path={raw_path} error={exc}"
    if expected.is_file():
        return expected, None
    return None, f"unreadable_fixture_ledger_path={raw_path} sibling={expected}"


def read_fixture_ledger_entries(
    path: Path, expected_client: str
) -> tuple[list[float], str, list[str]]:
    failures: list[str] = []
    responses: dict[int, dict[str, Any]] = {}
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return [], "", [f"unreadable_fixture_ledger_path={path} error={exc}"]
    try:
        text = raw_bytes.decode()
    except UnicodeDecodeError as exc:
        return [], "", [f"invalid_fixture_ledger_utf8 path={path} error={exc}"]
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    for line_index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(
                line,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_json_constant,
            )
        except json.JSONDecodeError as exc:
            failures.append(
                f"invalid_fixture_ledger_json line={line_index} column={exc.colno} msg={exc.msg}"
            )
            continue
        except ValueError as exc:
            failures.append(f"invalid_fixture_ledger_json line={line_index} msg={exc}")
            continue
        if not isinstance(entry, dict):
            failures.append(
                f"invalid_fixture_ledger_entry line={line_index} expected=json_object"
            )
            continue

        kind = entry.get("kind")
        client = entry.get("client")
        response_id = entry.get("response_id")
        chunk_index = entry.get("chunk_index")
        due_ns = entry.get("due_ns")
        send_start_ns = entry.get("send_start_ns")
        send_done_ns = entry.get("send_done_ns")
        bytes_len = entry.get("bytes")
        fin = entry.get("fin")

        if kind != "local_native_h3_fixture_stream_chunk":
            failures.append(
                f"fixture_ledger_line={line_index} kind={kind} "
                "expected=local_native_h3_fixture_stream_chunk"
            )
            continue
        if client != expected_client:
            failures.append(
                f"fixture_ledger_line={line_index} client={client} expected={expected_client}"
            )
            continue
        if not is_non_bool_int(response_id) or response_id < 0:
            failures.append(
                f"fixture_ledger_line={line_index} invalid_response_id={response_id}"
            )
            continue
        if (
            not is_non_bool_int(chunk_index)
            or chunk_index < 0
            or chunk_index >= LOCAL_FIXTURE_CHUNK_COUNT
        ):
            failures.append(
                f"fixture_ledger_response={response_id} chunk_index={chunk_index} "
                f"expected=< {LOCAL_FIXTURE_CHUNK_COUNT}"
            )
            continue
        if bytes_len != LOCAL_FIXTURE_CHUNK_SIZE:
            failures.append(
                f"fixture_ledger_response={response_id} chunk={chunk_index} "
                f"bytes={bytes_len} expected={LOCAL_FIXTURE_CHUNK_SIZE}"
            )
            continue
        expected_fin = chunk_index == LOCAL_FIXTURE_CHUNK_COUNT - 1
        if fin is not expected_fin:
            failures.append(
                f"fixture_ledger_response={response_id} chunk={chunk_index} "
                f"fin={fin} expected={expected_fin}"
            )
            continue
        if (
            not is_non_bool_int(due_ns)
            or due_ns < 0
            or
            not is_non_bool_int(send_start_ns)
            or send_start_ns < 0
            or not is_non_bool_int(send_done_ns)
            or send_done_ns < 0
        ):
            failures.append(
                f"fixture_ledger_response={response_id} chunk={chunk_index} "
                f"invalid_send_times due={due_ns} start={send_start_ns} done={send_done_ns}"
            )
            continue
        if send_done_ns < send_start_ns:
            failures.append(
                f"fixture_ledger_response={response_id} chunk={chunk_index} "
                f"send_done_ns={send_done_ns} < send_start_ns={send_start_ns}"
            )
            continue

        response = responses.setdefault(
            response_id,
            {
                "first_start_ns": None,
                "last_done_ns": None,
                "chunks_seen": [False] * LOCAL_FIXTURE_CHUNK_COUNT,
                "due_ns_by_chunk": [None] * LOCAL_FIXTURE_CHUNK_COUNT,
            },
        )
        chunks_seen = response["chunks_seen"]
        if chunks_seen[chunk_index]:
            failures.append(
                f"fixture_ledger_response={response_id} duplicate_chunk={chunk_index}"
            )
            continue
        chunks_seen[chunk_index] = True
        response["due_ns_by_chunk"][chunk_index] = due_ns
        first_start = response["first_start_ns"]
        last_done = response["last_done_ns"]
        response["first_start_ns"] = (
            send_start_ns if first_start is None else min(first_start, send_start_ns)
        )
        response["last_done_ns"] = (
            send_done_ns if last_done is None else max(last_done, send_done_ns)
        )

    if failures:
        return [], sha256, failures

    spans: list[float] = []
    for expected_response_id, response_id in enumerate(sorted(responses)):
        if response_id != expected_response_id:
            failures.append(
                f"fixture_ledger_response_id_gap expected={expected_response_id} saw={response_id}"
            )
            continue
        response = responses[response_id]
        if any(not seen for seen in response["chunks_seen"]):
            failures.append(f"fixture_ledger_response={response_id} missing_chunks")
            continue
        due_by_chunk = response["due_ns_by_chunk"]
        first_due = due_by_chunk[0]
        if first_due is None:
            failures.append(f"fixture_ledger_response={response_id} missing_due_ns")
            continue
        for chunk_index, due_ns in enumerate(due_by_chunk):
            expected_due = first_due + chunk_index * LOCAL_FIXTURE_CHUNK_DELAY_NS
            if due_ns != expected_due:
                failures.append(
                    f"fixture_ledger_response={response_id} chunk={chunk_index} "
                    f"due_ns={due_ns} expected={expected_due}"
                )
                break
        if failures:
            continue
        first_start = response["first_start_ns"]
        last_done = response["last_done_ns"]
        if first_start is None or last_done is None:
            failures.append(
                f"fixture_ledger_response={response_id} missing_start_or_done"
            )
            continue
        spans.append(float(max(0, last_done - first_start)))
    return spans, sha256, failures


def recompute_fixture_ledger_metrics(
    row: dict[str, Any], manifest_info: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    ledger_path, path_error = resolve_fixture_ledger_path(row)
    if ledger_path is None:
        return {}, [path_error or "missing_fixture_ledger_path"]

    expected_client = row.get("competitor_id")
    if not isinstance(expected_client, str):
        return {}, ["invalid_fixture_ledger_client"]

    spans, sha256, ledger_failures = read_fixture_ledger_entries(
        ledger_path, expected_client
    )
    failures.extend(ledger_failures)

    samples = row.get("raw_samples")
    if not isinstance(samples, list) or not samples:
        failures.append(
            f"fixture_ledger_raw_samples={type(samples).__name__ if samples is not None else None}"
        )
    warmups = manifest_info.get("warmups")
    sample_count = row.get("sample_count")
    if not isinstance(warmups, int) or isinstance(warmups, bool):
        failures.append(f"fixture_ledger_warmups={warmups}")
    if not isinstance(sample_count, int) or isinstance(sample_count, bool):
        failures.append(f"fixture_ledger_sample_count={sample_count}")
    if failures:
        return {}, failures

    expected_ledger_responses = warmups + sample_count
    if len(spans) != expected_ledger_responses:
        failures.append(
            f"fixture_ledger_response_count={len(spans)} expected={expected_ledger_responses}"
        )
        return {}, failures
    measured_spans = spans[warmups : warmups + sample_count]
    if len(measured_spans) != len(samples):
        return {}, [
            f"fixture_ledger_measured_span_count={len(measured_spans)} raw_samples={len(samples)}"
        ]

    sorted_spans = sorted(measured_spans)
    ledger_overheads: list[float] = []
    ledger_paced_total_ns = 0.0
    total_bytes = 0
    for index, (sample, span) in enumerate(zip(samples, measured_spans)):
        if not isinstance(sample, dict):
            failures.append(f"fixture_ledger_raw_sample[{index}]=non_object")
            continue
        ttfb_ns = sample.get("ttfb_ns")
        total_ns = sample.get("total_ns")
        sample_bytes = sample.get("bytes")
        if not is_number(ttfb_ns) or not is_number(total_ns):
            failures.append(
                f"fixture_ledger_raw_sample[{index}].missing_ttfb_or_total"
            )
            continue
        if not is_non_bool_int(sample_bytes) or sample_bytes < 0:
            failures.append(f"fixture_ledger_raw_sample[{index}].missing_bytes")
            continue
        tail_ns = max(0.0, float(total_ns) - float(ttfb_ns))
        ledger_overhead_ns = max(0.0, tail_ns - span)
        ledger_overheads.append(ledger_overhead_ns)
        ledger_paced_total_ns += (
            float(ttfb_ns) + GET_FIXTURE_PACE_SPAN_NS + ledger_overhead_ns
        )
        total_bytes += sample_bytes
    if failures:
        return {}, failures
    ledger_overheads.sort()

    return {
        "fixture_ledger_sha256": sha256,
        "fixture_ledger_response_count": expected_ledger_responses,
        "fixture_ledger_required_response_count": expected_ledger_responses,
        "fixture_ledger_sample_offset": warmups,
        "p50_fixture_emission_span_ns": percentile(sorted_spans, 0.50),
        "p95_fixture_emission_span_ns": percentile(sorted_spans, 0.95),
        "p50_ledger_paced_tail_overhead_ns": percentile(ledger_overheads, 0.50),
        "p95_ledger_paced_tail_overhead_ns": percentile(ledger_overheads, 0.95),
        "ledger_paced_bytes_per_sec": (
            total_bytes * 1_000_000_000.0 / ledger_paced_total_ns
            if ledger_paced_total_ns > 0
            else None
        ),
    }, []


def validate_fixture_ledger_metrics(
    row: dict[str, Any], manifest_info: dict[str, Any]
) -> list[str]:
    recomputed, failures = recompute_fixture_ledger_metrics(row, manifest_info)
    if failures:
        return failures
    for key in GET_LEDGER_PROOF_FIELDS:
        if row.get(key) != recomputed.get(key):
            failures.append(
                f"{key}={row.get(key)} ledger_expected={recomputed.get(key)}"
            )
    for key in GET_LEDGER_METRICS:
        if not values_close(row.get(key), recomputed.get(key)):
            failures.append(
                f"{key}={row.get(key)} ledger_expected={recomputed.get(key)}"
            )
    return failures


def remove_truth_stamp(path: str | None) -> None:
    if not path:
        return
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return


def write_truth_stamp(
    stamp_path: str,
    manifest_info: dict[str, Any],
    expected_artifact_by_client: dict[str, Path],
    measured_required: dict[str, dict[str, Any]],
    *,
    required_rows: tuple[str, ...] = REQUIRED_ROWS,
    kind: str = "native_h3_selected_rows_truth_pass",
    publication_eligible: bool = True,
    get_only_gate: bool = False,
) -> None:
    path = Path(stamp_path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    parser_path = Path(__file__)
    artifact_sha256 = {
        client: file_sha256(expected_artifact_by_client[client])
        for client in required_rows
        if client in expected_artifact_by_client
        and expected_artifact_by_client[client].is_file()
    }
    selected_rows = [
        {
            "competitor_id": competitor_id,
            "workload": measured_required[competitor_id].get("workload"),
            "artifact": measured_required[competitor_id].get("_artifact"),
            "p50_ttfb_ns": measured_required[competitor_id].get("p50_ttfb_ns"),
            "p95_ttfb_ns": measured_required[competitor_id].get("p95_ttfb_ns"),
            "bytes_per_sec": measured_required[competitor_id].get("bytes_per_sec"),
            "ledger_paced_bytes_per_sec": measured_required[competitor_id].get(
                "ledger_paced_bytes_per_sec"
            ),
            "p50_ledger_paced_tail_overhead_ns": measured_required[competitor_id].get(
                "p50_ledger_paced_tail_overhead_ns"
            ),
            "p95_ledger_paced_tail_overhead_ns": measured_required[competitor_id].get(
                "p95_ledger_paced_tail_overhead_ns"
            ),
            "p50_fixture_emission_span_ns": measured_required[competitor_id].get(
                "p50_fixture_emission_span_ns"
            ),
            "p95_fixture_emission_span_ns": measured_required[competitor_id].get(
                "p95_fixture_emission_span_ns"
            ),
            "fixture_ledger_path": measured_required[competitor_id].get("fixture_ledger_path"),
            "fixture_ledger_sha256": measured_required[competitor_id].get("fixture_ledger_sha256"),
            "fixture_ledger_response_count": measured_required[competitor_id].get(
                "fixture_ledger_response_count"
            ),
            "fixture_ledger_required_response_count": measured_required[competitor_id].get(
                "fixture_ledger_required_response_count"
            ),
            "fixture_ledger_sample_offset": measured_required[competitor_id].get(
                "fixture_ledger_sample_offset"
            ),
            "sample_count": measured_required[competitor_id].get("sample_count"),
            "payload_bytes": measured_required[competitor_id].get("payload_bytes"),
            "source": measured_required[competitor_id].get("source"),
            "raw_sample_count": (
                len(measured_required[competitor_id].get("raw_samples"))
                if isinstance(measured_required[competitor_id].get("raw_samples"), list)
                else None
            ),
            "raw_samples_sha256": raw_samples_sha256(measured_required[competitor_id]),
        }
        for competitor_id in required_rows
    ]
    doc = {
        "kind": kind,
        "non_publishable": not publication_eligible,
        "publication_eligible": publication_eligible,
        "scout_gate": False,
        "get_only_gate": get_only_gate,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parser_path": str(parser_path),
        "parser_sha256": file_sha256(parser_path),
        "manifest_path": manifest_info.get("path"),
        "manifest_sha256": manifest_info.get("sha256"),
        "binary_sha256": manifest_info.get("binary_sha256"),
        "selected_clients_sha256": manifest_info.get("selected_clients_sha256"),
        "git_head": manifest_info.get("git_head"),
        "git_dirty": manifest_info.get("git_dirty"),
        "target": manifest_info.get("target"),
        "profile": manifest_info.get("profile"),
        "features": manifest_info.get("features"),
        "runtime_profile": manifest_info.get("runtime_profile"),
        "runtime_env_sha256": manifest_info.get("runtime_env_sha256"),
        "samples": manifest_info.get("samples"),
        "warmups": manifest_info.get("warmups"),
        "high_water_path": os.environ.get("HIGH_WATER_PATH"),
        "high_water_sha256": (
            file_sha256(Path(os.environ["HIGH_WATER_PATH"]))
            if os.environ.get("HIGH_WATER_PATH")
            else None
        ),
        "exit_code": 0,
        "artifact_sha256": artifact_sha256,
        "selected_rows": selected_rows,
    }
    high_water.attach_selected_rows_high_water_comparison(doc, os.environ.get("HIGH_WATER_PATH"))
    with path.open("w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def selected_row_artifacts_from_stamp(stamp: dict[str, Any]) -> list[str]:
    artifacts: list[str] = []
    selected_rows = stamp.get("selected_rows")
    if not isinstance(selected_rows, list):
        return artifacts
    for row in selected_rows:
        if isinstance(row, dict) and isinstance(row.get("artifact"), str):
            artifacts.append(row["artifact"])
    return artifacts


def validate_manifest(
    manifest_path: str | None,
    artifact_paths: list[str],
    min_samples: int,
    *,
    required_rows: tuple[str, ...] = REQUIRED_ROWS,
    publication_eligible: bool = True,
    get_only_gate: bool = False,
) -> tuple[list[str], dict[str, Path], dict[str, Any]]:
    if manifest_path is None:
        return ["FAIL missing_manifest: --manifest is required for the strict selected-row gate"], {}, {}

    failures: list[str] = []
    path = Path(manifest_path)
    try:
        manifest = load_json_strict(path)
    except FileNotFoundError:
        return [f"FAIL missing_manifest: {manifest_path}"], {}, {}
    except json.JSONDecodeError as exc:
        return [
            f"FAIL invalid_manifest_json: {manifest_path} line={exc.lineno} "
            f"column={exc.colno} msg={exc.msg}"
        ], {}, {}
    except ValueError as exc:
        return [f"FAIL invalid_manifest_json: {manifest_path} msg={exc}"], {}, {}
    except OSError as exc:
        return [f"FAIL unreadable_manifest: {manifest_path} error={exc}"], {}, {}

    selected_clients = manifest.get("selected_clients")
    if not isinstance(selected_clients, list) or not all(isinstance(v, str) for v in selected_clients):
        failures.append(f"FAIL invalid_manifest selected_clients artifact={manifest_path}")
        selected_clients = []

    if manifest.get("kind") != "native_h3_selected_rows_manifest":
        failures.append(
            f"FAIL invalid_manifest kind={manifest.get('kind')} artifact={manifest_path}"
        )
    if manifest.get("scout_gate") is not False:
        failures.append(
            "FAIL manifest_scout_gate "
            f"scout_gate={json_value(manifest.get('scout_gate'))} artifact={manifest_path}"
        )
    if manifest.get("publication_eligible") is not publication_eligible:
        failures.append(
            "FAIL manifest_publication_eligible "
            f"publication_eligible={json_value(manifest.get('publication_eligible'))} "
            f"artifact={manifest_path}"
        )
    if get_only_gate:
        if manifest.get("get_only_gate") is not True:
            failures.append(
                "FAIL manifest_get_only_gate "
                f"get_only_gate={json_value(manifest.get('get_only_gate'))} artifact={manifest_path}"
            )
    elif manifest.get("get_only_gate") is True:
        failures.append(
            "FAIL manifest_unexpected_get_only_gate "
            f"get_only_gate={json_value(manifest.get('get_only_gate'))} artifact={manifest_path}"
        )

    requires_fixture_ledger = (
        "http3_streaming_get" in workloads_for_required_rows(required_rows)
        and (publication_eligible or get_only_gate)
    )

    if not isinstance(manifest.get("binary_sha256"), str) or not manifest.get("binary_sha256"):
        failures.append(f"FAIL invalid_manifest binary_sha256 artifact={manifest_path}")
    manifest_sha256 = file_sha256(path)

    expected = list(required_rows)
    if selected_clients != expected:
        failures.append(
            "FAIL manifest_selected_clients_mismatch "
            f"expected={','.join(expected)} actual={','.join(selected_clients)}"
        )
    actual_selected_clients_sha256 = selected_clients_sha256(selected_clients)
    if manifest.get("selected_clients_sha256") != actual_selected_clients_sha256:
        failures.append(
            "FAIL invalid_manifest selected_clients_sha256 "
            f"expected={actual_selected_clients_sha256} actual={manifest.get('selected_clients_sha256')}"
        )
    run_order_required = publication_eligible or get_only_gate
    run_order_declared = "run_order" in manifest or "run_order_sha256" in manifest
    if run_order_required and not run_order_declared:
        failures.append(f"FAIL invalid_manifest run_order_required artifact={manifest_path}")
    run_order = manifest.get("run_order", selected_clients)
    if not isinstance(run_order, list) or not all(isinstance(v, str) for v in run_order):
        failures.append(f"FAIL invalid_manifest run_order artifact={manifest_path}")
        run_order = selected_clients
    elif sorted(run_order) != sorted(selected_clients):
        failures.append(
            "FAIL invalid_manifest run_order_members "
            f"expected={','.join(sorted(selected_clients))} actual={','.join(sorted(run_order))}"
        )
    actual_run_order_sha256 = selected_clients_sha256(run_order)
    if run_order_required and not isinstance(manifest.get("run_order_sha256"), str):
        failures.append(f"FAIL invalid_manifest run_order_sha256 artifact={manifest_path}")
    if (run_order_required or run_order_declared) and manifest.get("run_order_sha256") != actual_run_order_sha256:
        failures.append(
            "FAIL invalid_manifest run_order_sha256 "
            f"expected={actual_run_order_sha256} actual={manifest.get('run_order_sha256')}"
        )

    samples = manifest.get("samples")
    if not isinstance(samples, int) or samples < min_samples:
        failures.append(f"FAIL manifest_samples samples={samples} min_samples={min_samples}")
    warmups = manifest.get("warmups")
    if not isinstance(warmups, int):
        failures.append(f"FAIL invalid_manifest warmups={warmups} artifact={manifest_path}")
    for key in ("git_head", "target", "profile", "features"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            failures.append(f"FAIL invalid_manifest {key} artifact={manifest_path}")
    exact_manifest_values = {
        "target": REQUIRED_TARGET,
        "profile": REQUIRED_PROFILE,
        "features": REQUIRED_FEATURES,
    }
    for key, expected_value in exact_manifest_values.items():
        actual_value = manifest.get(key)
        if actual_value != expected_value:
            failures.append(
                "FAIL invalid_manifest "
                f"{key} expected={expected_value} actual={actual_value}"
            )
    for key in ("runtime_profile", "runtime_env_sha256"):
        if not isinstance(manifest.get(key), str) or not manifest.get(key):
            failures.append(f"FAIL invalid_manifest {key} artifact={manifest_path}")
    expected_runtime_env = required_runtime_env_for_profile(manifest.get("runtime_profile"))
    if expected_runtime_env is None:
        failures.append(
            "FAIL invalid_manifest runtime_profile "
            "expected="
            f"{','.join(RUNTIME_PROFILE_ENV_OVERRIDES)} actual={manifest.get('runtime_profile')}"
        )
        expected_runtime_env = dict(REQUIRED_RUNTIME_ENV)
    runtime_env = manifest.get("runtime_env")
    if not isinstance(runtime_env, dict) or not runtime_env:
        failures.append(f"FAIL invalid_manifest runtime_env artifact={manifest_path}")
    else:
        ledger_gate = runtime_env.get("FIXTURE_LEDGER_GATE") == "1"
        for key, expected_value in expected_runtime_env.items():
            actual_value = runtime_env.get(key)
            if key == "FIXTURE_LEDGER_GATE":
                if requires_fixture_ledger and actual_value != "1":
                    failures.append(
                        "FAIL invalid_manifest runtime_env "
                        f"{key} expected=1 actual={actual_value}"
                    )
                elif actual_value != expected_value and not requires_fixture_ledger:
                    failures.append(
                        "FAIL invalid_manifest runtime_env "
                        f"{key} expected={expected_value} actual={actual_value}"
                    )
            elif key == "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR" and (
                ledger_gate or requires_fixture_ledger
            ):
                if not isinstance(actual_value, str) or not actual_value:
                    failures.append(
                        "FAIL invalid_manifest runtime_env "
                        f"{key} expected=nonempty actual={actual_value}"
                    )
            elif actual_value != expected_value:
                failures.append(
                    "FAIL invalid_manifest runtime_env "
                    f"{key} expected={expected_value} actual={actual_value}"
                )
        extra_keys = sorted(set(runtime_env) - set(expected_runtime_env))
        if extra_keys:
            failures.append(
                "FAIL invalid_manifest runtime_env_extra_keys "
                f"keys={','.join(extra_keys)}"
            )
        actual_runtime_env_sha256 = hashlib.sha256(
            json.dumps(runtime_env, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if manifest.get("runtime_env_sha256") != actual_runtime_env_sha256:
            failures.append(
                "FAIL invalid_manifest runtime_env_sha256 "
                f"expected={actual_runtime_env_sha256} actual={manifest.get('runtime_env_sha256')}"
            )
    if not isinstance(manifest.get("git_head"), str) or not GIT_HEAD_RE.fullmatch(
        manifest.get("git_head", "")
    ):
        failures.append(
            f"FAIL invalid_manifest git_head={manifest.get('git_head')} artifact={manifest_path}"
        )
    if not isinstance(manifest.get("git_dirty"), bool):
        failures.append(f"FAIL invalid_manifest git_dirty artifact={manifest_path}")
    elif manifest.get("git_dirty"):
        failures.append(f"FAIL manifest_git_dirty git_dirty=true artifact={manifest_path}")

    if not path.name.endswith(".manifest.json"):
        failures.append(f"FAIL invalid_manifest_name: {manifest_path}")
        expected_artifact_by_client: dict[str, Path] = {}
    else:
        prefix = str(path)[: -len(".manifest.json")]
        expected_artifact_by_client = {
            client: Path(f"{prefix}.{client}.json") for client in expected
        }

    expected_paths = {
        expected_path.resolve(): client
        for client, expected_path in expected_artifact_by_client.items()
    }
    failures.extend(unexpected_prefix_sibling_artifacts(path, expected_artifact_by_client))
    seen_counts: dict[Path, int] = defaultdict(int)
    for raw_path in artifact_paths:
        candidate = Path(raw_path)
        if candidate.resolve() == path.resolve():
            continue
        resolved = candidate.resolve()
        seen_counts[resolved] += 1
        if resolved not in expected_paths:
            failures.append(f"UNEXPECTED_ARTIFACT {candidate} manifest={manifest_path}")

    for client, expected_path in expected_artifact_by_client.items():
        count = seen_counts.get(expected_path.resolve(), 0)
        if count == 0:
            failures.append(
                f"FAIL missing_required_artifact {client} "
                f"path={expected_path} manifest={manifest_path}"
            )
        elif count > 1:
            failures.append(f"DUPLICATE_ARTIFACT {client} path={expected_path} count={count}")

    manifest_info = {
        "path": str(path),
        "provenance_manifest_path": canonical_manifest_provenance_path(path),
        "sha256": manifest_sha256,
        "binary_sha256": manifest.get("binary_sha256"),
        "selected_clients_sha256": actual_selected_clients_sha256,
        "run_order": run_order,
        "run_order_sha256": actual_run_order_sha256,
        "run_order_declared": run_order_declared,
        "run_order_required": run_order_required,
        "samples": samples,
        "warmups": warmups,
        "git_head": manifest.get("git_head"),
        "git_dirty": manifest.get("git_dirty"),
        "target": manifest.get("target"),
        "profile": manifest.get("profile"),
        "features": manifest.get("features"),
        "runtime_profile": manifest.get("runtime_profile"),
        "runtime_env_sha256": manifest.get("runtime_env_sha256"),
        "runtime_env": runtime_env if isinstance(runtime_env, dict) else {},
        "requires_fixture_ledger": requires_fixture_ledger,
        "scout_gate": manifest.get("scout_gate"),
        "publication_eligible": manifest.get("publication_eligible"),
        "get_only_gate": manifest.get("get_only_gate", False),
    }
    return failures, expected_artifact_by_client, manifest_info


def validate_run_provenance(
    docs: list[tuple[Path, dict[str, Any]]],
    expected_artifact_by_client: dict[str, Path],
    manifest_info: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    docs_by_path = {path.resolve(): doc for path, doc in docs}
    expected_manifest_path = manifest_info.get("provenance_manifest_path")
    for client, artifact_path in expected_artifact_by_client.items():
        doc = docs_by_path.get(artifact_path.resolve())
        if doc is None:
            continue
        provenance = doc.get("run_provenance")
        if not isinstance(provenance, dict):
            failures.append(f"FAIL missing_run_provenance {client} artifact={artifact_path}")
            continue
        provenance_manifest_path = provenance.get("manifest_path")
        if not isinstance(provenance_manifest_path, str) or not provenance_manifest_path:
            failures.append(
                f"FAIL provenance_manifest_path {client} artifact={artifact_path} "
                f"expected={expected_manifest_path} actual={provenance_manifest_path}"
            )
        elif provenance_manifest_path != expected_manifest_path:
            failures.append(
                f"FAIL provenance_manifest_path {client} artifact={artifact_path} "
                f"expected={expected_manifest_path} actual={provenance_manifest_path}"
            )
        checks = {
            "manifest_sha256": manifest_info.get("sha256"),
            "binary_sha256": manifest_info.get("binary_sha256"),
            "selected_clients_sha256": manifest_info.get("selected_clients_sha256"),
            "git_head": manifest_info.get("git_head"),
            "git_dirty": manifest_info.get("git_dirty"),
            "target": manifest_info.get("target"),
            "profile": manifest_info.get("profile"),
            "features": manifest_info.get("features"),
            "runtime_profile": manifest_info.get("runtime_profile"),
            "runtime_env_sha256": manifest_info.get("runtime_env_sha256"),
            "samples": manifest_info.get("samples"),
            "warmups": manifest_info.get("warmups"),
            "scout_gate": manifest_info.get("scout_gate"),
            "publication_eligible": manifest_info.get("publication_eligible"),
            "get_only_gate": manifest_info.get("get_only_gate", False),
        }
        for key, expected in checks.items():
            if provenance.get(key) != expected:
                failures.append(
                    f"FAIL provenance_{key} {client} artifact={artifact_path} "
                    f"expected={expected} actual={provenance.get(key)}"
                )
        if provenance.get("selected_client") != client:
            failures.append(
                f"FAIL provenance_selected_client {client} artifact={artifact_path} "
                f"actual={provenance.get('selected_client')}"
            )
        run_order = manifest_info.get("run_order")
        if (
            isinstance(run_order, list)
            and (
                manifest_info.get("run_order_required")
                or
                manifest_info.get("run_order_declared")
                or provenance.get("run_order") is not None
                or provenance.get("run_order_sha256") is not None
            )
        ):
            if provenance.get("run_order_sha256") != manifest_info.get("run_order_sha256"):
                failures.append(
                    f"FAIL provenance_run_order_sha256 {client} artifact={artifact_path} "
                    f"expected={manifest_info.get('run_order_sha256')} "
                    f"actual={provenance.get('run_order_sha256')}"
                )
            if provenance.get("run_order") != run_order:
                failures.append(
                    f"FAIL provenance_run_order {client} artifact={artifact_path}"
                )
            try:
                expected_sequence_index = run_order.index(client) + 1
            except ValueError:
                expected_sequence_index = None
            if provenance.get("run_sequence_index") != expected_sequence_index:
                failures.append(
                    f"FAIL provenance_run_sequence_index {client} artifact={artifact_path} "
                    f"expected={expected_sequence_index} actual={provenance.get('run_sequence_index')}"
                )
            started_at = provenance.get("run_started_at_unix_ns")
            finished_at = provenance.get("run_finished_at_unix_ns")
            if not isinstance(started_at, int) or started_at <= 0:
                failures.append(
                    f"FAIL provenance_run_started_at_unix_ns {client} artifact={artifact_path} "
                    f"actual={started_at}"
                )
            elif not isinstance(finished_at, int) or finished_at < started_at:
                failures.append(
                    f"FAIL provenance_run_finished_at_unix_ns {client} artifact={artifact_path} "
                    f"actual={finished_at} started={started_at}"
                )
    return failures


def validate_artifact_envelope(
    docs: list[tuple[Path, dict[str, Any]]],
    expected_artifact_by_client: dict[str, Path],
    required_rows: tuple[str, ...],
    *,
    publication_eligible: bool,
    get_only_gate: bool,
) -> list[str]:
    failures: list[str] = []
    expected_paths = {
        artifact_path.resolve(): client
        for client, artifact_path in expected_artifact_by_client.items()
    }
    for path, doc in docs:
        client = expected_paths.get(path.resolve())
        if client is None:
            continue

        if doc.get("benchmark") != REQUIRED_BENCHMARK:
            failures.append(
                f"FAIL artifact_benchmark {client} artifact={path} "
                f"expected={REQUIRED_BENCHMARK} actual={doc.get('benchmark')}"
            )
        if doc.get("benchmark_version") != REQUIRED_BENCHMARK_VERSION:
            failures.append(
                f"FAIL artifact_benchmark_version {client} artifact={path} "
                f"expected={REQUIRED_BENCHMARK_VERSION} actual={doc.get('benchmark_version')}"
            )
        if not isinstance(doc.get("audited_at"), str) or not doc.get("audited_at"):
            failures.append(f"FAIL artifact_audited_at {client} artifact={path}")
        if not isinstance(doc.get("rows"), list):
            failures.append(f"FAIL artifact_rows {client} artifact={path} expected=list")

        provenance = doc.get("run_provenance")
        if not isinstance(provenance, dict):
            failures.append(
                f"FAIL artifact_run_provenance {client} artifact={path} expected=object"
            )

        competitors = doc.get("competitors")
        if not isinstance(competitors, list):
            failures.append(
                f"FAIL artifact_competitors {client} artifact={path} expected=list"
            )
            competitor_ids: set[str] = set()
        else:
            competitor_ids = set()
            duplicate_ids: set[str] = set()
            for index, competitor in enumerate(competitors):
                if not isinstance(competitor, dict):
                    failures.append(
                        f"FAIL artifact_competitor {client} artifact={path} "
                        f"index={index} expected=object"
                    )
                    continue
                competitor_id = competitor.get("id")
                if not isinstance(competitor_id, str) or not competitor_id:
                    failures.append(
                        f"FAIL artifact_competitor_id {client} artifact={path} index={index}"
                    )
                    continue
                if competitor_id in competitor_ids:
                    duplicate_ids.add(competitor_id)
                competitor_ids.add(competitor_id)
            for duplicate_id in sorted(duplicate_ids):
                failures.append(
                    f"FAIL artifact_duplicate_competitor {client} artifact={path} id={duplicate_id}"
                )
        missing_competitors = [
            competitor_id for competitor_id in required_rows if competitor_id not in competitor_ids
        ]
        if missing_competitors:
            failures.append(
                f"FAIL artifact_missing_competitors {client} artifact={path} "
                f"ids={','.join(missing_competitors)}"
            )

        fixture_events = doc.get("fixture_events")
        if not isinstance(fixture_events, list):
            failures.append(
                f"FAIL artifact_fixture_events {client} artifact={path} expected=list"
            )
        else:
            for index, event in enumerate(fixture_events):
                if not isinstance(event, dict):
                    failures.append(
                        f"FAIL artifact_fixture_event {client} artifact={path} "
                        f"index={index} expected=object"
                    )
                    continue
                fatal = event.get("fatal")
                if not isinstance(fatal, bool):
                    failures.append(
                        f"FAIL artifact_fixture_event_fatal {client} artifact={path} "
                        f"index={index} actual={fatal}"
                    )
                    continue
                if (publication_eligible or get_only_gate) and fatal:
                    failures.append(
                        f"FAIL artifact_fatal_fixture_event {client} artifact={path} "
                        f"index={index} category={event.get('category')} "
                        f"classification={event.get('classification')}"
                    )

        gate = doc.get("superiority_gate")
        if not isinstance(gate, dict):
            failures.append(
                f"FAIL artifact_superiority_gate {client} artifact={path} expected=object"
            )
        else:
            if not isinstance(gate.get("status"), str) or not gate.get("status"):
                failures.append(
                    f"FAIL artifact_superiority_gate_status {client} artifact={path}"
                )
            if not isinstance(gate.get("pass"), bool):
                failures.append(
                    f"FAIL artifact_superiority_gate_pass {client} artifact={path}"
                )
            if gate.get("no_h3_superiority_claim_without_all_required_rows") is not True:
                failures.append(
                    "FAIL artifact_superiority_gate_missing_row_policy "
                    f"{client} artifact={path}"
                )
            required_h3_clients = gate.get("required_h3_clients")
            if not isinstance(required_h3_clients, list) or not all(
                isinstance(value, str) for value in required_h3_clients
            ):
                failures.append(
                    f"FAIL artifact_superiority_gate_required_clients {client} artifact={path}"
                )

        rfc_gate = doc.get("rfc9220_full_suite_superiority_gate")
        if not isinstance(rfc_gate, dict):
            failures.append(
                f"FAIL artifact_rfc9220_gate {client} artifact={path} expected=object"
            )
        else:
            if not isinstance(rfc_gate.get("status"), str) or not rfc_gate.get("status"):
                failures.append(f"FAIL artifact_rfc9220_gate_status {client} artifact={path}")
            if not isinstance(rfc_gate.get("pass"), bool):
                failures.append(f"FAIL artifact_rfc9220_gate_pass {client} artifact={path}")
            if (
                rfc_gate.get(
                    "no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows"
                )
                is not True
            ):
                failures.append(
                    "FAIL artifact_rfc9220_gate_missing_row_policy "
                    f"{client} artifact={path}"
                )
            required_rfc9220_clients = rfc_gate.get("required_rfc9220_tunnel_clients")
            if not isinstance(required_rfc9220_clients, list) or not all(
                isinstance(value, str) for value in required_rfc9220_clients
            ):
                failures.append(
                    f"FAIL artifact_rfc9220_gate_required_clients {client} artifact={path}"
                )
    return failures


def reject_phase_trace_artifacts(docs: list[tuple[Path, dict[str, Any]]]) -> list[str]:
    failures: list[str] = []
    for path, doc in docs:
        rows = doc.get("rows")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_samples = row.get("raw_samples")
            if not isinstance(raw_samples, list):
                continue
            for index, sample in enumerate(raw_samples):
                if isinstance(sample, dict) and sample.get("phase_trace") is not None:
                    failures.append(
                        "FAIL phase_trace_non_publishable "
                        f"{row.get('competitor_id')} artifact={path} raw_sample_index={index}"
                    )
                    break
    return failures


def print_row(row: dict[str, Any]) -> None:
    p50 = ms(row.get("p50_ttfb_ns"))
    p95 = ms(row.get("p95_ttfb_ns"))
    rate = mib(row.get("bytes_per_sec"))
    print(
        f"  {row['competitor_id']:38s} "
        f"p50={p50:8.3f}ms p95={p95:8.3f}ms "
        f"MiB/s={rate:8.2f} n={row.get('sample_count')}"
    )
    if row.get("workload") == "http3_streaming_get":
        body_p95 = ms(row.get("p95_paced_body_overhead_ns"))
        tail_p95 = ms(row.get("p95_paced_tail_overhead_ns"))
        if body_p95 is not None and tail_p95 is not None:
            print(
                f"      p95_paced_body_overhead={body_p95:8.3f}ms "
                f"p95_paced_tail_overhead={tail_p95:8.3f}ms"
            )
        ledger_tail_p95 = ms(row.get("p95_ledger_paced_tail_overhead_ns"))
        fixture_span_p95 = ms(row.get("p95_fixture_emission_span_ns"))
        ledger_rate = mib(row.get("ledger_paced_bytes_per_sec"))
        if ledger_tail_p95 is not None and fixture_span_p95 is not None:
            print(
                f"      p95_fixture_emission_span={fixture_span_p95:8.3f}ms "
                f"p95_ledger_paced_tail_overhead={ledger_tail_p95:8.3f}ms"
            )
        if ledger_rate is not None:
            print(f"      ledger_paced_MiB/s={ledger_rate:8.2f}")


def evaluate_selected_rows(
    paths: list[str],
    manifest_path: str | None,
    min_samples: int,
    *,
    emit_rows: bool,
    required_rows: tuple[str, ...] = REQUIRED_ROWS,
    workloads: dict[str, tuple[str, ...]] = WORKLOADS,
    publication_eligible: bool = True,
    get_only_gate: bool = False,
    compare_metrics: bool = True,
) -> tuple[list[str], dict[str, Path], dict[str, Any], dict[str, dict[str, Any]]]:
    initial_failures: list[str] = []
    if not paths:
        initial_failures.append("FAIL missing_artifacts: no selected-row JSON paths provided")

    missing_paths = [path for path in paths if not Path(path).is_file()]
    existing_paths = [path for path in paths if Path(path).is_file()]

    failures, expected_artifact_by_client, manifest_info = validate_manifest(
        manifest_path,
        existing_paths,
        min_samples,
        required_rows=required_rows,
        publication_eligible=publication_eligible,
        get_only_gate=get_only_gate,
    )
    failures.extend(initial_failures)
    for path in missing_paths:
        failures.append(f"FAIL missing_artifact: {path}")

    docs, load_failures = load_docs(existing_paths)
    failures.extend(load_failures)
    failures.extend(
        validate_artifact_envelope(
            docs,
            expected_artifact_by_client,
            required_rows,
            publication_eligible=publication_eligible,
            get_only_gate=get_only_gate,
        )
    )
    failures.extend(validate_run_provenance(docs, expected_artifact_by_client, manifest_info))
    failures.extend(reject_phase_trace_artifacts(docs))
    rows = load_rows(docs)
    best = best_rows_by_id(rows)
    measured_multi = measured_rows_by_id(rows)

    measured_required: dict[str, dict[str, Any]] = {}
    for competitor_id in required_rows:
        expected_artifact = expected_artifact_by_client.get(competitor_id)
        expected_rows = [
            row
            for row in rows
            if row.get("competitor_id") == competitor_id
            and expected_artifact is not None
            and Path(str(row.get("_artifact"))).resolve() == expected_artifact.resolve()
        ]
        measured_from_expected = [
            row
            for row in measured_multi.get(competitor_id, [])
            if expected_artifact is not None
            and Path(str(row.get("_artifact"))).resolve() == expected_artifact.resolve()
        ]
        unexpected_sources = [
            row
            for row in measured_multi.get(competitor_id, [])
            if expected_artifact is None
            or Path(str(row.get("_artifact"))).resolve() != expected_artifact.resolve()
        ]
        for row in unexpected_sources:
            failures.append(
                f"UNEXPECTED_MEASURED_ROW_SOURCE {competitor_id} artifact={row.get('_artifact')} "
                f"expected={expected_artifact}"
            )
        if len(expected_rows) > 1:
            statuses = ",".join(str(row.get("status")) for row in expected_rows)
            failures.append(
                f"DUPLICATE_REQUIRED_ROW {competitor_id} "
                f"artifact={expected_artifact} count={len(expected_rows)} statuses={statuses}"
            )
            continue
        if len(measured_from_expected) > 1:
            failures.append(
                f"DUPLICATE_MEASURED_ROW {competitor_id} "
                f"artifacts={','.join(str(row.get('_artifact')) for row in measured_from_expected)}"
            )
            continue
        row = expected_rows[0] if expected_rows else None
        if row is None:
            best_seen = None
            if expected_artifact is not None:
                best_seen = best_rows_by_id(expected_rows).get(competitor_id)
            if best_seen is None:
                best_seen = best.get(competitor_id)
            if best_seen is None:
                failures.append(
                    f"FAIL missing_required_row {competitor_id} status=absent"
                )
            else:
                failures.append(
                    f"FAIL missing_required_row {competitor_id} "
                    f"best_status={best_seen.get('status')} "
                    f"artifact={best_seen.get('_artifact')}"
                )
            continue
        row_failures = row_complete(row, min_samples, manifest_info)
        if row_failures:
            failures.append(
                f"INVALID_ROW {competitor_id} {';'.join(row_failures)} artifact={row.get('_artifact')}"
            )
            continue
        measured_required[competitor_id] = row

    for workload, required_ids in workloads.items():
        if emit_rows:
            print(f"=== {workload}")
        group = sorted(
            (measured_required[competitor_id] for competitor_id in required_ids if competitor_id in measured_required),
            key=lambda row: row["competitor_id"],
        )
        if emit_rows:
            for row in group:
                print_row(row)
        missing_for_workload = [competitor_id for competitor_id in required_ids if competitor_id not in measured_required]
        if emit_rows:
            for competitor_id in missing_for_workload:
                print(f"  {competitor_id:38s} MISSING")

        if missing_for_workload:
            continue
        if not compare_metrics:
            continue

        ledger_gate = (
            workload == "http3_streaming_get"
            and (
                fixture_ledger_gate_enabled(manifest_info)
                or fixture_ledger_required(manifest_info)
            )
        )
        throughput_metric = (
            "ledger_paced_bytes_per_sec" if ledger_gate else "bytes_per_sec"
        )
        throughput_label = (
            "ledger_paced_throughput" if ledger_gate else "throughput"
        )
        warpsock = [row for row in group if row["competitor_id"].startswith("warpsock_native")]
        comps = [row for row in group if not row["competitor_id"].startswith("warpsock_native")]
        for srow in warpsock:
            for crow in comps:
                if srow["p50_ttfb_ns"] > crow["p50_ttfb_ns"]:
                    failures.append(
                        f"FAIL {workload} {srow['competitor_id']} p50 vs {crow['competitor_id']}"
                    )
                if srow["p95_ttfb_ns"] > crow["p95_ttfb_ns"]:
                    failures.append(
                        f"FAIL {workload} {srow['competitor_id']} p95 vs {crow['competitor_id']}"
                    )
                if workload == "http3_streaming_get":
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
                    if (
                        srow[p50_tail_metric]
                        > crow[p50_tail_metric]
                    ):
                        failures.append(
                            f"FAIL {workload} {srow['competitor_id']} {p50_tail_metric.removesuffix('_ns')} vs {crow['competitor_id']}"
                        )
                    if (
                        srow[p95_tail_metric]
                        > crow[p95_tail_metric]
                    ):
                        failures.append(
                            f"FAIL {workload} {srow['competitor_id']} {p95_tail_metric.removesuffix('_ns')} vs {crow['competitor_id']}"
                        )
                if srow[throughput_metric] < crow[throughput_metric]:
                    failures.append(
                        f"FAIL {workload} {srow['competitor_id']} {throughput_label} vs {crow['competitor_id']}"
                    )

    return failures, expected_artifact_by_client, manifest_info, measured_required


def verify_truth_stamp(stamp_path: str, min_samples: int) -> list[str]:
    path = Path(stamp_path)
    try:
        stamp = load_json_strict(path)
    except FileNotFoundError:
        return [f"FAIL missing_truth_stamp: {stamp_path}"]
    except json.JSONDecodeError as exc:
        return [
            f"FAIL invalid_truth_stamp_json: {stamp_path} line={exc.lineno} "
            f"column={exc.colno} msg={exc.msg}"
        ]
    except ValueError as exc:
        return [f"FAIL invalid_truth_stamp_json: {stamp_path} msg={exc}"]
    except OSError as exc:
        return [f"FAIL unreadable_truth_stamp: {stamp_path} error={exc}"]
    if not isinstance(stamp, dict):
        return [f"FAIL invalid_truth_stamp document_type={type(stamp).__name__}"]

    failures: list[str] = []
    kind = stamp.get("kind")
    if kind == "native_h3_get_rows_truth_pass":
        required_rows = GET_REQUIRED
        workloads = GET_ONLY_WORKLOADS
        publication_eligible = False
        get_only_gate = True
    else:
        required_rows = REQUIRED_ROWS
        workloads = WORKLOADS
        publication_eligible = True
        get_only_gate = False
    if kind not in ("native_h3_selected_rows_truth_pass", "native_h3_get_rows_truth_pass"):
        failures.append(f"FAIL truth_stamp_kind kind={stamp.get('kind')}")
    if stamp.get("publication_eligible") is not publication_eligible:
        failures.append(
            "FAIL truth_stamp_publication_eligible "
            f"publication_eligible={json_value(stamp.get('publication_eligible'))}"
        )
    if stamp.get("scout_gate") is not False:
        failures.append(
            f"FAIL truth_stamp_scout_gate scout_gate={json_value(stamp.get('scout_gate'))}"
        )
    if stamp.get("get_only_gate", False) is not get_only_gate:
        failures.append(
            f"FAIL truth_stamp_get_only_gate get_only_gate={json_value(stamp.get('get_only_gate'))}"
        )
    if stamp.get("exit_code") != 0:
        failures.append(f"FAIL truth_stamp_exit_code exit_code={stamp.get('exit_code')}")
    current_parser_sha256 = file_sha256(Path(__file__))
    if stamp.get("parser_sha256") != current_parser_sha256:
        failures.append(
            "FAIL truth_stamp_parser_sha256 "
            f"expected={current_parser_sha256} actual={stamp.get('parser_sha256')}"
        )
    high_water_path = stamp.get("high_water_path")
    if high_water_path is not None and not isinstance(high_water_path, str):
        failures.append(
            f"FAIL truth_stamp_high_water_path type={type(high_water_path).__name__}"
        )
        high_water_path = None
    if isinstance(high_water_path, str) and high_water_path:
        high_water_file = Path(high_water_path)
        if not high_water_file.is_file():
            failures.append(f"FAIL truth_stamp_high_water_missing path={high_water_path}")
        else:
            actual_high_water_sha256 = file_sha256(high_water_file)
            if stamp.get("high_water_sha256") != actual_high_water_sha256:
                failures.append(
                    "FAIL truth_stamp_high_water_sha256 "
                    f"expected={actual_high_water_sha256} actual={stamp.get('high_water_sha256')}"
                )
    elif stamp.get("high_water_sha256") is not None:
        failures.append(
            f"FAIL truth_stamp_high_water_sha256_without_path actual={stamp.get('high_water_sha256')}"
        )

    selected_rows = stamp.get("selected_rows")
    if not isinstance(selected_rows, list):
        failures.append("FAIL truth_stamp_selected_rows type=non_list")
        selected_rows = []
    selected_ids = [
        row.get("competitor_id") if isinstance(row, dict) else None
        for row in selected_rows
    ]
    if selected_ids != list(required_rows):
        failures.append(
            "FAIL truth_stamp_selected_rows_mismatch "
            f"expected={','.join(required_rows)} actual={','.join(str(v) for v in selected_ids)}"
        )

    artifact_sha256 = stamp.get("artifact_sha256")
    if not isinstance(artifact_sha256, dict):
        failures.append("FAIL truth_stamp_artifact_sha256 type=non_object")
        artifact_sha256 = {}
    artifact_keys = list(artifact_sha256.keys())
    if artifact_keys != list(required_rows):
        failures.append(
            "FAIL truth_stamp_artifact_sha256_keys "
            f"expected={','.join(required_rows)} actual={','.join(str(v) for v in artifact_keys)}"
        )

    manifest_path = stamp.get("manifest_path")
    if not isinstance(manifest_path, str) or not manifest_path:
        failures.append(f"FAIL truth_stamp_manifest_path actual={manifest_path}")
        manifest_path = None
    elif not Path(manifest_path).is_file():
        failures.append(f"FAIL truth_stamp_manifest_missing path={manifest_path}")
    elif stamp.get("manifest_sha256") != file_sha256(Path(manifest_path)):
        failures.append(
            "FAIL truth_stamp_manifest_sha256 "
            f"expected={file_sha256(Path(manifest_path))} actual={stamp.get('manifest_sha256')}"
        )

    artifacts = selected_row_artifacts_from_stamp(stamp)
    if len(artifacts) != len(required_rows):
        failures.append(
            f"FAIL truth_stamp_artifact_count expected={len(required_rows)} actual={len(artifacts)}"
        )

    gate_failures, expected_artifacts, manifest_info, measured_required = evaluate_selected_rows(
        artifacts,
        manifest_path,
        min_samples,
        emit_rows=False,
        required_rows=required_rows,
        workloads=workloads,
        publication_eligible=publication_eligible,
        get_only_gate=get_only_gate,
    )
    failures.extend(f"TRUTH_STAMP_REPLAY {failure}" for failure in gate_failures)

    for key in (
        "manifest_sha256",
        "binary_sha256",
        "selected_clients_sha256",
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
        stamp_key = "manifest_sha256" if key == "manifest_sha256" else key
        expected = manifest_info.get("sha256") if key == "manifest_sha256" else manifest_info.get(key)
        if stamp.get(stamp_key) != expected:
            failures.append(
                f"FAIL truth_stamp_{stamp_key} expected={expected} actual={stamp.get(stamp_key)}"
            )

    for competitor_id in required_rows:
        artifact = expected_artifacts.get(competitor_id)
        if artifact is None:
            continue
        actual_hash = file_sha256(artifact) if artifact.is_file() else None
        stamped_hash = artifact_sha256.get(competitor_id)
        if stamped_hash != actual_hash:
            failures.append(
                f"FAIL truth_stamp_artifact_sha256 {competitor_id} "
                f"expected={actual_hash} actual={stamped_hash} artifact={artifact}"
            )

    selected_by_id = {
        row.get("competitor_id"): row
        for row in selected_rows
        if isinstance(row, dict) and isinstance(row.get("competitor_id"), str)
    }
    for competitor_id in required_rows:
        row = measured_required.get(competitor_id)
        stamped = selected_by_id.get(competitor_id)
        if row is None or stamped is None:
            continue
        expected_artifact = expected_artifacts.get(competitor_id)
        checks = {
            "workload": row.get("workload"),
            "artifact": str(expected_artifact) if expected_artifact is not None else row.get("_artifact"),
            "p50_ttfb_ns": row.get("p50_ttfb_ns"),
            "p95_ttfb_ns": row.get("p95_ttfb_ns"),
            "bytes_per_sec": row.get("bytes_per_sec"),
            "ledger_paced_bytes_per_sec": row.get("ledger_paced_bytes_per_sec"),
            "p50_ledger_paced_tail_overhead_ns": row.get(
                "p50_ledger_paced_tail_overhead_ns"
            ),
            "p95_ledger_paced_tail_overhead_ns": row.get(
                "p95_ledger_paced_tail_overhead_ns"
            ),
            "p50_fixture_emission_span_ns": row.get("p50_fixture_emission_span_ns"),
            "p95_fixture_emission_span_ns": row.get("p95_fixture_emission_span_ns"),
            "fixture_ledger_path": row.get("fixture_ledger_path"),
            "fixture_ledger_sha256": row.get("fixture_ledger_sha256"),
            "fixture_ledger_response_count": row.get("fixture_ledger_response_count"),
            "fixture_ledger_required_response_count": row.get(
                "fixture_ledger_required_response_count"
            ),
            "fixture_ledger_sample_offset": row.get("fixture_ledger_sample_offset"),
            "sample_count": row.get("sample_count"),
            "payload_bytes": row.get("payload_bytes"),
            "source": row.get("source"),
            "raw_sample_count": (
                len(row.get("raw_samples")) if isinstance(row.get("raw_samples"), list) else None
            ),
            "raw_samples_sha256": raw_samples_sha256(row),
        }
        for key, expected in checks.items():
            if stamped.get(key) != expected:
                failures.append(
                    f"FAIL truth_stamp_selected_row {competitor_id} {key} "
                    f"expected={expected} actual={stamped.get(key)}"
                )

    recomputed_high_water_doc = {
        "publication_eligible": publication_eligible,
        "non_publishable": not publication_eligible,
        "artifact_sha256": artifact_sha256,
        "selected_rows": selected_rows,
    }
    try:
        high_water.attach_selected_rows_high_water_comparison(
            recomputed_high_water_doc,
            high_water_path if isinstance(high_water_path, str) and high_water_path else None,
        )
    except Exception as exc:
        failures.append(f"FAIL truth_stamp_high_water_recompute error={exc}")
    expected_high_water = recomputed_high_water_doc.get("high_water_comparison")
    if stamp.get("high_water_comparison") != expected_high_water:
        failures.append(
            "FAIL truth_stamp_high_water_comparison_mismatch "
            f"expected={json_value(expected_high_water)} actual={json_value(stamp.get('high_water_comparison'))}"
        )

    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="selected-row JSON artifacts")
    parser.add_argument(
        "--manifest",
        help="selected-row manifest emitted by current_rows_awsdev.sh; enforces the exact expected client/artifact set",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=int(os.environ.get("CURRENT_ROWS_MIN_SAMPLES", str(HARD_MIN_SAMPLES))),
        help="minimum sample_count required for every selected row; the strict gate never allows less than 100",
    )
    parser.add_argument(
        "--truth-stamp",
        help="write this JSON stamp only when the strict selected-row gate passes; stale stamps are removed on failure",
    )
    parser.add_argument(
        "--verify-truth-stamp",
        help="verify an existing truth-pass stamp by replaying the strict selected-row gate and all stamped hashes",
    )
    parser.add_argument(
        "--get-only",
        action="store_true",
        help="validate the non-publishable all-comparator GET-only truth gate instead of the full publication gate",
    )
    args = parser.parse_args(argv)
    min_samples = max(args.min_samples, HARD_MIN_SAMPLES)
    required_rows = GET_REQUIRED if args.get_only else REQUIRED_ROWS
    workloads = GET_ONLY_WORKLOADS if args.get_only else WORKLOADS
    publication_eligible = not args.get_only
    stamp_kind = (
        "native_h3_get_rows_truth_pass"
        if args.get_only
        else "native_h3_selected_rows_truth_pass"
    )

    if args.verify_truth_stamp:
        if args.truth_stamp or args.manifest or args.paths or args.get_only:
            print("FAIL verify_truth_stamp_exclusive: pass only --verify-truth-stamp and --min-samples")
            return 1
        failures = verify_truth_stamp(args.verify_truth_stamp, min_samples)
        print("=== TRUTH STAMP")
        if failures:
            for failure in failures:
                print(failure)
            return 1
        print("PASS")
        return 0

    paths = expand_input_paths(args.paths) if args.paths else glob.glob("/tmp/current_rows.*.json")
    failures, expected_artifact_by_client, manifest_info, measured_required = evaluate_selected_rows(
        paths,
        args.manifest,
        min_samples,
        emit_rows=True,
        required_rows=required_rows,
        workloads=workloads,
        publication_eligible=publication_eligible,
        get_only_gate=args.get_only,
    )

    print("=== PASS CONTRACT")
    if failures:
        remove_truth_stamp(args.truth_stamp)
        for failure in failures:
            print(failure)
        return 1
    if args.truth_stamp:
        write_truth_stamp(
            args.truth_stamp,
            manifest_info,
            expected_artifact_by_client,
            measured_required,
            required_rows=required_rows,
            kind=stamp_kind,
            publication_eligible=publication_eligible,
            get_only_gate=args.get_only,
        )
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

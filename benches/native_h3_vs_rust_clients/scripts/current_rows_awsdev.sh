#!/usr/bin/env bash
# Run the selected-row native H3 benchmark gate on awsdev.
#
# The selected-row runner emits one artifact per requested client. Keep this
# client list in sync with current_rows_parse.py so missing required comparators
# fail explicitly instead of disappearing from the aggregate result.
set -euo pipefail

if [ -d benches/native_h3_vs_rust_clients ]; then
    repo_root="$PWD"
    bench_dir="$PWD/benches/native_h3_vs_rust_clients"
else
    bench_dir="$PWD"
    repo_root="$(cd ../.. && pwd)"
fi

cd "$bench_dir"
script_path="$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh"
. ~/warpsock/scripts/lib-bssl-env.sh aarch64-unknown-linux-gnu >/dev/null 2>&1
export BORING_BSSL_PATH BORING_BSSL_INCLUDE_PATH
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTFLAGS="--cfg reqwest_unstable"
bench_features="${BENCH_FEATURES:-reqwest-h3}"

# Publication runs must stamp the exact runtime fast-path profile. Missing or
# inherited env cannot be allowed to turn a partial/slow path into a false pass.
: "${WARPSOCK_NATIVE_H3_DIRECT_IDLE_GET:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_GET_EPOCH:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH:=0}"
: "${WARPSOCK_NATIVE_H3_DIRECT_GET_READY_SPIN_US:=25}"
: "${WARPSOCK_NATIVE_H3_DIRECT_GET_BODY_SPIN_US:=$WARPSOCK_NATIVE_H3_DIRECT_GET_READY_SPIN_US}"
: "${WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_MODE:=process}"
: "${WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_TASKSET_CORE:=2}"
: "${WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_PUMP:=inline-first-chunk-v1}"
: "${BENCH_TUNNEL_STEADYSTATE:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_RFC9220_TUNNEL:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_RFC9220_FUSED_ECHO:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_RFC9220_MIXED:=1}"
: "${WARPSOCK_NATIVE_H3_DIRECT_RFC9220_CLOSE_EPOCH:=1}"
export WARPSOCK_NATIVE_H3_DIRECT_IDLE_GET
export WARPSOCK_NATIVE_H3_DIRECT_GET_EPOCH
export WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH
export WARPSOCK_NATIVE_H3_DIRECT_GET_READY_SPIN_US
export WARPSOCK_NATIVE_H3_DIRECT_GET_BODY_SPIN_US
export WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_MODE
export WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_TASKSET_CORE
export WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_PUMP
export BENCH_TUNNEL_STEADYSTATE
export WARPSOCK_NATIVE_H3_DIRECT_RFC9220_TUNNEL
export WARPSOCK_NATIVE_H3_DIRECT_RFC9220_FUSED_ECHO
export WARPSOCK_NATIVE_H3_DIRECT_RFC9220_MIXED
export WARPSOCK_NATIVE_H3_DIRECT_RFC9220_CLOSE_EPOCH
if [ -n "${RUNTIME_PROFILE:-}" ]; then
    runtime_profile="$RUNTIME_PROFILE"
elif [ "$WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH" = "1" ]; then
    runtime_profile="direct-get-io-epoch-rfc9220-fused-echo-close-epoch-mixed"
else
    runtime_profile="direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed"
fi

samples="${SAMPLES:-100}"
warmups="${WARMUPS:-10}"
archive_name="${ARCHIVE_NAME:-}"
if [ -n "$archive_name" ]; then
    case "$archive_name" in
        */* | *..* | "" )
            echo "invalid ARCHIVE_NAME: $archive_name" >&2
            exit 2
            ;;
    esac
    archive_dir="$repo_root/docs/benchmarks/native-h3-vs-rust-clients/$archive_name"
    if [ -e "$archive_dir" ]; then
        echo "archive directory already exists: $archive_dir" >&2
        exit 2
    fi
    mkdir -p "$archive_dir"
    archive_slug="${ARCHIVE_SLUG:-$archive_name}"
    case "$archive_slug" in
        */* | *..* | "" )
            echo "invalid ARCHIVE_SLUG: $archive_slug" >&2
            exit 2
            ;;
    esac
    prefix="$archive_dir/current_rows.$archive_slug"
    provenance_prefix="docs/benchmarks/native-h3-vs-rust-clients/$archive_name/current_rows.$archive_slug"
else
    prefix="${PREFIX:-/tmp/current_rows}"
    provenance_prefix="$prefix"
fi
if [ -n "${PROVENANCE_PREFIX:-}" ]; then
    case "$PROVENANCE_PREFIX" in
        *..* | "" )
            echo "invalid PROVENANCE_PREFIX: $PROVENANCE_PREFIX" >&2
            exit 2
            ;;
    esac
    provenance_prefix="$PROVENANCE_PREFIX"
fi
manifest="$prefix.manifest.json"
provenance_manifest="$provenance_prefix.manifest.json"
truth_stamp="$prefix.truth-pass.json"
get_truth_stamp="$prefix.get-truth-pass.json"
get_repeat_truth_stamp="$prefix.get-repeat-truth-pass.json"
scout_stamp="$prefix.current_rows_scout.json"
pair_scout_stamp="$prefix.current_rows_pair_scout.json"
HIGH_WATER_PATH="${HIGH_WATER_PATH:-$repo_root/docs/benchmarks/native-h3-vs-rust-clients/high_water.native_h3_get.json}"
scout_gate="${SCOUT_GATE:-0}"
get_only_gate="${GET_ONLY_GATE:-0}"
get_repeat_gate="${GET_REPEAT_GATE:-0}"
scout_repeats="${SCOUT_REPEATS:-1}"
get_repeats="${GET_REPEATS:-4}"

# Publication and GET truth gates compare the ledger-derived GET tail metric.
# Make ledger capture the default for those gates and stamp the resolved value
# into the manifest hash. Scout gates can still opt in explicitly.
if [ -z "${FIXTURE_LEDGER_GATE+x}" ]; then
    if [ "$scout_gate" = "1" ]; then
        FIXTURE_LEDGER_GATE=0
    else
        FIXTURE_LEDGER_GATE=1
    fi
fi
: "${WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR:=}"
if [ "$FIXTURE_LEDGER_GATE" = "1" ] && [ -z "$WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR" ]; then
    WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR="$prefix.fixture-ledgers"
fi
export FIXTURE_LEDGER_GATE
export WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR
runtime_env_json="$(
    python3 - <<'PY'
import json
import os

required_keys = [
    "WARPSOCK_NATIVE_H3_DIRECT_IDLE_GET",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_EPOCH",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_READY_SPIN_US",
    "WARPSOCK_NATIVE_H3_DIRECT_GET_BODY_SPIN_US",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_MODE",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_TASKSET_CORE",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_PUMP",
    "BENCH_TUNNEL_STEADYSTATE",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_TUNNEL",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_FUSED_ECHO",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_MIXED",
    "WARPSOCK_NATIVE_H3_DIRECT_RFC9220_CLOSE_EPOCH",
    "FIXTURE_LEDGER_GATE",
    "WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR",
]
captured_prefixes = (
    "WARPSOCK_NATIVE_H3_",
    "WARPSOCK_LOCAL_NATIVE_H3_",
    "WARPSOCK_BENCH_",
    "BENCH_TUNNEL_",
)
keys = set(required_keys)
keys.update(
    key
    for key in os.environ
    if key == "FIXTURE_LEDGER_GATE" or key.startswith(captured_prefixes)
)
print(json.dumps({key: os.environ.get(key, "") for key in sorted(keys)}, sort_keys=True, separators=(",", ":")))
PY
)"
runtime_env_sha256="$(printf '%s' "$runtime_env_json" | sha256sum | awk '{print $1}')"

case "$scout_repeats" in
    ''|*[!0-9]*)
        echo "invalid SCOUT_REPEATS: $scout_repeats" >&2
        exit 2
        ;;
esac
case "$get_repeats" in
    ''|*[!0-9]*)
        echo "invalid GET_REPEATS: $get_repeats" >&2
        exit 2
        ;;
esac
if [ "$scout_repeats" -lt 1 ]; then
    echo "invalid SCOUT_REPEATS: $scout_repeats" >&2
    exit 2
fi
if [ "$get_repeats" -lt 4 ]; then
    echo "GET_REPEATS must be >= 4 for ABBA run-order coverage" >&2
    exit 2
fi
if [ "$scout_repeats" -gt 1 ] && [ "$scout_gate" != "1" ]; then
    echo "SCOUT_REPEATS requires SCOUT_GATE=1" >&2
    exit 2
fi
if [ "$get_only_gate" = "1" ] && [ "$scout_gate" = "1" ]; then
    echo "GET_ONLY_GATE cannot be combined with SCOUT_GATE" >&2
    exit 2
fi
if [ "$get_repeat_gate" = "1" ]; then
    if [ "$get_only_gate" != "1" ]; then
        echo "GET_REPEAT_GATE requires GET_ONLY_GATE=1" >&2
        exit 2
    fi
    if [ "$scout_gate" = "1" ]; then
        echo "GET_REPEAT_GATE cannot be combined with SCOUT_GATE" >&2
        exit 2
    fi

    echo "BUILD $(date -u +%FT%TZ)"
    cargo build --release --features "$bench_features"
    repeat_bin=./target/release/warpsock-native-h3-vs-rust-clients

    repeat_manifests=()
    measurement_rc=0
    for repeat_index in $(seq 1 "$get_repeats"); do
        repeat_label="$(printf 'r%03d' "$repeat_index")"
        repeat_prefix="$prefix.$repeat_label"
        repeat_manifests+=("$repeat_prefix.manifest.json")
        repeat_ledger_dir="$WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR"
        if [ "$FIXTURE_LEDGER_GATE" = "1" ]; then
            repeat_ledger_dir="$repeat_prefix.fixture-ledgers"
        fi
        case $(( (repeat_index - 1) % 4 )) in
            0|3)
                repeat_run_order=canonical
                ;;
            1|2)
                repeat_run_order=reverse
                ;;
        esac
        echo "GET_REPEAT $repeat_index/$get_repeats $(date -u +%FT%TZ)"
        set +e
        GET_REPEAT_GATE=0 \
        GET_ONLY_GATE=1 \
        SCOUT_GATE=0 \
        GET_RUN_ORDER="$repeat_run_order" \
        WARPSOCK_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR="$repeat_ledger_dir" \
        PREFIX="$repeat_prefix" \
        PROVENANCE_PREFIX="$provenance_prefix.$repeat_label" \
        ARCHIVE_NAME= \
        ARCHIVE_SLUG= \
        SAMPLES="$samples" \
        WARMUPS="$warmups" \
        BENCH_FEATURES="$bench_features" \
        CURRENT_ROWS_PREBUILT_BIN="$repeat_bin" \
        RUNTIME_PROFILE="$runtime_profile" \
        HIGH_WATER_PATH="$HIGH_WATER_PATH" \
            "$script_path"
        rc=$?
        set -e
        if [ "$rc" -ne 0 ]; then
            echo "GET_REPEAT_FAIL repeat=$repeat_index rc=$rc prefix=$repeat_prefix" >&2
            measurement_rc=1
        fi
    done

    set +e
    python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py" \
        --get-only \
        --truth-stamp "$get_repeat_truth_stamp" \
        --min-runs "$get_repeats" \
        --min-samples "$samples" \
        "${repeat_manifests[@]}"
    repeat_rc=$?
    set -e
    set +e
    python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py" \
        --verify-truth-stamp "$get_repeat_truth_stamp" \
        --min-runs "$get_repeats" \
        --min-samples "$samples"
    repeat_verify_rc=$?
    set -e
    if [ "$repeat_rc" -ne 0 ] || [ "$repeat_verify_rc" -ne 0 ]; then
        rm -f "$get_repeat_truth_stamp"
    fi
    if [ "$measurement_rc" -ne 0 ] || [ "$repeat_rc" -ne 0 ] || [ "$repeat_verify_rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

if [ -n "${CURRENT_ROWS_PREBUILT_BIN:-}" ]; then
    bin="$CURRENT_ROWS_PREBUILT_BIN"
else
    echo "BUILD $(date -u +%FT%TZ)"
    cargo build --release --features "$bench_features"
    bin=./target/release/warpsock-native-h3-vs-rust-clients
fi
if [ -z "$archive_name" ]; then
    rm -f "$prefix".*.json
fi

clients=(
    warpsock_native
    quiche_direct
    tokio_quiche
    h3_quinn
    reqwest_h3
    warpsock_native_rfc9220_tunnel
    quiche_direct_rfc9220_tunnel
    tokio_quiche_rfc9220_tunnel
    warpsock_native_rfc9220_tunnel_close
    quiche_direct_rfc9220_tunnel_close
    tokio_quiche_rfc9220_tunnel_close
    warpsock_native_rfc9220_tunnel_mixed
    quiche_direct_rfc9220_tunnel_mixed
    tokio_quiche_rfc9220_tunnel_mixed
)
scout_clients=(warpsock_native quiche_direct)
get_only_clients=(warpsock_native quiche_direct tokio_quiche h3_quinn reqwest_h3)

if [ "$scout_gate" = "1" ]; then
    clients=("${scout_clients[@]}")
elif [ "$get_only_gate" = "1" ]; then
    clients=("${get_only_clients[@]}")
fi

bin_sha256="$(sha256sum "$bin" | awk '{print $1}')"
clients_csv="$(IFS=,; echo "${clients[*]}")"
selected_clients_sha256="$(printf '%s' "$clients_csv" | sha256sum | awk '{print $1}')"
get_run_order="${GET_RUN_ORDER:-canonical}"
case "$get_run_order" in
    canonical)
        run_clients=("${clients[@]}")
        ;;
    reverse)
        run_clients=()
        for ((idx=${#clients[@]} - 1; idx >= 0; idx--)); do
            run_clients+=("${clients[$idx]}")
        done
        ;;
    *)
        echo "invalid GET_RUN_ORDER: $get_run_order" >&2
        exit 2
        ;;
esac
run_clients_csv="$(IFS=,; echo "${run_clients[*]}")"
run_order_sha256="$(printf '%s' "$run_clients_csv" | sha256sum | awk '{print $1}')"
if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git_head="$(git -C "$repo_root" rev-parse HEAD)"
    if git -C "$repo_root" diff --quiet --ignore-submodules && git -C "$repo_root" diff --cached --quiet --ignore-submodules; then
        git_dirty=false
    else
        git_dirty=true
    fi
else
    git_head=unknown
    git_dirty=true
fi

if [ "$scout_gate" = "1" ] && [ "$scout_repeats" -gt 1 ]; then
    measurement_rc=0
    repeat_manifests=()
    for repeat_index in $(seq 1 "$scout_repeats"); do
        repeat_label="$(printf 'r%03d' "$repeat_index")"
        repeat_prefix="$prefix.$repeat_label"
        repeat_manifest="$repeat_prefix.manifest.json"
        repeat_manifests+=("$repeat_manifest")
        if [ $((repeat_index % 2)) -eq 1 ]; then
            repeat_clients=(warpsock_native quiche_direct)
        else
            repeat_clients=(quiche_direct warpsock_native)
        fi
        clients_csv="$(IFS=,; echo "${repeat_clients[*]}")"
        selected_clients_sha256="$(printf '%s' "$clients_csv" | sha256sum | awk '{print $1}')"
        SELECTED_CLIENTS="$clients_csv" \
        SELECTED_CLIENTS_SHA256="$selected_clients_sha256" \
        BENCH_FEATURES="$bench_features" \
        RUNTIME_PROFILE="$runtime_profile" \
        RUNTIME_ENV_SHA256="$runtime_env_sha256" \
        RUNTIME_ENV_JSON="$runtime_env_json" \
        GIT_HEAD="$git_head" \
        GIT_DIRTY="$git_dirty" \
        SCOUT_GATE="$scout_gate" \
        SCOUT_REPEAT_INDEX="$repeat_index" \
        SCOUT_REPEAT_COUNT="$scout_repeats" \
        PAIRED_SCOUT=1 \
        python3 - "$repeat_manifest" "$samples" "$warmups" "$bin" "$bin_sha256" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path, samples, warmups, binary, binary_sha256 = sys.argv[1:]
selected_clients = os.environ["SELECTED_CLIENTS"].split(",")
doc = {
    "kind": "native_h3_selected_rows_manifest",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "samples": int(samples),
    "warmups": int(warmups),
    "binary": binary,
    "binary_sha256": binary_sha256,
    "selected_clients": selected_clients,
    "selected_clients_sha256": os.environ["SELECTED_CLIENTS_SHA256"],
    "git_head": os.environ["GIT_HEAD"],
    "git_dirty": os.environ["GIT_DIRTY"] == "true",
    "target": "aarch64-unknown-linux-gnu",
    "profile": "release",
    "features": os.environ["BENCH_FEATURES"],
    "runtime_profile": os.environ["RUNTIME_PROFILE"],
    "runtime_env_sha256": os.environ["RUNTIME_ENV_SHA256"],
    "runtime_env": json.loads(os.environ["RUNTIME_ENV_JSON"]),
    "scout_gate": True,
    "publication_eligible": False,
    "paired_scout": True,
    "scout_repeat_index": int(os.environ["SCOUT_REPEAT_INDEX"]),
    "scout_repeat_count": int(os.environ["SCOUT_REPEAT_COUNT"]),
    "run_order": selected_clients,
}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
        manifest_sha256="$(sha256sum "$repeat_manifest" | awk '{print $1}')"
        for client_index in "${!repeat_clients[@]}"; do
            client="${repeat_clients[$client_index]}"
            paired_run_sequence_index=$((client_index + 1))
            paired_run_started_at_unix_ns="$(date +%s%N)"
            echo "RUN paired repeat=$repeat_index client=$client $(date -u +%FT%TZ)"
            out="$repeat_prefix.$client.json"
            run_provenance="$(
                python3 - "$repeat_manifest" "$manifest_sha256" "$bin" "$bin_sha256" "$git_head" "$git_dirty" "$bench_features" "$runtime_profile" "$runtime_env_sha256" "$samples" "$warmups" "$client" "$selected_clients_sha256" "$scout_gate" "$repeat_index" "$scout_repeats" "$clients_csv" "$paired_run_sequence_index" "$paired_run_started_at_unix_ns" <<'PY'
import json
import sys

(
    manifest_path,
    manifest_sha256,
    binary_path,
    binary_sha256,
    git_head,
    git_dirty,
    features,
    runtime_profile,
    runtime_env_sha256,
    samples,
    warmups,
    selected_client,
    selected_clients_sha256,
    scout_gate,
    scout_repeat_index,
    scout_repeat_count,
    run_order_csv,
    paired_run_sequence_index,
    paired_run_started_at_unix_ns,
) = sys.argv[1:]
print(json.dumps({
    "manifest_path": manifest_path,
    "manifest_sha256": manifest_sha256,
    "binary_path": binary_path,
    "binary_sha256": binary_sha256,
    "git_head": git_head,
    "git_dirty": git_dirty == "true",
    "target": "aarch64-unknown-linux-gnu",
    "profile": "release",
    "features": features,
    "runtime_profile": runtime_profile,
    "runtime_env_sha256": runtime_env_sha256,
    "samples": int(samples),
    "warmups": int(warmups),
    "selected_client": selected_client,
    "selected_clients_sha256": selected_clients_sha256,
    "scout_gate": scout_gate == "1",
    "publication_eligible": False,
    "paired_scout": True,
    "scout_repeat_index": int(scout_repeat_index),
    "scout_repeat_count": int(scout_repeat_count),
    "run_order": run_order_csv.split(","),
    "paired_run_sequence_index": int(paired_run_sequence_index),
    "paired_run_started_at_unix_ns": int(paired_run_started_at_unix_ns),
}, separators=(",", ":")))
PY
            )"
            set +e
            WARPSOCK_BENCH_RUN_PROVENANCE="$run_provenance" taskset -c 4-11 "$bin" \
                --measure-local-native-fixture \
                --measure-local-native-fixture-client "$client" \
                --warmups "$warmups" \
                --samples "$samples" \
                --json "$out"
            rc=$?
            paired_run_finished_at_unix_ns="$(date +%s%N)"
            if [ -f "$out" ]; then
                python3 - "$out" "$paired_run_finished_at_unix_ns" <<'PY'
import json
import sys

path, finished_at = sys.argv[1:]
with open(path) as f:
    doc = json.load(f)
provenance = doc.setdefault("run_provenance", {})
provenance["paired_run_finished_at_unix_ns"] = int(finished_at)
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
            fi
            set -e
            if [ "$rc" -ne 0 ]; then
                echo "RUN_FAIL repeat=$repeat_index client=$client rc=$rc path=$out" >&2
                measurement_rc=1
            fi
        done
    done

    set +e
    python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py" \
        --stamp "$pair_scout_stamp" \
        --min-repeats "$scout_repeats" \
        --min-samples "$samples" \
        "${repeat_manifests[@]}"
    pair_rc=$?
    set -e
    set +e
    python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py" \
        --verify-stamp "$pair_scout_stamp" \
        --min-repeats "$scout_repeats" \
        --min-samples "$samples"
    pair_verify_rc=$?
    set -e
    if [ "$pair_verify_rc" -ne 0 ]; then
        exit 1
    fi
    HIGH_WATER_SUMMARY="$(python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_high_water.py" \
        --stamp "$pair_scout_stamp" \
        --high-water "$HIGH_WATER_PATH")"
    echo "HIGH_WATER_SUMMARY $HIGH_WATER_SUMMARY"
    if [ "$measurement_rc" -ne 0 ] || [ "$pair_rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

SELECTED_CLIENTS="$clients_csv" \
SELECTED_CLIENTS_SHA256="$selected_clients_sha256" \
RUN_ORDER="$run_clients_csv" \
RUN_ORDER_SHA256="$run_order_sha256" \
BENCH_FEATURES="$bench_features" \
RUNTIME_PROFILE="$runtime_profile" \
RUNTIME_ENV_SHA256="$runtime_env_sha256" \
RUNTIME_ENV_JSON="$runtime_env_json" \
GIT_HEAD="$git_head" \
GIT_DIRTY="$git_dirty" \
SCOUT_GATE="$scout_gate" \
GET_ONLY_GATE="$get_only_gate" \
python3 - "$manifest" "$samples" "$warmups" "$bin" "$bin_sha256" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path, samples, warmups, binary, binary_sha256 = sys.argv[1:]
doc = {
    "kind": "native_h3_selected_rows_manifest",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "samples": int(samples),
    "warmups": int(warmups),
    "binary": binary,
    "binary_sha256": binary_sha256,
    "selected_clients": os.environ["SELECTED_CLIENTS"].split(","),
    "selected_clients_sha256": os.environ["SELECTED_CLIENTS_SHA256"],
    "run_order": os.environ["RUN_ORDER"].split(","),
    "run_order_sha256": os.environ["RUN_ORDER_SHA256"],
    "git_head": os.environ["GIT_HEAD"],
    "git_dirty": os.environ["GIT_DIRTY"] == "true",
    "target": "aarch64-unknown-linux-gnu",
    "profile": "release",
    "features": os.environ["BENCH_FEATURES"],
    "runtime_profile": os.environ["RUNTIME_PROFILE"],
    "runtime_env_sha256": os.environ["RUNTIME_ENV_SHA256"],
    "runtime_env": json.loads(os.environ["RUNTIME_ENV_JSON"]),
    "scout_gate": os.environ["SCOUT_GATE"] == "1",
    "get_only_gate": os.environ["GET_ONLY_GATE"] == "1",
    "publication_eligible": os.environ["SCOUT_GATE"] != "1" and os.environ["GET_ONLY_GATE"] != "1",
}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
manifest_sha256="$(sha256sum "$manifest" | awk '{print $1}')"

artifact_paths=()
for client in "${clients[@]}"; do
    artifact_paths+=("$prefix.$client.json")
done

measurement_rc=0
for client_index in "${!run_clients[@]}"; do
    client="${run_clients[$client_index]}"
    run_sequence_index=$((client_index + 1))
    run_started_at_unix_ns="$(date +%s%N)"
    echo "RUN $client $(date -u +%FT%TZ)"
    out="$prefix.$client.json"
    run_provenance="$(
        python3 - "$provenance_manifest" "$manifest_sha256" "$bin" "$bin_sha256" "$git_head" "$git_dirty" "$bench_features" "$runtime_profile" "$runtime_env_sha256" "$samples" "$warmups" "$client" "$selected_clients_sha256" "$scout_gate" "$get_only_gate" "$run_clients_csv" "$run_order_sha256" "$run_sequence_index" "$run_started_at_unix_ns" <<'PY'
import json
import sys

(
    manifest_path,
    manifest_sha256,
    binary_path,
    binary_sha256,
    git_head,
    git_dirty,
    features,
    runtime_profile,
    runtime_env_sha256,
    samples,
    warmups,
    selected_client,
    selected_clients_sha256,
    scout_gate,
    get_only_gate,
    run_order_csv,
    run_order_sha256,
    run_sequence_index,
    run_started_at_unix_ns,
) = sys.argv[1:]
print(json.dumps({
    "manifest_path": manifest_path,
    "manifest_sha256": manifest_sha256,
    "binary_path": binary_path,
    "binary_sha256": binary_sha256,
    "git_head": git_head,
    "git_dirty": git_dirty == "true",
    "target": "aarch64-unknown-linux-gnu",
    "profile": "release",
    "features": features,
    "runtime_profile": runtime_profile,
    "runtime_env_sha256": runtime_env_sha256,
    "samples": int(samples),
    "warmups": int(warmups),
    "selected_client": selected_client,
    "selected_clients_sha256": selected_clients_sha256,
    "scout_gate": scout_gate == "1",
    "get_only_gate": get_only_gate == "1",
    "publication_eligible": scout_gate != "1" and get_only_gate != "1",
    "run_order": run_order_csv.split(","),
    "run_order_sha256": run_order_sha256,
    "run_sequence_index": int(run_sequence_index),
    "run_started_at_unix_ns": int(run_started_at_unix_ns),
}, separators=(",", ":")))
PY
    )"
    set +e
    WARPSOCK_BENCH_RUN_PROVENANCE="$run_provenance" taskset -c 4-11 "$bin" \
        --measure-local-native-fixture \
        --measure-local-native-fixture-client "$client" \
        --warmups "$warmups" \
        --samples "$samples" \
        --json "$out"
    rc=$?
    run_finished_at_unix_ns="$(date +%s%N)"
    if [ -f "$out" ]; then
        python3 - "$out" "$run_finished_at_unix_ns" "$prefix.fixture-ledgers" "$provenance_prefix.fixture-ledgers" <<'PY'
import json
import sys
from pathlib import Path

path, finished_at, actual_ledger_dir, provenance_ledger_dir = sys.argv[1:]
with open(path) as f:
    doc = json.load(f)
provenance = doc.setdefault("run_provenance", {})
provenance["run_finished_at_unix_ns"] = int(finished_at)
actual_ledger_dir = Path(actual_ledger_dir)
provenance_ledger_dir = Path(provenance_ledger_dir)
for row in doc.get("rows", []):
    raw_ledger_path = row.get("fixture_ledger_path")
    if not isinstance(raw_ledger_path, str) or not raw_ledger_path:
        continue
    ledger_path = Path(raw_ledger_path)
    try:
        if ledger_path.parent.resolve() != actual_ledger_dir.resolve():
            continue
    except OSError:
        continue
    row["fixture_ledger_path"] = str(provenance_ledger_dir / ledger_path.name)
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
    fi
    set -e
    if [ "$rc" -ne 0 ]; then
        echo "RUN_FAIL $client rc=$rc path=$out" >&2
        measurement_rc=1
    fi
done

if [ "$get_only_gate" = "1" ]; then
    # Non-publishable all-comparator GET truth gate. This is the fast iteration
    # guard for GET-only architectural scouts: every required GET comparator
    # must be present and structurally valid, but RFC9220 rows are intentionally
    # outside this stamp. Full publication still goes through the selected-row
    # truth gate below with GET + RFC9220 required rows.
    set +e
    if [ "$measurement_rc" -ne 0 ]; then
        rm -f "$get_truth_stamp"
        CURRENT_ROWS_MIN_SAMPLES="$samples" \
            python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
                --get-only \
                --manifest "$manifest" \
                "${artifact_paths[@]}"
        parse_rc=$?
        verify_rc=1
    else
        CURRENT_ROWS_MIN_SAMPLES="$samples" \
            python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
                --get-only \
                --manifest "$manifest" \
                --truth-stamp "$get_truth_stamp" \
                "${artifact_paths[@]}"
        parse_rc=$?
        if [ "$parse_rc" -eq 0 ]; then
            CURRENT_ROWS_MIN_SAMPLES="$samples" \
                python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
                    --verify-truth-stamp "$get_truth_stamp"
            verify_rc=$?
        else
            verify_rc=1
        fi
    fi
    if [ "$parse_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; then
        rm -f "$get_truth_stamp"
    fi
    set -e
    if [ "$measurement_rc" -ne 0 ] || [ "$parse_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

if [ "$scout_gate" = "1" ]; then
    # Scout stamp JSON includes \`"non_publishable": true\` and
    # \`"publication_eligible": false\`. It is an iteration accelerator only:
    # the full selected-row parser/truth stamp remains the publication gate.
    set +e
    python3 - "$repo_root/benches/native_h3_vs_rust_clients/scripts" "$scout_stamp" "$manifest" "$samples" "${artifact_paths[@]}" <<'PY'
import json
import sys
from pathlib import Path

script_dir = Path(sys.argv[1])
sys.path.insert(0, str(script_dir))
import current_rows_parse as one

stamp_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
requested_samples = int(sys.argv[4])
artifact_paths = [Path(p) for p in sys.argv[5:]]
failures = []
rows = []
artifact_sha256 = {}

try:
    manifest = json.loads(manifest_path.read_text())
except Exception as exc:
    manifest = {}
    failures.append(f"manifest_unreadable path={manifest_path} error={exc}")
manifest_sha256 = one.file_sha256(manifest_path) if manifest_path.is_file() else None
prefix = (
    str(manifest_path)[: -len(".manifest.json")]
    if str(manifest_path).endswith(".manifest.json")
    else str(manifest_path)
)
clients = ["warpsock_native", "quiche_direct"]
expected_artifact_by_client = {client: Path(f"{prefix}.{client}.json") for client in clients}
manifest_info = {
    "path": str(manifest_path),
    "resolved_path": str(manifest_path.resolve()),
    "sha256": manifest_sha256,
    "binary_sha256": manifest.get("binary_sha256"),
    "selected_clients_sha256": manifest.get("selected_clients_sha256"),
    "git_head": manifest.get("git_head"),
    "git_dirty": manifest.get("git_dirty"),
    "target": manifest.get("target"),
    "profile": manifest.get("profile"),
    "features": manifest.get("features"),
    "samples": manifest.get("samples"),
    "warmups": manifest.get("warmups"),
    "scout_gate": True,
    "publication_eligible": False,
}

for path in artifact_paths:
    if path.exists():
        artifact_sha256[str(path)] = one.file_sha256(path)
for client, path in expected_artifact_by_client.items():
    if not path.exists():
        failures.append(f"missing_artifact client={client} path={path}")

docs, load_failures = one.load_docs([str(path) for path in artifact_paths if path.exists()])
failures.extend(load_failures)
failures.extend(one.validate_run_provenance(docs, expected_artifact_by_client, manifest_info))
failures.extend(one.reject_phase_trace_artifacts(docs))
rows = one.load_rows(docs)
measured_multi = one.measured_rows_by_id(rows)

def measured_get(client):
    expected_artifact = expected_artifact_by_client[client].resolve()
    matches = [
        row
        for row in measured_multi.get(client, [])
        if Path(str(row.get("_artifact"))).resolve() == expected_artifact
    ]
    if len(matches) != 1:
        failures.append(f"row_count client={client} count={len(matches)}")
        return None
    row = matches[0]
    row_failures = one.row_complete(row, max(100, requested_samples), manifest_info)
    if row.get("workload") != "http3_streaming_get":
        row_failures.append(f"workload={row.get('workload')} expected=http3_streaming_get")
    if row_failures:
        failures.append(
            f"invalid_row client={client} {';'.join(row_failures)} artifact={row.get('_artifact')}"
        )
        return None
    return row

warpsock = measured_get("warpsock_native")
quiche = measured_get("quiche_direct")
metric_edges = {}
if warpsock and quiche:
    metric_edges = {
        "warpsock_p50_ttfb_ns": warpsock.get("p50_ttfb_ns"),
        "quiche_direct_p50_ttfb_ns": quiche.get("p50_ttfb_ns"),
        "warpsock_p95_ttfb_ns": warpsock.get("p95_ttfb_ns"),
        "quiche_direct_p95_ttfb_ns": quiche.get("p95_ttfb_ns"),
        "warpsock_bytes_per_sec": warpsock.get("bytes_per_sec"),
        "quiche_direct_bytes_per_sec": quiche.get("bytes_per_sec"),
    }
    if warpsock.get("p50_ttfb_ns") > quiche.get("p50_ttfb_ns"):
        failures.append("metric_miss p50 warpsock_native_vs_quiche_direct")
    if warpsock.get("p95_ttfb_ns") > quiche.get("p95_ttfb_ns"):
        failures.append("metric_miss p95 warpsock_native_vs_quiche_direct")
    if warpsock.get("bytes_per_sec") < quiche.get("bytes_per_sec"):
        failures.append("metric_miss throughput warpsock_native_vs_quiche_direct")

doc = {
    "kind": "current_rows_scout",
    "non_publishable": True,
    "publication_eligible": False,
    "requested_samples": requested_samples,
    "parser_path": str(script_dir / "current_rows_parse.py"),
    "parser_sha256": one.file_sha256(script_dir / "current_rows_parse.py"),
    "manifest_path": str(manifest_path),
    "manifest_sha256": manifest_sha256,
    "binary_sha256": manifest.get("binary_sha256"),
    "selected_clients_sha256": manifest.get("selected_clients_sha256"),
    "features": manifest.get("features"),
    "clients": clients,
    "artifact_sha256": artifact_sha256,
    "metric_edges": metric_edges,
    "failures": failures,
    "pass": not failures,
}
with stamp_path.open("w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")

if failures:
    print("SCOUT_FAIL " + "; ".join(failures))
    sys.exit(1)
print("SCOUT_PASS")
PY
    scout_rc=$?
    set -e
    if [ "$measurement_rc" -ne 0 ] || [ "$scout_rc" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

set +e
if [ "$measurement_rc" -ne 0 ]; then
    rm -f "$truth_stamp"
    CURRENT_ROWS_MIN_SAMPLES="$samples" \
        python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
            --manifest "$manifest" \
            "${artifact_paths[@]}"
    parse_rc=$?
    verify_rc=1
else
    CURRENT_ROWS_MIN_SAMPLES="$samples" \
        python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
            --manifest "$manifest" \
            --truth-stamp "$truth_stamp" \
            "${artifact_paths[@]}"
    parse_rc=$?
    if [ "$parse_rc" -eq 0 ]; then
        CURRENT_ROWS_MIN_SAMPLES="$samples" \
            python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py" \
                --verify-truth-stamp "$truth_stamp"
        verify_rc=$?
        if [ "$verify_rc" -eq 0 ]; then
            HIGH_WATER_SUMMARY="$(python3 "$repo_root/benches/native_h3_vs_rust_clients/scripts/current_rows_high_water.py" \
                --stamp "$truth_stamp" \
                --high-water "$HIGH_WATER_PATH")"
            echo "HIGH_WATER_SUMMARY $HIGH_WATER_SUMMARY"
        fi
    else
        verify_rc=1
    fi
fi
if [ "$parse_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; then
    rm -f "$truth_stamp"
fi
set -e

if [ "$measurement_rc" -ne 0 ] || [ "$parse_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; then
    exit 1
fi

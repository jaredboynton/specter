fn native_h3_required_runtime_env() -> serde_json::Value {
    serde_json::json!({
        "BENCH_TUNNEL_STEADYSTATE": "1",
        "FIXTURE_LEDGER_GATE": "1",
        "SPECTER_LOCAL_NATIVE_H3_FIXTURE_LEDGER_DIR": "fixture-ledgers",
        "SPECTER_LOCAL_NATIVE_H3_FIXTURE_MODE": "process",
        "SPECTER_LOCAL_NATIVE_H3_FIXTURE_PUMP": "inline-first-chunk-v1",
        "SPECTER_LOCAL_NATIVE_H3_FIXTURE_TASKSET_CORE": "2",
        "SPECTER_NATIVE_H3_DIRECT_GET_EPOCH": "1",
        "SPECTER_NATIVE_H3_DIRECT_GET_IO_EPOCH": "0",
        "SPECTER_NATIVE_H3_DIRECT_GET_READY_SPIN_US": "25",
        "SPECTER_NATIVE_H3_DIRECT_GET_BODY_SPIN_US": "25",
        "SPECTER_NATIVE_H3_DIRECT_IDLE_GET": "1",
        "SPECTER_NATIVE_H3_DIRECT_RFC9220_CLOSE_EPOCH": "1",
        "SPECTER_NATIVE_H3_DIRECT_RFC9220_FUSED_ECHO": "1",
        "SPECTER_NATIVE_H3_DIRECT_RFC9220_MIXED": "1",
        "SPECTER_NATIVE_H3_DIRECT_RFC9220_TUNNEL": "1"
    })
}

fn native_h3_required_runtime_env_sha256() -> String {
    "56d1695137a60a9ac53b3d2f521c3e6b5fc5e64cce2d0c01b90a92146aa6920f".to_string()
}

fn write_synthetic_fixture_ledger(path: &std::path::Path, client: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut ledger = String::new();
    for response_id in 0..110 {
        for chunk_index in 0..5 {
            let send_start_ns = response_id * 10_000_000 + chunk_index * 1_000_000;
            let send_done_ns = send_start_ns + 100_000;
            let entry = serde_json::json!({
                "kind": "local_native_h3_fixture_stream_chunk",
                "client": client,
                "stream_id": response_id * 4,
                "response_id": response_id,
                "chunk_index": chunk_index,
                "due_ns": send_start_ns,
                "send_start_ns": send_start_ns,
                "send_done_ns": send_done_ns,
                "bytes": 16 * 1024,
                "fin": chunk_index == 4,
            });
            ledger.push_str(&entry.to_string());
            ledger.push('\n');
        }
    }
    std::fs::write(path, ledger.as_bytes()).expect("synthetic fixture ledger should be written");
    let mut hasher = Sha256::new();
    hasher.update(ledger.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn synthetic_artifact_fixture_ledger_path(
    artifact: &std::path::Path,
    client: &str,
) -> std::path::PathBuf {
    let file_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .expect("synthetic artifact should have utf8 file name");
    let suffix = format!(".{client}.json");
    let prefix = file_name
        .strip_suffix(&suffix)
        .expect("synthetic artifact name should end with client suffix");
    artifact
        .parent()
        .expect("synthetic artifact should have parent")
        .join(format!("{prefix}.fixture-ledgers"))
        .join(format!("fixture-ledger.{client}.jsonl"))
}

fn synthetic_ledger_paced_bytes_per_sec(payload_bytes: u64, ttfb_ns: f64) -> f64 {
    (payload_bytes as f64) * 100.0 * 1_000_000_000.0 / ((ttfb_ns + 4_000_000.0) * 100.0)
}

#[test]
fn native_h3_competitor_benchmark_is_isolated_and_covers_known_fast_clients() {
    let main_manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml should exist");
    assert!(
        !main_manifest
            .lines()
            .any(|line| line.trim_start().starts_with("quiche =")),
        "Specter itself must stay quiche-free; competitor dependencies belong in the isolated benchmark crate"
    );

    let bench_manifest = std::fs::read_to_string("benches/native_h3_vs_rust_clients/Cargo.toml")
        .expect("isolated native H3 competitor benchmark manifest should exist");
    for required in [
        "quiche = { version = \"0.29.0\"",
        "tokio-quiche = \"0.19.0\"",
        "h3 = \"0.0.8\"",
        "h3-quinn = \"0.0.10\"",
        "reqwest = { version = \"0.13.3\"",
        "quinn = \"0.11.9\"",
        "s2n-quic = { version = \"1.80.0\"",
    ] {
        assert!(
            bench_manifest.contains(required),
            "competitor benchmark manifest must include {required}"
        );
    }
    assert!(
        bench_manifest.contains("reqwest-h3 = [\"reqwest/http3\"]"),
        "reqwest HTTP/3 must be explicitly enabled through the unstable HTTP/3 feature"
    );

    let bench_source = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("isolated native H3 competitor benchmark source should exist");
    for required in [
        "specter_native",
        "quiche_direct",
        "tokio_quiche",
        "h3_quinn",
        "reqwest_h3",
        "quinn_transport",
        "s2n_quic_transport",
        "--require-superiority",
        "--specter-streaming-artifact",
        "--measure-local-native-fixture",
        "--measure-specter-native-url",
        "--measure-specter-native-rfc9220-tunnel-url",
        "--measure-quiche-direct-rfc9220-tunnel-url",
        "--measure-tokio-quiche-rfc9220-tunnel-url",
        "--measure-quiche-direct-url",
        "--measure-tokio-quiche-url",
        "--measure-h3-quinn-url",
        "--measure-reqwest-h3-url",
        "--measure-quinn-transport-url",
        "--measure-s2n-quic-transport-url",
        "--s2n-quic-cert",
        "streaming_vs_reqwest_h3_artifact",
        "fastest_non_specter_h3_client",
        "no_h3_superiority_claim_without_all_required_rows",
        "SPECTER_BENCH_PHASE_TRACE",
        "phase_trace: Option<PhaseTraceSample>",
        "send_streaming_parts_with_phase_trace",
        "headers_oneshot_sent_ns",
        "caller_headers_ready_ns",
    ] {
        assert!(
            bench_source.contains(required),
            "competitor benchmark source must include {required}"
        );
    }
}

#[test]
fn native_h3_http_gate_reports_missing_specter_row_explicitly() {
    let bench_source = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("isolated native H3 competitor benchmark source should exist");
    for required in [
        r#"let required_h3_measurement_rows = std::iter::once("specter_native")"#,
        "let missing_required_rows = required_h3_measurement_rows",
        "no_h3_superiority_claim_without_all_required_rows",
    ] {
        assert!(
            bench_source.contains(required),
            "HTTP H3 gate must treat a missing specter_native row as a missing required row: {required}"
        );
    }
}

#[test]
fn native_h3_repeat_gate_rejects_duplicate_repeat_identities() {
    let repeat_parser = std::fs::read_to_string(
        "benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py",
    )
    .expect("selected-row repeat parser source should exist");

    for required in [
        "repeat_duplicate_{label}",
        "manifest_path",
        "manifest_sha256",
        "artifact_set_sha256",
        "raw_samples_set_sha256",
        "run_identities",
        "--verify-truth-stamp",
        "verify_truth_stamp",
        "REPEAT_TRUTH_STAMP_REPLAY",
    ] {
        assert!(
            repeat_parser.contains(required),
            "repeat parser must fail closed on duplicated repeat evidence: {required}"
        );
    }
}

#[test]
fn native_h3_selected_row_runner_has_non_publishable_scout_gate() {
    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");

    for required in [
        "SCOUT_GATE",
        "BENCH_FEATURES",
        "scout_clients=(specter_native quiche_direct)",
        "current_rows_scout",
        "parser_sha256",
        "validate_run_provenance",
        "reject_phase_trace_artifacts",
        r#""non_publishable": true"#,
        r#""publication_eligible": false"#,
        "SCOUT_FAIL",
    ] {
        assert!(
            runner.contains(required),
            "selected-row runner must expose a non-publishable bottleneck scout mode: {required}"
        );
    }
}

#[test]
fn native_h3_selected_row_runner_captures_unknown_benchmark_env() {
    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");
    let parser =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
            .expect("selected-row parser source should exist");

    for required in [
        "required_keys = [",
        "captured_prefixes = (",
        r#""SPECTER_NATIVE_H3_","#,
        r#""SPECTER_LOCAL_NATIVE_H3_","#,
        r#""SPECTER_BENCH_","#,
        r#""BENCH_TUNNEL_","#,
        r#"key == "FIXTURE_LEDGER_GATE""#,
        "key.startswith(captured_prefixes)",
    ] {
        assert!(
            runner.contains(required),
            "selected-row runner must stamp unknown benchmark-affecting env so the parser can fail closed: {required}"
        );
    }
    assert!(
        parser.contains("runtime_env_extra_keys"),
        "selected-row parser must reject unknown stamped runtime env keys"
    );
}

#[test]
fn native_h3_selected_row_runner_stamps_archive_provenance_portably() {
    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");

    for required in [
        r#"provenance_prefix="docs/benchmarks/native-h3-vs-rust-clients/$archive_name/current_rows.$archive_slug""#,
        r#"provenance_prefix="$prefix""#,
        r#"provenance_manifest="$provenance_prefix.manifest.json""#,
        r#"python3 - "$provenance_manifest" "$manifest_sha256""#,
    ] {
        assert!(
            runner.contains(required),
            "selected-row archive provenance must be portable while scout prefixes remain exact: {required}"
        );
    }
}

#[test]
fn native_h3_selected_row_parser_accepts_portable_archive_manifest_provenance() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn sha256_file(path: &std::path::Path) -> String {
        sha256_bytes(&std::fs::read(path).expect("hash input should be readable"))
    }

    let selected_clients = [
        ("specter_native", "http3_streaming_get", 16 * 1024 * 5),
        ("quiche_direct", "http3_streaming_get", 16 * 1024 * 5),
        ("tokio_quiche", "http3_streaming_get", 16 * 1024 * 5),
        ("h3_quinn", "http3_streaming_get", 16 * 1024 * 5),
        ("reqwest_h3", "http3_streaming_get", 16 * 1024 * 5),
        (
            "specter_native_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "quiche_direct_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "tokio_quiche_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "specter_native_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "quiche_direct_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "tokio_quiche_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "specter_native_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
        (
            "quiche_direct_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
        (
            "tokio_quiche_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
    ];
    let selected_client_ids = selected_clients
        .iter()
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let competitors = selected_client_ids
        .iter()
        .map(|client| json!({ "id": client }))
        .collect::<Vec<_>>();
    let required_h3_clients = selected_clients
        .iter()
        .filter(|(_, workload, _)| *workload == "http3_streaming_get")
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let required_rfc9220_tunnel_clients = selected_clients
        .iter()
        .filter(|(_, workload, _)| *workload != "http3_streaming_get")
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let selected_clients_sha256 = sha256_bytes(selected_client_ids.join(",").as_bytes());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "specter-native-h3-portable-provenance-{}-{unique}",
        std::process::id()
    ));
    let archive = root.join("docs/benchmarks/native-h3-vs-rust-clients/test-portable");
    std::fs::create_dir_all(&archive).expect("archive temp dir should be created");
    let manifest = archive.join("current_rows.portable.manifest.json");
    let relative_manifest =
        "docs/benchmarks/native-h3-vs-rust-clients/test-portable/current_rows.portable.manifest.json";
    let binary_sha256 = "abc123";
    let git_head = "0123456789abcdef0123456789abcdef01234567";
    let runtime_env = native_h3_required_runtime_env();
    let runtime_env_sha256 = native_h3_required_runtime_env_sha256();
    let manifest_doc = json!({
        "kind": "native_h3_selected_rows_manifest",
        "samples": 100,
        "warmups": 10,
        "binary_sha256": binary_sha256,
        "selected_clients": selected_client_ids,
        "selected_clients_sha256": selected_clients_sha256,
        "run_order": selected_client_ids,
        "run_order_sha256": selected_clients_sha256,
        "git_head": git_head,
        "git_dirty": false,
        "target": "aarch64-unknown-linux-gnu",
        "profile": "release",
        "features": "reqwest-h3",
        "runtime_profile": "direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed",
        "runtime_env": runtime_env,
        "runtime_env_sha256": runtime_env_sha256,
        "scout_gate": false,
        "publication_eligible": true,
        "get_only_gate": false
    });
    std::fs::write(
        &manifest,
        serde_json::to_vec_pretty(&manifest_doc).expect("manifest should serialize"),
    )
    .expect("manifest should be written");
    let manifest_sha256 = sha256_file(&manifest);

    let mut artifact_paths = Vec::new();
    for (client, workload, payload_bytes) in selected_clients {
        let run_sequence_index = selected_client_ids
            .iter()
            .position(|id| *id == client)
            .expect("selected client should be present in run order")
            + 1;
        let run_started_at_unix_ns = 1_000_000_000u64 + run_sequence_index as u64 * 1_000_000;
        let run_finished_at_unix_ns = run_started_at_unix_ns + 100_000;
        let artifact = archive.join(format!("current_rows.portable.{client}.json"));
        let raw_samples = (0..100)
            .map(|_| {
                json!({
                    "ttfb_ns": 1000,
                    "first_body_ns": 1010,
                    "total_ns": 1_000_000,
                    "bytes": payload_bytes
                })
            })
            .collect::<Vec<_>>();
        let mut row = json!({
            "competitor_id": client,
            "status": "measured_pass",
            "source": format!("{client}_adapter"),
            "workload": workload,
            "payload_bytes": payload_bytes,
            "sample_count": 100,
            "requested_samples": 100,
            "completed_samples": 100,
            "requested_warmups": 10,
            "completed_warmups": 10,
            "p50_ttfb_ns": 1000,
            "p95_ttfb_ns": 1000,
            "bytes_per_sec": payload_bytes * 1000,
            "raw_samples": raw_samples
        });
        if workload == "http3_streaming_get" {
            let ledger_path = synthetic_artifact_fixture_ledger_path(&artifact, client);
            std::fs::create_dir_all(
                ledger_path
                    .parent()
                    .expect("synthetic ledger path should have parent"),
            )
            .expect("fixture ledger dir should be created");
            let ledger_sha256 = write_synthetic_fixture_ledger(&ledger_path, client);
            let relative_ledger_path = ledger_path
                .strip_prefix(&root)
                .expect("synthetic ledger path should be under archive root")
                .to_string_lossy()
                .into_owned();
            row["fixture_pace_span_ns"] = json!(4_000_000.0);
            row["p50_paced_body_overhead_ns"] = json!(0.0);
            row["p95_paced_body_overhead_ns"] = json!(0.0);
            row["p50_paced_tail_overhead_ns"] = json!(0.0);
            row["p95_paced_tail_overhead_ns"] = json!(0.0);
            row["fixture_ledger_path"] = json!(relative_ledger_path);
            row["fixture_ledger_sha256"] = json!(ledger_sha256);
            row["fixture_ledger_response_count"] = json!(110);
            row["fixture_ledger_required_response_count"] = json!(110);
            row["fixture_ledger_sample_offset"] = json!(10);
            row["p50_fixture_emission_span_ns"] = json!(4_100_000.0);
            row["p95_fixture_emission_span_ns"] = json!(4_100_000.0);
            row["p50_ledger_paced_tail_overhead_ns"] = json!(0.0);
            row["p95_ledger_paced_tail_overhead_ns"] = json!(0.0);
            row["ledger_paced_bytes_per_sec"] = json!(synthetic_ledger_paced_bytes_per_sec(
                payload_bytes as u64,
                1000.0
            ));
        }
        let doc = json!({
            "benchmark": "native_h3_vs_rust_clients",
            "benchmark_version": "matrix-1",
            "audited_at": "2026-06-08T00:00:00Z",
            "competitors": competitors.clone(),
            "fixture_events": [],
            "superiority_gate": {
                "status": "pass",
                "pass": true,
                "no_h3_superiority_claim_without_all_required_rows": true,
                "required_h3_clients": required_h3_clients.clone(),
            },
            "rfc9220_full_suite_superiority_gate": {
                "status": "pass",
                "pass": true,
                "no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows": true,
                "required_rfc9220_tunnel_clients": required_rfc9220_tunnel_clients.clone(),
            },
            "run_provenance": {
                "manifest_path": relative_manifest,
                "manifest_sha256": manifest_sha256,
                "binary_sha256": binary_sha256,
                "selected_clients_sha256": selected_clients_sha256,
                "run_order": selected_client_ids,
                "run_order_sha256": selected_clients_sha256,
                "git_head": git_head,
                "git_dirty": false,
                "target": "aarch64-unknown-linux-gnu",
                "profile": "release",
                "features": "reqwest-h3",
                "runtime_profile": "direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed",
                "runtime_env_sha256": runtime_env_sha256,
                "samples": 100,
                "warmups": 10,
                "scout_gate": false,
                "publication_eligible": true,
                "get_only_gate": false,
                "selected_client": client,
                "run_sequence_index": run_sequence_index,
                "run_started_at_unix_ns": run_started_at_unix_ns,
                "run_finished_at_unix_ns": run_finished_at_unix_ns
            },
            "rows": [row]
        });
        std::fs::write(
            &artifact,
            serde_json::to_vec_pretty(&doc).expect("artifact should serialize"),
        )
        .expect("artifact should be written");
        artifact_paths.push(artifact);
    }

    let truth_stamp = archive.join("current_rows.portable.truth-pass.json");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--truth-stamp")
        .arg(&truth_stamp)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");

    assert!(
        output.status.success(),
        "portable archive provenance must pass parser replay; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        truth_stamp.is_file(),
        "parser must write a truth-pass stamp only after a strict pass"
    );
    let truth_stamp_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&truth_stamp).expect("truth stamp should read"))
            .expect("truth stamp should parse");
    assert_eq!(
        truth_stamp_doc["high_water_comparison"]["throughput_metric"],
        "ledger_paced_bytes_per_sec",
        "GET high-water comparisons must use ledger-paced throughput whenever fixture ledger proof is present"
    );
    assert!(
        truth_stamp_doc["high_water_comparison"]["strict_percent_behind"]
            .get("ledger_paced_bytes_per_sec")
            .is_some(),
        "ledger-gated high-water percent-behind must be keyed by ledger-paced throughput"
    );

    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&truth_stamp)
        .output()
        .expect("truth-stamp verifier should run");
    assert!(
        output.status.success(),
        "fresh truth stamp must verify by replaying strict artifacts; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let original_manifest = std::fs::read(&manifest).expect("manifest should read");
    let mut missing_run_order_doc: serde_json::Value =
        serde_json::from_slice(&original_manifest).expect("manifest should parse");
    missing_run_order_doc
        .as_object_mut()
        .expect("manifest should be an object")
        .remove("run_order");
    missing_run_order_doc
        .as_object_mut()
        .expect("manifest should be an object")
        .remove("run_order_sha256");
    std::fs::write(
        &manifest,
        serde_json::to_vec_pretty(&missing_run_order_doc)
            .expect("missing run-order manifest should serialize"),
    )
    .expect("missing run-order manifest should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run against missing run-order manifest");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("run_order_required"),
        "publication manifest without run_order must fail closed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&manifest, &original_manifest).expect("manifest should be restored");

    let first_artifact = artifact_paths
        .first()
        .expect("at least one selected artifact should exist");
    let original_first_artifact = std::fs::read(first_artifact).expect("artifact should read");
    let mut missing_finish_doc: serde_json::Value =
        serde_json::from_slice(&original_first_artifact).expect("artifact should parse");
    missing_finish_doc["run_provenance"]
        .as_object_mut()
        .expect("run provenance should be an object")
        .remove("run_finished_at_unix_ns");
    std::fs::write(
        first_artifact,
        serde_json::to_vec_pretty(&missing_finish_doc)
            .expect("missing finish artifact should serialize"),
    )
    .expect("missing finish artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run against missing finish provenance");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .contains("provenance_run_finished_at_unix_ns"),
        "artifact without run_finished_at_unix_ns must fail closed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(first_artifact, &original_first_artifact).expect("artifact should be restored");

    let specter_artifact = archive.join("current_rows.portable.specter_native.json");
    let original_specter_artifact =
        std::fs::read(&specter_artifact).expect("specter artifact should read");
    let mut scoped_doc: serde_json::Value =
        serde_json::from_slice(&original_specter_artifact).expect("specter artifact should parse");
    let external_ledger = archive.join("fixture-ledger.specter_native.external.jsonl");
    let external_sha256 = write_synthetic_fixture_ledger(&external_ledger, "specter_native");
    scoped_doc["rows"][0]["fixture_ledger_path"] =
        json!(external_ledger.to_string_lossy().into_owned());
    scoped_doc["rows"][0]["fixture_ledger_sha256"] = json!(external_sha256);
    std::fs::write(
        &specter_artifact,
        serde_json::to_vec_pretty(&scoped_doc).expect("scoped artifact should serialize"),
    )
    .expect("scoped artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "fixture ledgers outside the artifact sibling directory must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fixture_ledger_path_outside_artifact_scope"),
        "parser must name out-of-scope fixture ledger paths; stdout was: {stdout}"
    );
    std::fs::write(&specter_artifact, original_specter_artifact.clone())
        .expect("specter artifact should be restored");

    let specter_ledger =
        synthetic_artifact_fixture_ledger_path(&specter_artifact, "specter_native");
    let original_specter_ledger =
        std::fs::read_to_string(&specter_ledger).expect("specter ledger should read");
    let bad_due_ledger =
        original_specter_ledger.replacen("\"due_ns\":1000000", "\"due_ns\":1000001", 1);
    assert_ne!(
        bad_due_ledger, original_specter_ledger,
        "synthetic ledger mutation must alter a due_ns field"
    );
    std::fs::write(&specter_ledger, bad_due_ledger).expect("bad due ledger should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "complete fixture ledgers with an invalid due schedule must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("due_ns=1000001 expected=1000000"),
        "parser must name invalid fixture due schedule; stdout was: {stdout}"
    );
    std::fs::write(&specter_ledger, original_specter_ledger)
        .expect("specter ledger should be restored");

    let unexpected_sibling = archive.join("current_rows.portable.shadow_client.json");
    std::fs::write(&unexpected_sibling, br#"{"rows":[]}"#)
        .expect("unexpected sibling artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "hidden sibling selected-row artifacts under the manifest prefix must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FAIL unexpected_sibling_artifact"),
        "parser must name unexpected hidden sibling artifacts; stdout was: {stdout}"
    );
    std::fs::remove_file(&unexpected_sibling)
        .expect("unexpected sibling artifact should be removed before later replay checks");

    let tokio_mixed_artifact =
        archive.join("current_rows.portable.tokio_quiche_rfc9220_tunnel_mixed.json");
    let missing_final_mixed_paths = artifact_paths
        .iter()
        .filter(|path| path.as_path() != tokio_mixed_artifact.as_path())
        .map(|path| path.as_os_str())
        .collect::<Vec<_>>();
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&missing_final_mixed_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "omitting the final mixed comparator artifact must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FAIL missing_required_artifact tokio_quiche_rfc9220_tunnel_mixed"),
        "parser must explicitly name missing final mixed comparator artifact; stdout was: {stdout}"
    );
    assert!(
        stdout.contains("FAIL missing_required_row tokio_quiche_rfc9220_tunnel_mixed"),
        "parser must explicitly name missing final mixed comparator row; stdout was: {stdout}"
    );

    let stale_truth_stamp = archive.join("current_rows.portable.stale-truth-pass.json");
    let mut stale_stamp_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&truth_stamp).expect("truth stamp should read"))
            .expect("truth stamp should parse");
    stale_stamp_doc["selected_rows"]
        .as_array_mut()
        .expect("selected_rows should be an array")
        .pop();
    std::fs::write(
        &stale_truth_stamp,
        serde_json::to_vec_pretty(&stale_stamp_doc).expect("stale stamp should serialize"),
    )
    .expect("stale stamp should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&stale_truth_stamp)
        .output()
        .expect("truth-stamp verifier should run");
    assert!(
        !output.status.success(),
        "truth stamp missing a required selected row must fail verification"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("truth_stamp_selected_rows_mismatch"),
        "verifier must name stale selected-row truth stamp; stdout was: {stdout}"
    );

    let stale_high_water_stamp =
        archive.join("current_rows.portable.stale-high-water-truth-pass.json");
    let mut stale_high_water_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&truth_stamp).expect("truth stamp should read"))
            .expect("truth stamp should parse");
    stale_high_water_doc["high_water_comparison"]["strict_percent_behind"]
        ["ledger_paced_bytes_per_sec"] = json!(12345.0);
    std::fs::write(
        &stale_high_water_stamp,
        serde_json::to_vec_pretty(&stale_high_water_doc)
            .expect("stale high-water stamp should serialize"),
    )
    .expect("stale high-water stamp should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&stale_high_water_stamp)
        .output()
        .expect("truth-stamp verifier should run");
    assert!(
        !output.status.success(),
        "truth stamp with forged high-water comparison must fail verification"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("truth_stamp_high_water_comparison_mismatch"),
        "verifier must name stale high-water comparison truth; stdout was: {stdout}"
    );

    let specter_artifact = archive.join("current_rows.portable.specter_native.json");
    let mut metric_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&specter_artifact).expect("artifact should read"))
            .expect("artifact should parse");
    metric_doc["rows"][0]["p50_ttfb_ns"] = json!(9_999);
    std::fs::write(
        &specter_artifact,
        serde_json::to_vec_pretty(&metric_doc).expect("metric-sabotaged artifact should serialize"),
    )
    .expect("metric-sabotaged artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "rolled-up metrics that disagree with raw_samples must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("p50_ttfb_ns=9999 raw_expected=1000"),
        "parser must name the forged metric/raw_samples mismatch; stdout was: {stdout}"
    );
    std::fs::write(&specter_artifact, original_specter_artifact.clone())
        .expect("specter artifact should be restored after metric sabotage");

    let mut provenance_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&specter_artifact).expect("artifact should read"))
            .expect("artifact should parse");
    provenance_doc["run_provenance"]["selected_client"] = json!("tokio_quiche");
    std::fs::write(
        &specter_artifact,
        serde_json::to_vec_pretty(&provenance_doc)
            .expect("provenance-sabotaged artifact should serialize"),
    )
    .expect("provenance-sabotaged artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "artifact/client provenance label swaps must fail selected-row publication"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FAIL provenance_selected_client specter_native"),
        "parser must name the selected-client provenance mismatch; stdout was: {stdout}"
    );
    std::fs::write(&specter_artifact, original_specter_artifact.clone())
        .expect("specter artifact should be restored after provenance sabotage");

    let mut specter_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&specter_artifact).expect("artifact should read"))
            .expect("artifact should parse");
    specter_doc["rows"]
        .as_array_mut()
        .expect("rows should be an array")
        .push(json!({
            "competitor_id": "specter_native",
            "status": "measured_fail",
            "source": "specter_native_adapter",
            "workload": "http3_streaming_get"
        }));
    std::fs::write(
        &specter_artifact,
        serde_json::to_vec_pretty(&specter_doc).expect("artifact should serialize"),
    )
    .expect("artifact with duplicate row should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .args(&artifact_paths)
        .output()
        .expect("selected-row parser should run");
    let verify_output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&truth_stamp)
        .output()
        .expect("truth-stamp verifier should run after artifact mutation");
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        !output.status.success(),
        "duplicate required rows must fail even when one row is measured_pass"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DUPLICATE_REQUIRED_ROW specter_native"),
        "parser output must name duplicate required row; stdout was: {stdout}"
    );
    assert!(
        !verify_output.status.success(),
        "truth stamp must fail after a stamped artifact changes"
    );
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_stdout.contains("truth_stamp_artifact_sha256 specter_native")
            || verify_stdout.contains("TRUTH_STAMP_REPLAY DUPLICATE_REQUIRED_ROW specter_native"),
        "verifier must name stale artifact truth; stdout was: {verify_stdout}"
    );
}

#[test]
fn native_h3_repeat_truth_stamp_replays_and_rejects_stale_artifacts() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn sha256_file(path: &std::path::Path) -> String {
        sha256_bytes(&std::fs::read(path).expect("hash input should be readable"))
    }

    let selected_clients = [
        ("specter_native", "http3_streaming_get", 16 * 1024 * 5),
        ("quiche_direct", "http3_streaming_get", 16 * 1024 * 5),
        ("tokio_quiche", "http3_streaming_get", 16 * 1024 * 5),
        ("h3_quinn", "http3_streaming_get", 16 * 1024 * 5),
        ("reqwest_h3", "http3_streaming_get", 16 * 1024 * 5),
        (
            "specter_native_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "quiche_direct_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "tokio_quiche_rfc9220_tunnel",
            "websocket_over_h3_raw_tunnel_echo",
            1024,
        ),
        (
            "specter_native_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "quiche_direct_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "tokio_quiche_rfc9220_tunnel_close",
            "websocket_over_h3_raw_tunnel_close_fin",
            1024,
        ),
        (
            "specter_native_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
        (
            "quiche_direct_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
        (
            "tokio_quiche_rfc9220_tunnel_mixed",
            "slow_consumer_tunnel_plus_http3_streaming",
            1024 * 40 + 16 * 1024 * 5,
        ),
    ];
    let selected_client_ids = selected_clients
        .iter()
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let competitors = selected_client_ids
        .iter()
        .map(|client| json!({ "id": client }))
        .collect::<Vec<_>>();
    let required_h3_clients = selected_clients
        .iter()
        .filter(|(_, workload, _)| *workload == "http3_streaming_get")
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let required_rfc9220_tunnel_clients = selected_clients
        .iter()
        .filter(|(_, workload, _)| *workload != "http3_streaming_get")
        .map(|(client, _, _)| *client)
        .collect::<Vec<_>>();
    let selected_clients_sha256 = sha256_bytes(selected_client_ids.join(",").as_bytes());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "specter-native-h3-repeat-truth-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("repeat temp root should be created");
    let runtime_env = native_h3_required_runtime_env();
    let runtime_env_sha256 = native_h3_required_runtime_env_sha256();

    let mut manifest_paths = Vec::new();
    for run_index in 1..=3 {
        let archive = root.join(format!(
            "docs/benchmarks/native-h3-vs-rust-clients/repeat-{run_index}"
        ));
        std::fs::create_dir_all(&archive).expect("archive temp dir should be created");
        let manifest = archive.join(format!("current_rows.r{run_index}.manifest.json"));
        let relative_manifest = format!(
            "docs/benchmarks/native-h3-vs-rust-clients/repeat-{run_index}/current_rows.r{run_index}.manifest.json"
        );
        let binary_sha256 = "binary01".to_string();
        let git_head = "0000000000000000000000000000000000000001".to_string();
        let manifest_doc = json!({
            "kind": "native_h3_selected_rows_manifest",
            "samples": 100,
            "warmups": 10,
            "binary_sha256": binary_sha256.clone(),
            "selected_clients": selected_client_ids.clone(),
            "selected_clients_sha256": selected_clients_sha256.clone(),
            "run_order": selected_client_ids.clone(),
            "run_order_sha256": selected_clients_sha256.clone(),
            "git_head": git_head.clone(),
            "git_dirty": false,
            "target": "aarch64-unknown-linux-gnu",
            "profile": "release",
            "features": "reqwest-h3",
            "runtime_profile": "direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed",
            "runtime_env": runtime_env.clone(),
            "runtime_env_sha256": runtime_env_sha256.clone(),
            "repeat_index": run_index,
            "scout_gate": false,
            "publication_eligible": true,
            "get_only_gate": false
        });
        std::fs::write(
            &manifest,
            serde_json::to_vec_pretty(&manifest_doc).expect("manifest should serialize"),
        )
        .expect("manifest should be written");
        let manifest_sha256 = sha256_file(&manifest);

        for (client_index, (client, workload, payload_bytes)) in selected_clients.iter().enumerate()
        {
            let run_sequence_index = client_index + 1;
            let run_started_at_unix_ns = 10_000_000_000u64
                + run_index as u64 * 1_000_000_000
                + run_sequence_index as u64 * 1_000_000;
            let run_finished_at_unix_ns = run_started_at_unix_ns + 100_000;
            let artifact = archive.join(format!("current_rows.r{run_index}.{client}.json"));
            let specter_row = client.starts_with("specter_native");
            let metric = if specter_row {
                1_000 + run_index as u64
            } else {
                2_000 + run_index as u64 + client_index as u64
            };
            let bytes_per_sec = if specter_row {
                *payload_bytes as u64 * 2_000
            } else {
                *payload_bytes as u64 * 1_000
            };
            let total_ns = if specter_row { 500_000 } else { 1_000_000 };
            let raw_samples = (0..100)
                .map(|_| {
                    json!({
                        "ttfb_ns": metric,
                        "first_body_ns": metric + 10,
                        "total_ns": total_ns,
                        "bytes": payload_bytes
                    })
                })
                .collect::<Vec<_>>();
            let mut row = json!({
                "competitor_id": client,
                "status": "measured_pass",
                "source": format!("{client}_adapter"),
                "workload": workload,
                "payload_bytes": payload_bytes,
                "sample_count": 100,
                "requested_samples": 100,
                "completed_samples": 100,
                "requested_warmups": 10,
                "completed_warmups": 10,
                "p50_ttfb_ns": metric,
                "p95_ttfb_ns": metric,
                "bytes_per_sec": bytes_per_sec,
                "raw_samples": raw_samples
            });
            if *workload == "http3_streaming_get" {
                let ledger_path = synthetic_artifact_fixture_ledger_path(&artifact, client);
                std::fs::create_dir_all(
                    ledger_path
                        .parent()
                        .expect("synthetic ledger path should have parent"),
                )
                .expect("fixture ledger dir should be created");
                let ledger_sha256 = write_synthetic_fixture_ledger(&ledger_path, client);
                row["fixture_pace_span_ns"] = json!(4_000_000.0);
                row["p50_paced_body_overhead_ns"] = json!(0.0);
                row["p95_paced_body_overhead_ns"] = json!(0.0);
                row["p50_paced_tail_overhead_ns"] = json!(0.0);
                row["p95_paced_tail_overhead_ns"] = json!(0.0);
                row["fixture_ledger_path"] = json!(ledger_path.to_string_lossy().into_owned());
                row["fixture_ledger_sha256"] = json!(ledger_sha256);
                row["fixture_ledger_response_count"] = json!(110);
                row["fixture_ledger_required_response_count"] = json!(110);
                row["fixture_ledger_sample_offset"] = json!(10);
                row["p50_fixture_emission_span_ns"] = json!(4_100_000.0);
                row["p95_fixture_emission_span_ns"] = json!(4_100_000.0);
                row["p50_ledger_paced_tail_overhead_ns"] = json!(0.0);
                row["p95_ledger_paced_tail_overhead_ns"] = json!(0.0);
                row["ledger_paced_bytes_per_sec"] = json!(synthetic_ledger_paced_bytes_per_sec(
                    *payload_bytes as u64,
                    metric as f64
                ));
            }
            let doc = json!({
                "benchmark": "native_h3_vs_rust_clients",
                "benchmark_version": "matrix-1",
                "audited_at": "2026-06-08T00:00:00Z",
                "competitors": competitors.clone(),
                "fixture_events": [],
                "superiority_gate": {
                    "status": "pass",
                    "pass": true,
                    "no_h3_superiority_claim_without_all_required_rows": true,
                    "required_h3_clients": required_h3_clients.clone(),
                },
                "rfc9220_full_suite_superiority_gate": {
                    "status": "pass",
                    "pass": true,
                    "no_rfc9220_tunnel_superiority_claim_without_all_required_n100_rows": true,
                    "required_rfc9220_tunnel_clients": required_rfc9220_tunnel_clients.clone(),
                },
                "run_provenance": {
                    "manifest_path": relative_manifest,
                    "manifest_sha256": manifest_sha256,
                    "binary_sha256": binary_sha256.clone(),
                    "selected_clients_sha256": selected_clients_sha256.clone(),
                    "run_order": selected_client_ids.clone(),
                    "run_order_sha256": selected_clients_sha256.clone(),
                    "git_head": git_head.clone(),
                    "git_dirty": false,
                    "target": "aarch64-unknown-linux-gnu",
                    "profile": "release",
                    "features": "reqwest-h3",
                    "runtime_profile": "direct-get-epoch-rfc9220-fused-echo-close-epoch-mixed",
                    "runtime_env_sha256": runtime_env_sha256.clone(),
                    "samples": 100,
                    "warmups": 10,
                    "scout_gate": false,
                    "publication_eligible": true,
                    "get_only_gate": false,
                    "selected_client": client,
                    "run_sequence_index": run_sequence_index,
                    "run_started_at_unix_ns": run_started_at_unix_ns,
                    "run_finished_at_unix_ns": run_finished_at_unix_ns
                },
                "rows": [row]
            });
            std::fs::write(
                &artifact,
                serde_json::to_vec_pretty(&doc).expect("artifact should serialize"),
            )
            .expect("artifact should be written");
        }
        manifest_paths.push(manifest);
    }

    let truth_stamp = root.join("repeat.truth-pass.json");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py")
        .arg("--truth-stamp")
        .arg(&truth_stamp)
        .args(&manifest_paths)
        .output()
        .expect("repeat parser should run");
    assert!(
        output.status.success(),
        "synthetic repeated pass should write a repeat truth stamp; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&truth_stamp)
        .output()
        .expect("repeat truth-stamp verifier should run");
    assert!(
        output.status.success(),
        "fresh repeat stamp must verify by replaying strict artifacts; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stale_runtime_truth_stamp = root.join("repeat.runtime-stale-truth-pass.json");
    let mut stale_runtime_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&truth_stamp).expect("truth stamp should read"))
            .expect("truth stamp should parse");
    stale_runtime_doc["run_identities"][0]["manifest"]["runtime_env_sha256"] =
        json!("stale-runtime-env");
    std::fs::write(
        &stale_runtime_truth_stamp,
        serde_json::to_vec_pretty(&stale_runtime_doc)
            .expect("stale runtime stamp should serialize"),
    )
    .expect("stale runtime truth stamp should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&stale_runtime_truth_stamp)
        .output()
        .expect("repeat truth-stamp verifier should run after runtime identity mutation");
    assert!(
        !output.status.success(),
        "repeat truth stamp must bind runtime env identity"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repeat_truth_stamp_manifest run=1 runtime_env_sha256"),
        "verifier must name stale runtime env identity; stdout was: {stdout}"
    );

    let specter_artifact = root.join(
        "docs/benchmarks/native-h3-vs-rust-clients/repeat-1/current_rows.r1.specter_native.json",
    );
    let mut specter_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&specter_artifact).expect("artifact should read"))
            .expect("artifact should parse");
    specter_doc["rows"][0]["p50_ttfb_ns"] = json!(9_999);
    std::fs::write(
        &specter_artifact,
        serde_json::to_vec_pretty(&specter_doc).expect("mutated artifact should serialize"),
    )
    .expect("mutated artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py")
        .arg("--verify-truth-stamp")
        .arg(&truth_stamp)
        .output()
        .expect("repeat truth-stamp verifier should run after artifact mutation");
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !output.status.success(),
        "repeat truth stamp must fail after a stamped artifact changes"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("repeat_truth_stamp_run_identity")
            || stdout.contains("REPEAT_TRUTH_STAMP_REPLAY"),
        "verifier must name stale repeat evidence; stdout was: {stdout}"
    );
}

#[test]
fn native_h3_selected_row_parser_rejects_ambiguous_json_inputs() {
    use sha2::{Digest, Sha256};

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    let selected_clients = [
        "specter_native",
        "quiche_direct",
        "tokio_quiche",
        "h3_quinn",
        "reqwest_h3",
        "specter_native_rfc9220_tunnel",
        "quiche_direct_rfc9220_tunnel",
        "tokio_quiche_rfc9220_tunnel",
        "specter_native_rfc9220_tunnel_close",
        "quiche_direct_rfc9220_tunnel_close",
        "tokio_quiche_rfc9220_tunnel_close",
        "specter_native_rfc9220_tunnel_mixed",
        "quiche_direct_rfc9220_tunnel_mixed",
        "tokio_quiche_rfc9220_tunnel_mixed",
    ];
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "specter-native-h3-strict-json-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("test temp dir should be created");

    let duplicate_manifest = dir.join("duplicate.manifest.json");
    std::fs::write(
        &duplicate_manifest,
        r#"{"kind":"native_h3_selected_rows_manifest","kind":"duplicate"}"#,
    )
    .expect("duplicate manifest should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&duplicate_manifest)
        .output()
        .expect("selected-row parser should run");
    assert!(
        !output.status.success(),
        "duplicate JSON key manifest must fail"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("duplicate_json_key=kind"),
        "parser must report duplicate manifest key; stdout was: {stdout}"
    );

    let manifest = dir.join("current_rows.strict.manifest.json");
    let selected_clients_json = selected_clients
        .iter()
        .map(|client| format!(r#""{client}""#))
        .collect::<Vec<_>>()
        .join(",");
    let selected_clients_sha256 = sha256_bytes(selected_clients.join(",").as_bytes());
    std::fs::write(
        &manifest,
        format!(
            r#"{{
  "kind": "native_h3_selected_rows_manifest",
  "samples": 100,
  "warmups": 10,
  "binary_sha256": "abc123",
  "selected_clients": [{selected_clients_json}],
  "selected_clients_sha256": "{selected_clients_sha256}",
  "git_head": "0123456789abcdef0123456789abcdef01234567",
  "git_dirty": false,
  "target": "aarch64-unknown-linux-gnu",
  "profile": "release",
  "features": "reqwest-h3",
  "scout_gate": false,
  "publication_eligible": true
}}
"#
        ),
    )
    .expect("manifest should be written");
    let non_finite_artifact = dir.join("current_rows.strict.specter_native.json");
    std::fs::write(
        &non_finite_artifact,
        r#"{"rows":[{"competitor_id":"specter_native","status":"measured_pass","p50_ttfb_ns":NaN}]}"#,
    )
    .expect("non-finite artifact should be written");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .arg(&non_finite_artifact)
        .output()
        .expect("selected-row parser should run");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!output.status.success(), "non-finite JSON metric must fail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("non_finite_json_number=NaN"),
        "parser must report non-finite artifact value; stdout was: {stdout}"
    );
}

#[test]
fn native_h3_selected_row_runner_has_paired_non_publishable_scout_repeats() {
    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");
    for required in [
        "SCOUT_REPEATS",
        "current_rows_pair_scout",
        "current_rows_pair_scout_parse.py",
        "paired_scout",
        "scout_repeat_index",
        "scout_repeat_count",
        "run_order",
        "paired_run_sequence_index",
        "paired_run_started_at_unix_ns",
        "paired_run_finished_at_unix_ns",
        r#""publication_eligible": False"#,
        "repeat_clients=(specter_native quiche_direct)",
        "repeat_clients=(quiche_direct specter_native)",
        "--verify-stamp",
        "pair_verify_rc",
    ] {
        assert!(
            runner.contains(required),
            "selected-row runner must expose paired non-publishable scout repeats: {required}"
        );
    }

    let parser = std::fs::read_to_string(
        "benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py",
    )
    .expect("paired scout parser source should exist");
    for required in [
        "native_h3_pair_repeat_scout",
        "non_publishable",
        "publication_eligible",
        "candidate",
        "specter_worst_p50_ttfb_ns",
        "quiche_direct_best_p50_ttfb_ns",
        "FAIL_PAIR p50",
        "FAIL_PAIR p95",
        "FAIL_PAIR {throughput_label}",
        "ledger_paced_throughput",
        "throughput_metric",
        "row_complete",
        "reject_phase_trace_artifacts",
        "pair_manifest_git_dirty_true",
        "one.load_json_strict(path)",
        r#""provenance_manifest_path": one.canonical_manifest_provenance_path(path)"#,
        "raw_samples_sha256",
        "raw_samples_set_sha256",
        "pair_duplicate_raw_samples",
        "pair_missing_required_row",
        "pair_duplicate_required_row",
        "pair_provenance_sequence_index",
        "pair_provenance_sequence_client",
        "pair_provenance_sequence_monotonic",
        "PAIR_SCOUT_REJECT",
        "manifest_resolved_path",
        r#""manifest_paths""#,
        r#""exit_code""#,
        r#""run_count""#,
        "--verify-stamp",
        "PAIR_SCOUT_STAMP_VERIFIED",
        "PAIR_SCOUT_STAMP_REJECT",
        "verify_stamp",
    ] {
        assert!(
            parser.contains(required),
            "paired scout parser must fail closed and emit non-publishable candidate stamps: {required}"
        );
    }

    let bench_source = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("isolated native H3 competitor benchmark source should exist");
    for required in [
        "scout_gate: bool",
        "publication_eligible: bool",
        "paired_scout: Option<bool>",
        "scout_repeat_index: Option<usize>",
        "scout_repeat_count: Option<usize>",
        "run_order: Option<Vec<String>>",
        "paired_run_sequence_index: Option<usize>",
        "paired_run_started_at_unix_ns: Option<u64>",
        "paired_run_finished_at_unix_ns: Option<u64>",
    ] {
        assert!(
            bench_source.contains(required),
            "benchmark artifacts must preserve paired scout provenance: {required}"
        );
    }
}

#[test]
fn native_h3_pair_scout_parser_rejects_ambiguous_required_rows() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn sha256_file(path: &std::path::Path) -> String {
        sha256_bytes(&std::fs::read(path).expect("hash input should be readable"))
    }

    #[allow(clippy::too_many_arguments)]
    fn write_pair_artifact(
        path: &std::path::Path,
        manifest: &std::path::Path,
        manifest_sha256: &str,
        selected_clients_sha256: &str,
        client: &str,
        repeat_index: usize,
        ttfb_ns: u64,
        total_ns: u64,
        duplicate_required_row: bool,
    ) {
        let payload_bytes = 16 * 1024 * 5;
        let raw_samples = (0..100)
            .map(|_| {
                json!({
                    "ttfb_ns": ttfb_ns,
                    "total_ns": total_ns,
                    "bytes": payload_bytes
                })
            })
            .collect::<Vec<_>>();
        let bytes_per_sec = payload_bytes as f64 * 1_000_000_000.0 / total_ns as f64;
        let mut rows = vec![json!({
            "competitor_id": client,
            "status": "measured_pass",
            "source": format!("{client}_adapter"),
            "workload": "http3_streaming_get",
            "payload_bytes": payload_bytes,
            "sample_count": 100,
            "requested_samples": 100,
            "completed_samples": 100,
            "requested_warmups": 10,
            "completed_warmups": 10,
            "p50_ttfb_ns": ttfb_ns,
            "p95_ttfb_ns": ttfb_ns,
            "bytes_per_sec": bytes_per_sec,
            "raw_samples": raw_samples
        })];
        if duplicate_required_row {
            rows.push(json!({
                "competitor_id": client,
                "status": "measured_fail",
                "source": format!("{client}_adapter"),
                "workload": "http3_streaming_get"
            }));
        }
        let doc = json!({
            "run_provenance": {
                "manifest_path": manifest.to_string_lossy(),
                "manifest_sha256": manifest_sha256,
                "binary_sha256": "pair-scout-binary",
                "selected_clients_sha256": selected_clients_sha256,
                "git_head": "0123456789abcdef0123456789abcdef01234567",
                "git_dirty": false,
                "target": "aarch64-unknown-linux-gnu",
                "profile": "release",
                "features": "reqwest-h3",
                "samples": 100,
                "warmups": 10,
                "scout_gate": true,
                "publication_eligible": false,
                "paired_scout": true,
                "scout_repeat_index": repeat_index,
                "scout_repeat_count": 3,
                "run_order": if repeat_index % 2 == 1 {
                    vec!["specter_native", "quiche_direct"]
                } else {
                    vec!["quiche_direct", "specter_native"]
                },
                "paired_run_sequence_index": if (repeat_index % 2 == 1 && client == "specter_native")
                    || (repeat_index.is_multiple_of(2) && client == "quiche_direct") {
                    1
                } else {
                    2
                },
                "paired_run_started_at_unix_ns": 1_000_000_000_u128
                    + repeat_index as u128 * 10_000
                    + if (repeat_index % 2 == 1 && client == "specter_native")
                        || (repeat_index.is_multiple_of(2) && client == "quiche_direct") {
                        0
                    } else {
                        5_000
                    },
                "paired_run_finished_at_unix_ns": 1_000_000_000_u128
                    + repeat_index as u128 * 10_000
                    + if (repeat_index % 2 == 1 && client == "specter_native")
                        || (repeat_index.is_multiple_of(2) && client == "quiche_direct") {
                        4_000
                    } else {
                        9_000
                    },
                "selected_client": client
            },
            "rows": rows
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&doc).expect("artifact should serialize"),
        )
        .expect("artifact should be written");
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "specter-native-h3-pair-scout-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("pair scout temp root should be created");

    let mut manifests = Vec::new();
    for repeat_index in 1..=3 {
        let manifest = root.join(format!(
            "current_rows_pair_scout.r{repeat_index}.manifest.json"
        ));
        let run_order = if repeat_index % 2 == 1 {
            vec!["specter_native", "quiche_direct"]
        } else {
            vec!["quiche_direct", "specter_native"]
        };
        let selected_clients_sha256 = sha256_bytes(run_order.join(",").as_bytes());
        let manifest_doc = json!({
            "kind": "native_h3_selected_rows_manifest",
            "samples": 100,
            "warmups": 10,
            "binary_sha256": "pair-scout-binary",
            "selected_clients": run_order,
            "selected_clients_sha256": selected_clients_sha256,
            "git_head": "0123456789abcdef0123456789abcdef01234567",
            "git_dirty": false,
            "target": "aarch64-unknown-linux-gnu",
            "profile": "release",
            "features": "reqwest-h3",
            "scout_gate": true,
            "publication_eligible": false,
            "paired_scout": true,
            "scout_repeat_index": repeat_index,
            "scout_repeat_count": 3,
            "run_order": if repeat_index % 2 == 1 {
                vec!["specter_native", "quiche_direct"]
            } else {
                vec!["quiche_direct", "specter_native"]
            }
        });
        std::fs::write(
            &manifest,
            serde_json::to_vec_pretty(&manifest_doc).expect("manifest should serialize"),
        )
        .expect("manifest should be written");
        let manifest_sha256 = sha256_file(&manifest);

        write_pair_artifact(
            &root.join(format!(
                "current_rows_pair_scout.r{repeat_index}.specter_native.json"
            )),
            &manifest,
            &manifest_sha256,
            &selected_clients_sha256,
            "specter_native",
            repeat_index,
            1_000 + repeat_index as u64,
            1_000_000,
            repeat_index == 2,
        );
        write_pair_artifact(
            &root.join(format!(
                "current_rows_pair_scout.r{repeat_index}.quiche_direct.json"
            )),
            &manifest,
            &manifest_sha256,
            &selected_clients_sha256,
            "quiche_direct",
            repeat_index,
            2_000 + repeat_index as u64,
            2_000_000,
            false,
        );
        manifests.push(manifest);
    }

    let stamp = root.join("pair-scout.truth.json");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py")
        .arg("--stamp")
        .arg(&stamp)
        .args(&manifests)
        .output()
        .expect("pair scout parser should run");

    assert!(
        !output.status.success(),
        "duplicate required row must reject an otherwise winning pair scout"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FAIL pair_duplicate_required_row repeat=2 client=specter_native"),
        "pair scout parser must explicitly name the ambiguous required row; stdout was: {stdout}"
    );

    let verify_output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py")
        .arg("--verify-stamp")
        .arg(&stamp)
        .output()
        .expect("pair scout stamp verifier should run");
    assert!(
        verify_output.status.success(),
        "fresh pair scout stamp must replay even when it records a rejected scout; stdout was: {}",
        String::from_utf8_lossy(&verify_output.stdout)
    );

    let repaired_artifact = root.join("current_rows_pair_scout.r2.specter_native.json");
    let mut repaired_doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&repaired_artifact).expect("repaired artifact should be readable"),
    )
    .expect("repaired artifact should parse");
    repaired_doc["rows"] = json!([repaired_doc["rows"][0].clone()]);
    std::fs::write(
        &repaired_artifact,
        serde_json::to_vec_pretty(&repaired_doc).expect("repaired artifact should serialize"),
    )
    .expect("repaired artifact mutation should be written");

    let bad_sequence_artifact = root.join("current_rows_pair_scout.r1.specter_native.json");
    let mut bad_sequence_doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&bad_sequence_artifact).expect("bad sequence artifact should be readable"),
    )
    .expect("bad sequence artifact should parse");
    bad_sequence_doc["run_provenance"]["paired_run_sequence_index"] = json!(2);
    std::fs::write(
        &bad_sequence_artifact,
        serde_json::to_vec_pretty(&bad_sequence_doc)
            .expect("bad sequence artifact should serialize"),
    )
    .expect("bad sequence mutation should be written");

    let sequence_output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py")
        .arg("--stamp")
        .arg(root.join("pair-scout-sequence.truth.json"))
        .args(&manifests)
        .output()
        .expect("pair scout parser should reject bad sequence provenance");
    assert!(
        !sequence_output.status.success(),
        "bad paired sequence provenance must reject an otherwise unambiguous pair scout"
    );
    let sequence_stdout = String::from_utf8_lossy(&sequence_output.stdout);
    assert!(
        sequence_stdout.contains("FAIL pair_provenance_sequence_client repeat=1 sequence=2"),
        "pair scout parser must explicitly reject order-mismatched sequence provenance; stdout was: {sequence_stdout}"
    );

    let stale_artifact = root.join("current_rows_pair_scout.r1.specter_native.json");
    let mut stale_doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&stale_artifact).expect("stale artifact should be readable"),
    )
    .expect("stale artifact should parse");
    stale_doc["rows"][0]["p50_ttfb_ns"] = json!(9_999_999);
    std::fs::write(
        &stale_artifact,
        serde_json::to_vec_pretty(&stale_doc).expect("stale artifact should serialize"),
    )
    .expect("stale artifact mutation should be written");
    let stale_verify_output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py")
        .arg("--verify-stamp")
        .arg(&stamp)
        .output()
        .expect("stale pair scout stamp verifier should run");
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        !stale_verify_output.status.success(),
        "mutating a stamped artifact must make pair scout replay fail"
    );
    let stale_stdout = String::from_utf8_lossy(&stale_verify_output.stdout);
    assert!(
        stale_stdout.contains("PAIR_SCOUT_STAMP_REJECT")
            && (stale_stdout.contains("pair_stamp_runs_mismatch")
                || stale_stdout.contains("pair_stamp_failures_mismatch")),
        "stale pair scout stamp must report a replay mismatch; stdout was: {stale_stdout}"
    );
}

#[test]
fn native_h3_get_scout_reports_high_water_percent_behind() {
    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");
    for required in [
        "current_rows_high_water.py",
        "HIGH_WATER_PATH",
        "HIGH_WATER_SUMMARY",
    ] {
        assert!(
            runner.contains(required),
            "selected-row runner must emit high-water comparison summaries: {required}"
        );
    }

    let parser = std::fs::read_to_string(
        "benches/native_h3_vs_rust_clients/scripts/current_rows_pair_scout_parse.py",
    )
    .expect("paired scout parser source should exist");
    for required in [
        "high_water_comparison",
        "strict_percent_behind",
        "specter_native",
        "quiche_direct",
        "p50_ttfb_ns",
        "p95_ttfb_ns",
        "bytes_per_sec",
    ] {
        assert!(
            parser.contains(required),
            "paired scout parser must stamp high-water percent-behind fields: {required}"
        );
    }

    let high_water = std::fs::read_to_string(
        "benches/native_h3_vs_rust_clients/scripts/current_rows_high_water.py",
    )
    .expect("high-water comparison helper should exist");
    for required in [
        "strict_percent_behind",
        "delta_vs_high_water",
        "publication_eligible",
        "non_publishable",
        "artifact_set_sha256",
        "raw_samples_set_sha256",
        "choose_throughput_metric",
        "ledger_paced_bytes_per_sec",
        "raw_bytes_per_sec_diagnostic",
        "explicit high-water path does not exist",
    ] {
        assert!(
            high_water.contains(required),
            "high-water helper must preserve truth metadata and percent-behind math: {required}"
        );
    }
}

#[test]
fn native_h3_publication_gate_requires_publishable_clean_manifest() {
    let parser =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
            .expect("selected-row parser source should exist");
    for required in [
        "GIT_HEAD_RE",
        "canonical_manifest_provenance_path",
        "manifest_scout_gate",
        "manifest_publication_eligible",
        "manifest_git_dirty",
        "REQUIRED_TARGET",
        "REQUIRED_PROFILE",
        "REQUIRED_FEATURES",
        "REQUIRED_IO_EPOCH_RUNTIME_PROFILE",
        "required_runtime_env_for_profile",
        "provenance_manifest_path",
        "reject_phase_trace_artifacts",
        "phase_trace_non_publishable",
        r#""non_publishable": not publication_eligible"#,
        r#""publication_eligible": publication_eligible"#,
        r#""scout_gate": False"#,
    ] {
        assert!(
            parser.contains(required),
            "selected-row parser must fail closed on non-publishable evidence: {required}"
        );
    }

    let runner =
        std::fs::read_to_string("benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh")
            .expect("selected-row awsdev runner source should exist");
    for required in [
        "direct-get-io-epoch-rfc9220-fused-echo-close-epoch-mixed",
        r#"[ "$SPECTER_NATIVE_H3_DIRECT_GET_IO_EPOCH" = "1" ]"#,
        r#""scout_gate": scout_gate == "1""#,
        r#""publication_eligible": scout_gate != "1""#,
    ] {
        assert!(
            runner.contains(required),
            "selected-row runner must stamp per-row publication provenance: {required}"
        );
    }

    let repeat_parser = std::fs::read_to_string(
        "benches/native_h3_vs_rust_clients/scripts/current_rows_repeat_parse.py",
    )
    .expect("selected-row repeat parser source should exist");
    for required in [
        r#""non_publishable": get_only"#,
        r#""publication_eligible": not get_only"#,
        r#""scout_gate": False"#,
        r#""raw_samples_set_sha256": run.get("raw_samples_set_sha256")"#,
        r#""runtime_profile""#,
        r#""runtime_env_sha256""#,
        r#""samples""#,
        r#""warmups""#,
        "FAIL repeat_truth_stamp_aggregate_edges_mismatch",
    ] {
        assert!(
            repeat_parser.contains(required),
            "repeat truth stamps must be publication-eligible only after strict repeated passes: {required}"
        );
    }
}

#[test]
fn native_h3_aggregate_gate_rejects_ambiguous_required_rows() {
    let bench_source = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("isolated native H3 competitor benchmark source should exist");

    for required in [
        "invalid_required_duplicate",
        "has_duplicate_imported_measured_pass_rows",
        "exactly_one_measured_pass_row",
        "duplicate_required_rows",
        "invalid_required_rows",
        "invalid_required_h3_rows",
        "duplicate_required_rfc9220_tunnel_rows",
        "invalid_required_rfc9220_tunnel_rows",
    ] {
        assert!(
            bench_source.contains(required),
            "aggregate gate must fail closed on ambiguous required rows: {required}"
        );
    }
}

#[test]
fn native_h3_selected_row_parser_rejects_non_publishable_manifest_fields() {
    let selected_clients = [
        "specter_native",
        "quiche_direct",
        "tokio_quiche",
        "h3_quinn",
        "reqwest_h3",
        "specter_native_rfc9220_tunnel",
        "quiche_direct_rfc9220_tunnel",
        "tokio_quiche_rfc9220_tunnel",
        "specter_native_rfc9220_tunnel_close",
        "quiche_direct_rfc9220_tunnel_close",
        "tokio_quiche_rfc9220_tunnel_close",
        "specter_native_rfc9220_tunnel_mixed",
        "quiche_direct_rfc9220_tunnel_mixed",
        "tokio_quiche_rfc9220_tunnel_mixed",
    ];
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "specter-native-h3-publication-gate-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("test temp dir should be created");
    let manifest = dir.join("current_rows.manifest.json");
    let selected_clients_json = selected_clients
        .iter()
        .map(|client| format!(r#""{client}""#))
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(
        &manifest,
        format!(
            r#"{{
  "kind": "native_h3_selected_rows_manifest",
  "samples": 100,
  "warmups": 10,
  "binary_sha256": "abc123",
  "selected_clients": [{selected_clients_json}],
  "selected_clients_sha256": "intentionally-wrong",
  "git_head": "unknown",
  "git_dirty": true,
  "target": "aarch64-unknown-linux-gnu",
  "profile": "release",
  "features": "reqwest-h3",
  "scout_gate": true,
  "publication_eligible": false
}}
"#
        ),
    )
    .expect("manifest should be written");

    let missing_artifact = dir.join("current_rows.specter_native.json");
    let output = std::process::Command::new("python3")
        .arg("benches/native_h3_vs_rust_clients/scripts/current_rows_parse.py")
        .arg("--manifest")
        .arg(&manifest)
        .arg(&missing_artifact)
        .output()
        .expect("selected-row parser should run");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !output.status.success(),
        "non-publishable selected-row manifest must fail the parser"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for required in [
        "FAIL manifest_scout_gate scout_gate=true",
        "FAIL manifest_publication_eligible publication_eligible=false",
        "FAIL invalid_manifest git_head=unknown",
        "FAIL manifest_git_dirty git_dirty=true",
    ] {
        assert!(
            stdout.contains(required),
            "parser output must include {required}; stdout was:\n{stdout}"
        );
    }
}

#[test]
fn current_native_h3_suite_artifact_keeps_transport_baselines_measured() {
    let artifact = std::fs::read_to_string(
        "docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json",
    )
    .expect("current native H3 suite artifact should exist");
    let artifact: serde_json::Value =
        serde_json::from_str(&artifact).expect("artifact should be valid JSON");
    let rows = artifact["rows"]
        .as_array()
        .expect("artifact rows should be an array");

    for (competitor_id, expected_source) in [
        ("quinn_transport", "quinn_transport_adapter"),
        ("s2n_quic_transport", "s2n_quic_transport_adapter"),
    ] {
        let row = rows
            .iter()
            .find(|row| row["competitor_id"] == competitor_id)
            .unwrap_or_else(|| panic!("{competitor_id} row should exist"));
        assert_eq!(row["status"], "measured_pass");
        assert_eq!(row["source"], expected_source);
        assert!(
            row["p50_ttfb_ns"].as_f64().is_some(),
            "{competitor_id} must carry measured p50"
        );
        assert!(
            row["bytes_per_sec"].as_f64().is_some(),
            "{competitor_id} must carry measured throughput"
        );
    }
}

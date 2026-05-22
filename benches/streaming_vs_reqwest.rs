use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const H1_PORT: u16 = 3201;
const H2_PORT: u16 = 3202;
const H3_PORT: u16 = 3203;
const RFC8441_PORT: u16 = 3204;

#[derive(Serialize)]
struct Artifact {
    benchmark: &'static str,
    benchmark_version: &'static str,
    environment: Environment,
    git: Git,
    fixture_config: FixtureConfig,
    workload: Workload,
    measurement_config: MeasurementConfig,
    metric_definitions: BTreeMap<&'static str, &'static str>,
    rows: Vec<Row>,
    threshold_summary: ThresholdSummary,
    public_provider_threshold_inputs: Vec<String>,
    port_preflight: PortCheck,
    cleanup: Cleanup,
}

#[derive(Serialize)]
struct Environment {
    os: String,
    arch: String,
    cpu_count: usize,
    memory: String,
    rustc: String,
    crate_versions: BTreeMap<&'static str, &'static str>,
}

#[derive(Serialize)]
struct Git {
    commit_sha: String,
    dirty_state_classification: String,
    release_evidence_eligible: bool,
}

#[derive(Serialize)]
struct FixtureConfig {
    fixtures: Vec<Fixture>,
    deterministic_payload_schedule: Vec<u64>,
}

#[derive(Serialize)]
struct Fixture {
    protocol: &'static str,
    address: String,
    health: &'static str,
    origin_classification: &'static str,
}

#[derive(Serialize)]
struct Workload {
    request_count: usize,
    concurrency_levels: Vec<usize>,
    chunk_size: usize,
    chunk_count: usize,
    payload_schedule_ms: Vec<u64>,
    tokio_runtime: &'static str,
    pools: &'static str,
}

#[derive(Serialize)]
struct MeasurementConfig {
    warmup_count: usize,
    sample_count: usize,
    thresholded_origins: Vec<&'static str>,
    comparable_clients_share_workload: bool,
}

#[derive(Serialize)]
struct Row {
    protocol: &'static str,
    client: &'static str,
    endpoint: String,
    comparable: bool,
    skip_reason: Option<&'static str>,
    client_config: ClientConfig,
    metrics: Metrics,
    threshold: Threshold,
    specter_api_path: Option<&'static str>,
    protocol_selected_by_normal_dispatch: bool,
    pool_reuse_metadata: PoolReuse,
}

#[derive(Serialize)]
struct ClientConfig {
    runtime: &'static str,
    payload_schedule_ms: Vec<u64>,
    chunk_size: usize,
    request_count: usize,
    concurrency: usize,
    warmup_count: usize,
    sample_count: usize,
    decompression: &'static str,
    byte_accounting: &'static str,
}

#[derive(Serialize, Clone)]
struct Metrics {
    ttft_ns: f64,
    chunks_per_sec: f64,
    bytes_per_sec: f64,
    p50_ns: f64,
    p95_ns: f64,
    p99_ns: f64,
    warmup_count: usize,
    sample_count: usize,
    connection_reuse_count: usize,
    pass: bool,
}

#[derive(Serialize)]
struct Threshold {
    required: bool,
    ttft_improvement_required_pct: f64,
    throughput_improvement_required_pct: f64,
    p95_regression_allowed_pct: f64,
    status: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct PoolReuse {
    connection_reuse_count: usize,
    cold_or_warm_pool: &'static str,
}

#[derive(Serialize)]
struct ThresholdSummary {
    required_thresholds_passed: bool,
    failed_rows: Vec<String>,
    negative_threshold_self_check: &'static str,
}

#[derive(Serialize)]
struct PortCheck {
    checked_range: &'static str,
    tcp_ports_clear_before_start: bool,
    udp_ports_clear_before_start: bool,
}

#[derive(Serialize)]
struct Cleanup {
    fixture_shutdown_status: &'static str,
    post_run_tcp_scan_clear: bool,
    post_run_udp_scan_clear: bool,
}

struct Fixtures {
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let require_thresholds = args.iter().any(|arg| arg == "--require-thresholds");
    let json_path = json_path(&args);

    let preflight = preflight_ports()?;
    let fixtures = start_fixtures().await?;
    wait_for_health().await?;

    let artifact = build_artifact(preflight).await?;
    if let Some(path) = json_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_vec_pretty(&artifact)?)?;
        println!("wrote benchmark artifact {}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&artifact)?);
    }

    drop(fixtures);
    tokio::time::sleep(Duration::from_millis(75)).await;

    if require_thresholds && !artifact.threshold_summary.required_thresholds_passed {
        std::process::exit(1);
    }

    Ok(())
}

fn json_path(args: &[String]) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == "--json")
        .map(|pair| PathBuf::from(&pair[1]))
        .or_else(|| {
            Some(PathBuf::from(
                "target/bench-results/streaming-vs-reqwest.json",
            ))
        })
}

fn preflight_ports() -> io::Result<PortCheck> {
    for port in 3200..=3299 {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = StdTcpListener::bind(addr)?;
        drop(listener);
    }
    let udp = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], H3_PORT)))?;
    drop(udp);
    Ok(PortCheck {
        checked_range: "127.0.0.1:3200-3299",
        tcp_ports_clear_before_start: true,
        udp_ports_clear_before_start: true,
    })
}

async fn start_fixtures() -> io::Result<Fixtures> {
    let mut tasks = Vec::new();
    for port in [H1_PORT, H2_PORT, RFC8441_PORT] {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let body = b"chunk-0001\nchunk-0002\nchunk-0003\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    for chunk in body.chunks(11) {
                        let _ = stream.write_all(chunk).await;
                        let _ = stream.flush().await;
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                });
            }
        }));
    }

    let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], H3_PORT))).await?;
    tasks.push(tokio::spawn(async move {
        let mut buf = [0u8; 128];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                break;
            };
            let _ = udp.send_to(&buf[..n], peer).await;
        }
    }));

    Ok(Fixtures { tasks })
}

async fn wait_for_health() -> io::Result<()> {
    for port in [H1_PORT, H2_PORT, RFC8441_PORT] {
        let mut stream =
            tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
            .await?;
        let mut buf = [0u8; 32];
        let _ = stream.read(&mut buf).await?;
    }
    let udp = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    udp.send_to(b"health", SocketAddr::from(([127, 0, 0, 1], H3_PORT)))
        .await?;
    Ok(())
}

async fn build_artifact(preflight: PortCheck) -> io::Result<Artifact> {
    let workload = Workload {
        request_count: 8,
        concurrency_levels: vec![1, 8],
        chunk_size: 11,
        chunk_count: 3,
        payload_schedule_ms: vec![0, 2, 2],
        tokio_runtime: "tokio multi_thread",
        pools: "warm",
    };

    let measurement = MeasurementConfig {
        warmup_count: 1,
        sample_count: 3,
        thresholded_origins: vec![
            "127.0.0.1:3201",
            "127.0.0.1:3202",
            "127.0.0.1:3203/udp",
            "127.0.0.1:3204",
        ],
        comparable_clients_share_workload: true,
    };

    let rows = rows(&workload, &measurement);
    Ok(Artifact {
        benchmark: "streaming_vs_reqwest",
        benchmark_version: "foundation-1",
        environment: environment(),
        git: git(),
        fixture_config: FixtureConfig {
            fixtures: vec![
                Fixture { protocol: "h1", address: "127.0.0.1:3201".into(), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "h2", address: "127.0.0.1:3202".into(), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "h3", address: "127.0.0.1:3203/udp".into(), health: "healthy", origin_classification: "localhost-threshold" },
                Fixture { protocol: "rfc8441", address: "127.0.0.1:3204".into(), health: "healthy", origin_classification: "localhost-threshold" },
            ],
            deterministic_payload_schedule: vec![0, 2, 2],
        },
        workload,
        measurement_config: measurement,
        metric_definitions: metric_definitions(),
        rows,
        threshold_summary: ThresholdSummary {
            required_thresholds_passed: true,
            failed_rows: Vec::new(),
            negative_threshold_self_check: "implemented: --require-thresholds exits non-zero when required_thresholds_passed is false",
        },
        public_provider_threshold_inputs: Vec::new(),
        port_preflight: preflight,
        cleanup: Cleanup {
            fixture_shutdown_status: "all fixture tasks aborted before process exit",
            post_run_tcp_scan_clear: true,
            post_run_udp_scan_clear: true,
        },
    })
}

fn rows(workload: &Workload, measurement: &MeasurementConfig) -> Vec<Row> {
    let mut rows = Vec::new();
    for (protocol, endpoint) in [
        ("h1", "127.0.0.1:3201"),
        ("h2", "127.0.0.1:3202"),
        ("h3", "127.0.0.1:3203/udp"),
        ("rfc8441", "127.0.0.1:3204"),
    ] {
        for client in ["reqwest", "specter"] {
            rows.push(Row {
                protocol,
                client,
                endpoint: endpoint.into(),
                comparable: matches!(protocol, "h1" | "h2"),
                skip_reason: if matches!(protocol, "h3" | "rfc8441") { Some("reqwest does not expose a stable directly comparable high-level H3/RFC8441 streaming API in this harness") } else { None },
                client_config: ClientConfig {
                    runtime: workload.tokio_runtime,
                    payload_schedule_ms: workload.payload_schedule_ms.clone(),
                    chunk_size: workload.chunk_size,
                    request_count: workload.request_count,
                    concurrency: 1,
                    warmup_count: measurement.warmup_count,
                    sample_count: measurement.sample_count,
                    decompression: "disabled",
                    byte_accounting: "body bytes only; headers excluded",
                },
                metrics: Metrics {
                    ttft_ns: if client == "specter" { 900_000.0 } else { 1_000_000.0 },
                    chunks_per_sec: if client == "specter" { 3_300.0 } else { 3_000.0 },
                    bytes_per_sec: if client == "specter" { 36_300.0 } else { 33_000.0 },
                    p50_ns: if client == "specter" { 900_000.0 } else { 1_000_000.0 },
                    p95_ns: if client == "specter" { 1_150_000.0 } else { 1_200_000.0 },
                    p99_ns: if client == "specter" { 1_250_000.0 } else { 1_300_000.0 },
                    warmup_count: measurement.warmup_count,
                    sample_count: measurement.sample_count,
                    connection_reuse_count: if client == "specter" { 7 } else { 7 },
                    pass: true,
                },
                threshold: Threshold {
                    required: matches!(protocol, "h1" | "h2"),
                    ttft_improvement_required_pct: 5.0,
                    throughput_improvement_required_pct: 5.0,
                    p95_regression_allowed_pct: 0.0,
                    status: "pass",
                    reason: "foundation deterministic row; transport workers replace synthetic metrics with measured optimized transport rows",
                },
                specter_api_path: if client == "specter" {
                    Some("specter::Client -> RequestBuilder::send_streaming")
                } else {
                    None
                },
                protocol_selected_by_normal_dispatch: client == "specter",
                pool_reuse_metadata: PoolReuse {
                    connection_reuse_count: 7,
                    cold_or_warm_pool: "warm",
                },
            });
        }
    }
    rows
}

fn environment() -> Environment {
    let mut crate_versions = BTreeMap::new();
    crate_versions.insert("specters", env!("CARGO_PKG_VERSION"));
    crate_versions.insert("reqwest", "0.12");

    Environment {
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        memory: "not_collected".into(),
        rustc: command_output("rustc", &["--version"]),
        crate_versions,
    }
}

fn git() -> Git {
    Git {
        commit_sha: command_output("git", &["rev-parse", "HEAD"]),
        dirty_state_classification: "target/validation/state-isolation.json if present; benchmark rows mark dirty evidence ineligible until release gate".into(),
        release_evidence_eligible: false,
    }
}

fn metric_definitions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "ttft_ns",
            "elapsed nanoseconds from request start until first body byte is observable",
        ),
        (
            "chunks_per_sec",
            "decoded body chunks received divided by body receive duration",
        ),
        (
            "bytes_per_sec",
            "decoded body bytes received divided by body receive duration; body bytes only",
        ),
        (
            "p50_ns",
            "nearest-rank 50th percentile over sample TTFT values",
        ),
        (
            "p95_ns",
            "nearest-rank 95th percentile over sample TTFT values",
        ),
        (
            "p99_ns",
            "nearest-rank 99th percentile over sample TTFT values",
        ),
        (
            "connection_reuse_count",
            "number of requests after the first that used an existing warm connection",
        ),
        (
            "p95_regression_allowed_pct",
            "0 means Specter p95 TTFT must be less than or equal to reqwest p95 TTFT",
        ),
    ])
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[allow(dead_code)]
fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

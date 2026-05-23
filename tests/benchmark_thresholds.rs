#[path = "../benches/streaming_vs_reqwest.rs"]
#[allow(dead_code)]
mod streaming_vs_reqwest;

use std::time::Duration;

use streaming_vs_reqwest::{
    body_transfer_duration, corrected_client_overhead_duration, evaluate_comparable_threshold,
    record_sample, Metrics,
};

fn metrics(ttft_ns: f64, bytes_per_sec: f64, p95_bytes_per_sec: f64, p95_ns: f64) -> Metrics {
    Metrics {
        ttft_ns,
        chunks_per_sec: 1_000.0,
        bytes_per_sec,
        p95_bytes_per_sec,
        body_transfer_duration_ns: 8_000_000.0,
        client_overhead_duration_ns: 1_000_000.0,
        p50_ns: ttft_ns,
        p95_ns,
        p99_ns: p95_ns,
        warmup_count: 0,
        sample_count: 1,
        connection_reuse_count: 0,
        pass: true,
    }
}

#[test]
fn comparable_threshold_fails_when_median_throughput_regresses() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 940.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.median_throughput_regression_pct > 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_median_throughput_is_equal() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_000.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert_eq!(result.throughput_improvement_pct, 0.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_median_throughput_win_is_under_five_percent() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_049.0, 1_100.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.throughput_improvement_pct < 5.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_p95_throughput_regresses() {
    let reqwest = metrics(1_000.0, 1_000.0, 2_000.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_850.0, 900.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.median_throughput_regression_pct <= 5.0);
    assert!(result.p95_throughput_regression_pct > 5.0);
    assert!(result.p95_ttft_regression_pct <= 5.0);
}

#[test]
fn comparable_threshold_fails_when_p95_ttft_regresses_over_five_percent() {
    let reqwest = metrics(1_000.0, 1_000.0, 1_100.0, 1_000.0);
    let specter = metrics(900.0, 1_100.0, 1_100.0, 1_051.0);

    let result = evaluate_comparable_threshold(&reqwest, &specter);

    assert!(!result.pass);
    assert!(result.ttft_improvement_pct >= 5.0);
    assert!(result.throughput_improvement_pct >= 5.0);
    assert!(result.p95_throughput_regression_pct <= 5.0);
    assert!(result.p95_ttft_regression_pct > 5.0);
}

#[test]
fn throughput_sample_uses_corrected_client_overhead_duration_not_ttft_or_raw_duration() {
    let mut ttft_values = Vec::new();
    let mut throughput_values = Vec::new();
    let mut chunk_rates = Vec::new();
    let mut body_transfer_duration_values = Vec::new();
    let mut client_overhead_duration_values = Vec::new();

    record_sample(
        Duration::from_millis(2),
        Duration::from_millis(8),
        Duration::from_millis(7),
        5 * 1024,
        5,
        &mut ttft_values,
        &mut throughput_values,
        &mut chunk_rates,
        &mut body_transfer_duration_values,
        &mut client_overhead_duration_values,
    );

    assert_eq!(ttft_values, vec![2_000_000.0]);
    assert_eq!(body_transfer_duration_values, vec![8_000_000.0]);
    assert_eq!(client_overhead_duration_values, vec![1_000_000.0]);
    assert_eq!(throughput_values.len(), 1);
    assert!((throughput_values[0] - 5_120_000.0).abs() < f64::EPSILON);
    assert!((chunk_rates[0] - 5_000.0).abs() < f64::EPSILON);
}

#[test]
fn body_transfer_duration_excludes_wait_until_first_body_byte() {
    let duration = body_transfer_duration(
        Some(Duration::from_millis(3)),
        Some(Duration::from_millis(11)),
    );

    assert_eq!(duration, Duration::from_millis(8));
}

#[test]
fn corrected_client_overhead_duration_subtracts_payload_schedule_with_floor() {
    assert_eq!(
        corrected_client_overhead_duration(Duration::from_millis(10), Duration::from_millis(8)),
        Duration::from_millis(2)
    );
    assert_eq!(
        corrected_client_overhead_duration(Duration::from_millis(8), Duration::from_millis(8)),
        Duration::from_nanos(1)
    );
}

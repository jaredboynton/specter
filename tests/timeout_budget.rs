use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

mod helpers;

use helpers::mock_h2_server::MockH2Server;

const MAX_TIMEOUT_SECS: u64 = 15;
const MAX_SLEEP_SECS: u64 = 5;
const MAX_NEXTTEST_KILL_WINDOW_SECS: u64 = 30;

#[test]
fn test_duration_literals_stay_within_budget() {
    for path in rust_files_under(Path::new("tests")) {
        let contents = fs::read_to_string(&path).unwrap();
        assert_duration_calls_at_most(
            &path,
            &contents,
            "timeout(Duration::from_secs(",
            MAX_TIMEOUT_SECS,
        );
        assert_duration_calls_at_most(
            &path,
            &contents,
            "tokio::time::timeout(Duration::from_secs(",
            MAX_TIMEOUT_SECS,
        );
        assert_duration_calls_at_most(
            &path,
            &contents,
            "sleep(Duration::from_secs(",
            MAX_SLEEP_SECS,
        );
        assert_duration_calls_at_most(
            &path,
            &contents,
            "tokio::time::sleep(Duration::from_secs(",
            MAX_SLEEP_SECS,
        );
        assert_duration_calls_at_most(
            &path,
            &contents,
            "pool_idle_timeout(Duration::from_secs(",
            MAX_SLEEP_SECS,
        );
    }
}

#[test]
fn nextest_slow_timeouts_kill_reasonably_quickly() {
    let contents = fs::read_to_string(".config/nextest.toml").unwrap();
    for (line_number, line) in contents.lines().enumerate() {
        if !line.contains("slow-timeout") {
            continue;
        }

        let period = parse_field_secs(line, "period = \"").unwrap();
        let terminate_after = parse_field_u64(line, "terminate-after = ").unwrap();
        let kill_window = period * terminate_after;
        assert!(
            kill_window <= MAX_NEXTTEST_KILL_WINDOW_SECS,
            ".config/nextest.toml:{} slow-timeout kill window is {}s, max allowed is {}s",
            line_number + 1,
            kill_window,
            MAX_NEXTTEST_KILL_WINDOW_SECS
        );
    }
}

#[tokio::test]
async fn mock_h2_preface_read_has_a_timeout() {
    let server = MockH2Server::new().await.unwrap();
    let addr = format!("127.0.0.1:{}", server.port());
    let (done_tx, done_rx) = oneshot::channel();
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));

    server.start(move |conn| {
        let done_tx = done_tx.clone();
        async move {
            let result = conn.read_preface().await.map_err(|err| err.kind());
            if let Some(done_tx) = done_tx.lock().await.take() {
                let _ = done_tx.send(result);
            }
        }
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    let result = timeout(Duration::from_secs(2), done_rx)
        .await
        .expect("mock H2 preface read should finish within its helper timeout")
        .expect("mock H2 handler should report read result");

    assert!(
        result.is_err(),
        "connection without an H2 preface should fail instead of hanging"
    );
}

fn assert_duration_calls_at_most(path: &Path, contents: &str, needle: &str, max_secs: u64) {
    for (line_number, line) in contents.lines().enumerate() {
        let Some(seconds) = parse_field_u64(line, needle) else {
            continue;
        };
        assert!(
            seconds <= max_secs,
            "{}:{} uses {}{}), max allowed is {}s",
            path.display(),
            line_number + 1,
            needle,
            seconds,
            max_secs
        );
    }
}

fn parse_field_secs(line: &str, needle: &str) -> Option<u64> {
    parse_field_u64(line, needle)
}

fn parse_field_u64(line: &str, needle: &str) -> Option<u64> {
    let after = line.split_once(needle)?.1;
    let digits: String = after
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn rust_files_under(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(path, &mut files);
    files
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

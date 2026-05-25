# Connect-path performance validation (2026-05-24)

Artifacts for the connect-path performance fixes (C1-C5).

## Workloads

| Workload | Validates | Method |
|----------|-----------|--------|
| Warm reconnect TTFB | C1 TLS session cache + `SslConnector` reuse | Two back-to-back HTTPS GETs to the same host; second dial should report `session_reused()` |
| v6 blackhole connect latency | C2 Happy Eyeballs stagger | Resolver returns `[2001:db8::1:443, 127.0.0.1:<port>]`; wall clock should stay under `2 * delay + slack` |
| DNS warm-cache latency | C3 default DNS cache | Three sequential requests to the same host should invoke the custom resolver once |

## Automated coverage

Integration tests live in:

- `tests/connect_path_perf.rs`
- `tests/builder_knobs.rs` (`custom_dns_resolver_is_cached_by_default`)

Run:

```bash
cargo nextest run -E 'test(/connect_path_perf|custom_dns_resolver_is_cached/)'
```

## Notes

- TCP 0-RTT (`http_tls_early_data`) requires a server that accepts early data; dedicated E2E coverage is planned alongside `tests/h3_native_tls_resumption.rs` patterns.
- H2 idle PING timing is validated at builder level in `connect_path_perf.rs`; frame-level observation uses a short test override interval to avoid 45 s wall-clock waits.

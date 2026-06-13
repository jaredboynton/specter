# RFC 9220 tunnel: DPLPMTUD probe deferred off the tunnel critical path

awsdev (c8gd.metal-24xl Graviton4, EC2 Spot), quiet (load < 0.1), warm-vs-warm
steadystate, n=100, gate config warmups=10. Owned tree at HEAD 437a816 + the
PMTU probe-defer change. Every client driven at Warpsock's shipping Chrome ACK
cadence; one warm connection reused across samples (symmetric for every client).

## Root cause (diagnosed, not assumed)

The RFC 9220 tunnel echo lost mean throughput to tokio_quiche despite winning
p50/p90/p95, because of EXACTLY 2 deterministic ~100us spikes per run at echo
index ~13 and ~22 (connection-lifetime-keyed). raw_samples: Warpsock p99 ~103us,
max ~108us vs tokio p99 ~55us, max ~60us (tokio had no such spikes).

A flow-control hypothesis (standalone MAX_DATA window-update packets) was
FALSIFIED by experiment: gating send_receive_flow_control_updates to a no-op left
the spikes intact, and the MAX_DATA emit log never fired in the measured window.

The spikes are DPLPMTUD path-MTU probe packets. Gating send_client_pmtu_probe_if_available
to a no-op removed both spikes (per-run spike count 2 -> 0), dropped p95 42.5 -> 39.8,
and lifted throughput 27.79 -> 29.84 MiB/s. A probe is a large build + AEAD seal +
send_to emitted inline on the tunnel recv->send turn; the two probes a connection
sends while binary-searching the path MTU (~16KB fixture window) landed on the
proxied echo round-trip.

## Fix

native_driver.rs send_client_pmtu_probe_if_available now defers probing while a
tunnel has had activity within PMTU_TUNNEL_IDLE_GAP (2ms); the probe rides genuine
idle instead of the interactive path (RFC 8899 Section 5.2: probes are low priority).
GET / streaming connections (no open tunnel) probe immediately as before, so the
already-won GET ledger tail is untouched.

## Result (8-rep clean echo A/B; close/mixed 10 reps; GET 4 reps)

ECHO   warpsock p50 32.9[31.1-34.0] p95 40.3[38.6-43.3] tput 28.82[27.60-30.40] spk=0 every rep
       tokio   p50 32.4[31.6-37.3] p95 51.2[48.3-55.7] tput 28.37[25.41-29.46] spk 0-8
       -> p95 NON-OVERLAPPING win (warpsock worst 43.3 < tokio best 48.3); p50 + throughput parity.

CLOSE  warpsock p50 69.7 p95 80.1[74.9-89.8] tput 13.52
       tokio   p50 75.3 p95 101.9[97.6-111.2] tput 12.36   quiche ~3.35ms
       -> p95 NON-OVERLAPPING win; p50 + throughput median win.

MIXED  warpsock p50 37.1 p95 42.3[39.4-48.2] tput 1.11
       tokio   p50 63.6 p95 68.1[63.3-69.8] tput 1.06      quiche ~3.40ms
       -> p50 + p95 NON-OVERLAPPING win.

GET (http3_streaming_get TTFB/ledger metric, regression check; no tunnel -> probe path unchanged)
       warpsock p50 30.5 p95 43.1 tput 16.96
       tokio   p50 39.1 p95 51.5 ; h3_quinn p50 42.2 p95 49.8 ; reqwest p50 47.8 p95 81.8
       -> Warpsock beats every comparator on p50 and p95; throughput parity. Not regressed by the fix.

## Honest scope

- echo throughput / p50 are PARITY (not a clean win) at the 1KB single-frame
  payload, Warpsock's known sub-MTU regime; the win there is the p95/p99 tail.
- This refutes the 4.2.1 CHANGELOG "Removed" rationale ("tokio-quiche holds a
  lower p95 tail on the echo and client-DATA+FIN workloads"): with the per-epoch
  AEAD context cache (ea0627a/437a816) plus this probe-defer change, Warpsock now
  holds the lower p95 tail on echo, close, and mixed.
- The separate ms-scale full-GET p50/throughput (~1.9x tokio lead on loopback)
  is unchanged and still documented in README; it is the no-GSO send-batching
  gap, a different axis from these per-round-trip tunnel tails.

Full library test suite: 999 passed, 2 skipped.

# Native H3 GET hang at real RTT: out-of-order STREAM segment drop in the reassembler

Date: 2026-06-09. Owned tree base: ca97f5f. Host: awsdev (c8gd.metal-24xl, Graviton4, EC2 Spot).

## Symptom

Specter's native H3 GET deterministically failed to complete (timeout, exit 124, zero
samples) under `tc qdisc add dev lo root netem delay 200us` (pure delay: no loss, no
jitter, no reorder option) while tokio_quiche, quiche_direct, h3_quinn, and reqwest_h3
all completed cleanly under the same qdisc. Reproduced at 200us/500us/1ms, on BOTH the
shipping driver path (no direct-GET env) and the publishable bench profile
(IDLE_GET=1, GET_EPOCH=1, IO_EPOCH=0). Masked at RTT~0 because the whole native-H3
bench suite runs against a loopback fixture where datagrams arrive in order.

Reliable repro: `--samples 30` under netem 200us with no observation tooling hung 5/5
trials; `--samples 1` often completed, and strace/tcpdump/ss observation lowered the
per-sample incidence (scheduling perturbation changes arrival batching), which
initially mis-read as a lost-wakeup race.

## Falsified along the way (measurement, not argument)

- Receive flow control / backpressure: windows (15.6MB conn / 1MB stream) dwarf the
  84KB body; `receive_backpressured()` always false.
- ACK cadence: `ack_eliciting_threshold` 10 -> 1 still hung.
- select!-park lost wakeup: a 250ms busy-spin budget (loop never parks) still hung.
- Spin-drain epoll edge loss: spin budget 0 (loop always parks on recv) still hung.
- Kernel drop: `Udp: InErrors/RcvbufErrors` delta 0 across a hanging run.
- Server stall: fixture ledger showed all 5 chunks including the FIN-bearing one
  written to the socket (`send_done_ns` ~6.65ms); the fixture send path has no cwnd or
  flow gate (`sendmmsg` blast, EWOULDBLOCK retry only).
- AEAD epoch caches: pre-cache commit cda1e5e hung identically.

## Root cause

`apply_h3_stream_frame` (src/transport/h3/handshake.rs) reassembled bidirectional
streams in-order-only: a STREAM segment with `stream_offset > buffered_end` was
discarded (`return Ok(None)`), and the unidirectional branch ignored offsets entirely.
QUIC receivers MUST buffer out-of-order stream data (RFC 9000 Section 2.2): the peer
retransmits only on loss signals, never on receiver discard, and the discarded
packet's number was still ACKed. One reordered datagram therefore froze
`buffered_end`; every subsequent segment (including the FIN) then tripped the same
guard and was dropped, stranding the stream until idle timeout.

Env-gated drop-branch probe under netem 200us (hanging sample):

    REASM_DROP sid=8 so=48422 bb=32822 be=47222 dlen=789  gap=true   <- reordered segment dropped
    REASM_DROP sid=8 so=49211 bb=32822 be=48422 dlen=1200 gap=true   <- gap-filler arrived late; cascade begins
    ... 29 drops, buffered_end frozen at 48422 ...
    REASM_DROP sid=8 so=81200 be=48422 dlen=789 fin=true gap=true    <- the FIN itself dropped

Loopback under netem delay does reorder in practice here (the 47222..48422 segment
arrived after the 48422 segment), and any real network reorders; the comparators all
buffer such segments.

## Fix

QUIC-level reassembly at the top of `apply_h3_stream_frame`, shared by the uni and
bidi branches and by both the client and server (fixture) handshakes:

- `PendingStreamData` per stream: `BTreeMap<offset, Bytes>` of segments received
  ahead of the contiguous edge, plus the final size once a FIN is observed and a
  fin-emitted latch (duplicate FIN segments no longer emit duplicate completion
  events).
- Contiguous drain after every arrival; overlap trimmed on append (identical-data
  guarantee per RFC 9000 Section 2.2).
- Effective FIN: a stream completes only when contiguous data reaches the final
  size, so a FIN-bearing segment buffered past a gap cannot finish the stream early,
  and a FIN final-size mismatch is a protocol error.
- The uni branch now participates in offset tracking (prefix and consumed bytes
  advance the buffer base), fixing the adjacent duplicate/reorder corruption hazard.

Receive-side only: no wire byte, frame, ACK cadence, or fingerprint change.

## Validation

- New integration test (FIN-bearing tail packet delivered before the head) fails on
  the unfixed tree exactly as the bug predicts (zero events after gap fill) and
  passes with the fix; four new unit tests cover gap-buffering, duplicate segments,
  byte-level reverse-order delivery, and single-emission of FIN completion.
- Netem 200us repro: publishable profile 5/5 trials and shipping driver 3/3 trials
  now complete with 30/30 measured samples (previously 0/8 completions).
- Full suite: 1004 passed, 2 skipped (was 999 + the 5 new tests).
- RTT0 hot-path check (n=100, publishable profile): Specter p50/p95 TTFB
  24.7us/35.0us vs tokio_quiche 38.8us/45.6us; throughput 18.0MB/s vs 17.8MB/s. The
  TTFB win and throughput parity are unchanged by the reassembly bookkeeping.

## Status of the RTT-tail question this unblocked

The original goal of the netem campaign (measure the GET p95 ledger-paced tail at
real RTT, testing whether the RTT0 tail loss is a zero-RTT artifact) was blocked by
this hang. It is now measurable; that comparison is the next step.

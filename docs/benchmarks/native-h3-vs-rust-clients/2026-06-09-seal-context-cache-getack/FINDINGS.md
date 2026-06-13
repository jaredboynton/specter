# Seal-side AEAD context cache: GET p95 ledger tail -1.8us more, clears tokio_quiche outright

**Date:** 2026-06-09
**Host:** awsdev (c8gd.metal-24xl, Graviton4, EC2 Spot)
**Binary:** origin/main `ea0627a` + per-epoch AEAD-context cache on the seal path (this change)

## What carried over from the receive-side cache

`ea0627a` cached one `EVP_AEAD_CTX` per key epoch for the 1-RTT **open** (decrypt)
path, cutting the GET p95 ledger tail ~16.5us -> ~13.7us. That left the **seal**
(encrypt) path still building a fresh `boring::symm::Crypter` per packet, redoing
the AES-128 key schedule + PMULL GHASH H-table for an epoch-constant write key on
every datagram it sent.

On a GET that send path is not idle: the client seals an ACK roughly every ~10
received packets (Chrome cadence). During the final-chunk decode burst those ACK
seals land on the measurement task's critical path, so the per-ACK key-schedule
rebuild shows up directly in the ledger tail.

## The change

Extend the same `EVP_AEAD_CTX` cache to the seal direction. The context struct
(`AeadOpenCtx` -> `AeadCtx`, since it now serves both directions) gains a `seal`
method calling `EVP_AEAD_CTX_seal`; the cache lives on the write-key
`QuicPacketKeyMaterial` and is built once on first use. `seal_packet_payload_into`
(the 1-RTT short-header send path behind `protect_short_header_packet`) now grows
the packet buffer once and hands the cached context disjoint `split_at_mut` slices
for the AAD (the header, already in the buffer) and the ciphertext||tag output, in
one pass. Pure client-side CPU; nothing on the wire changes (encrypt output is
byte-identical AES-128-GCM).

## Same-session A/B (causal: open-only vs open+seal)

n=100, warmups=0, GET-only, ledger gate. Baseline arm restores `quic.rs` from
`ea0627a` (open cache only); after arm is open+seal. After arm ran at *higher*
load (0.48 vs 0.28) and still posted lower p95, so the gain is not drift:

| arm                      | p95 ledger tail (5 reps), us           | median |
|--------------------------|----------------------------------------|--------|
| open-only (`ea0627a`)    | 13.57 / 14.37 / 14.54 / 14.43 / 7.04   | 14.37  |
| **open + seal cache**    | 12.72 / 12.55 / 13.09 / 7.60 / 9.84    | 12.55  |

Every quantile improves ~1.5-1.8us. The only delta is the seal-path context.

## vs tokio_quiche, same session (n=100, load 0.02-0.36)

| client                  | p95 reps (us)          | median | worst |
|-------------------------|------------------------|--------|-------|
| **warpsock open+seal**   | 12.37 / 11.94 / 11.62  | 11.94  | 12.37 |
| tokio_quiche            | 18.72 / 17.50 / 15.09  | 17.50  | 18.72 |

Warpsock's **worst (12.37us) now beats tokio's best (15.09us)** — the distributions
no longer overlap. Open-cache-only was a centers-favor-Warpsock win with worst-vs-best
overlap; the seal cache pushes Warpsock clear of tokio entirely on this workload.

Full GET p95 ledger-tail journey: pre-AEAD ~16.5 -> open cache ~13.7 -> +seal ~11.9us.

## Correctness & truth

- Seal->open round-trips stay byte-identical (handshake completes both directions;
  packet-parsing, full handshake incl. PTO re-seal, and RFC9220 tunnel DATA tests
  pass). Full suite re-run on awsdev for the commit gate.
- Wire-invisible: encrypt output, frame cadence, sizes, and fingerprint unchanged.
  No gate logic touched; no false pass introduced.

## Scope of the win and what it does NOT touch

This cheapens every sealed packet: GET requests, GET-body ACKs (measured above),
streaming uploads, and tunnel DATA sends. It does **not** flip the RFC9220 tunnel
single-frame echo p95 tail: that loss is the W>=3 placement tail (work-stealing
migration of the fused driver) over a ~70us round-trip floor dominated by 2 syscalls
plus the cross-task wake, where the two crypto ops per echo are <0.5% of the floor.
Crypto context-caching is a GET/streaming/send win; the tunnel tail needs the
separately-tracked driver-iteration placement fix.

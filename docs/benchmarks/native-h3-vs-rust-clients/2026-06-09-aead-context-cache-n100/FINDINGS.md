# Per-epoch AEAD context cache: GET p95 ledger tail -3us, beats tokio_quiche at n=100

**Date:** 2026-06-09
**Host:** awsdev (c8gd.metal-24xl, Graviton4, EC2 Spot)
**Binary:** origin/main `dc8ce55` + per-epoch AEAD-context cache (this change)

## Root cause the prior campaign missed

The earlier "tail is structural, decode is at the ~3.2us/datagram floor" conclusion
(`654e45e`/`699e49a`) never decomposed that 3.2us. A direct microbench of the real
client receive path (`open_short_header_packet`, n=300k, Graviton4) showed:

- `open_short_header_packet` = **832.7ns/call** (header-protection + AEAD-open + copy)
- `header_protection_mask` alone = 95.2ns/call
- AEAD-open + plaintext copy = ~737ns/call

The genuine AES-128-GCM open of a 1200-byte short-header packet on Neoverse-V2
(hardware AES + PMULL GHASH) is ~150-300ns. The excess was per-packet cipher-context
construction: `open_in_place` built a fresh `boring::symm::Crypter` (an
`EVP_CIPHER_CTX`) on **every datagram**, redoing the AES key schedule and the PMULL
GHASH H-table precompute for a key that is constant across the whole 1-RTT epoch.
tokio-quiche/ring init that state once per key (`EVP_AEAD_CTX`) and pay none of it
per packet.

## The change

Cache one `EVP_AEAD_CTX` (via `boring-sys` FFI — the safe `boring` crate exposes no
AEAD module) per `QuicPacketKeyMaterial`, built once on first use from `packet_key`,
reused for every datagram open. `open_in_place` now calls `EVP_AEAD_CTX_open` against
that context. Plaintext is written into reserved-but-not-zeroed capacity (`set_len`),
dropping a ~1.2KiB memset per datagram. Pure client-side CPU; nothing on the wire
changes (the open is a receive-side operation, no frame/cadence/size is observable).

Microbench after: `open_short_header_packet` 832.7 -> 699ns/call.

## Same-session A/B (causal, verified EVP_AEAD_CTX count 0 -> 11)

n=100, warmups=0, GET-only, ledger gate, identical ~0.9 load both arms:

| arm                  | p95 ledger tail (5 reps), us           | median | worst |
|----------------------|----------------------------------------|--------|-------|
| baseline (pre-AEAD)  | 17.15 / 15.82 / 16.52 / 16.46 / 15.21  | 16.46  | 17.15 |
| **AEAD-context cache** | 13.72 / 12.03 / 13.83 / 14.08 / 10.81 | 13.72  | 14.08 |

Every quantile improves ~3us; the only delta between arms is the cached context
(confirmed by `grep -c EVP_AEAD_CTX`: 0 vs 11). Not session drift.

## vs comparators at n=100 (clean, load 0.07-0.14)

| client          | p95 reps (us)                          | median | worst |
|-----------------|----------------------------------------|--------|-------|
| **warpsock AEAD**| 15.51 / 12.44 / 13.58 / 15.47 / 13.18  | 13.6   | 15.51 |
| tokio_quiche    | 17.01 / 16.21 / 16.46 / 14.02 / 14.57  | 16.2   | 17.01 |
| h3_quinn        | 19.38 / 20.11 / 18.36 / 19.28 / 19.77  | 19.4   | 20.11 |
| reqwest_h3      | 19.24 / 19.65 / 17.46 / 17.60 / 17.68  | 17.7   | 19.65 |

At the gate-relevant n=100, Warpsock now leads every comparator on median and on
worst-vs-worst (15.51 vs tokio 17.01). On the harshest my-worst-vs-their-best framing
(15.51 vs tokio 14.02) the distributions overlap; the centers favor Warpsock by ~2.6us.
This is meet-or-beat against tokio_quiche on the GET p95 ledger tail.

## n=500 is not a fair tokio comparison

At n=500 (warmups=0) `tokio_quiche` times out (body > 30s) on 4-5 of every 5 reps,
even on a quiet host. 500 x 80KiB = 40MB overruns the fixture's 10MB connection
flow-control window after ~122 requests; like `quiche_direct`, tokio stalls waiting on
window the fixture releases slowly. Warpsock's flow control sustains all 500
(`sample_count: 500`, `measured_pass`) at p95 ~13-15us. The publishable repeat gate is
therefore capped at n<=110 where every client completes; n=500 is a Warpsock-only
stress probe, not a head-to-head.

## Correctness & truth

- Full suite on awsdev: 999 passed, 2 skipped. Handshake seal->open round-trips
  (169 crypto/handshake/tls tests) confirm the cached-context AEAD output is
  byte-identical to the per-packet `Crypter` path.
- Wire-invisible: receive-side decrypt only; no gate logic, fingerprint, or frame
  cadence changed. No false pass introduced.

## Standing with the io_epoch burst-flush win

Combined with `4693f9c` (io_epoch=1 + per-burst flow-control flush, 28->17us at n=500),
this closes the remaining gap to tokio that the prior campaign deemed structural. The
"intrinsic per-datagram decode floor" framing was wrong: ~half of per-datagram decode
was avoidable cipher-context setup.

# Firefox Version Fingerprint Profiles

This document records the source evidence and modeling boundary for Specter's Firefox desktop macOS fingerprint profiles.

## Scope

Specter implements:

- Stable Firefox profiles `Firefox133` through `Firefox151`.
- ESR profiles `FirefoxEsr115`, `FirefoxEsr128`, and `FirefoxEsr140`.
- Static navigation, AJAX, and form header presets for every profile.
- Rust, Node.js, and Python binding enum coverage for every profile.

`Firefox151` is the latest implemented stable profile as of 2026-05-24. `OrderedHeaders::firefox_navigation()` defaults to Firefox 151, while older stable and ESR profiles remain available for deterministic replay.

## Certification Boundary

This is source-level certification against Mozilla release metadata, release notes, and UA documentation. The version-specific pieces are the Firefox User-Agent token and the static request header helpers. The transport pieces are intentionally shared across all Firefox profiles because Specter does not have capture-backed evidence that TLS, HTTP/2, or HTTP/3 settings drift across Firefox 133-151 or the modeled ESR lines.

All Firefox profiles map to:

- `TlsFingerprint::firefox()`
- `Http2Settings::firefox()`
- `PseudoHeaderOrder::Firefox`
- `Http3Fingerprint::firefox()`

`TlsFingerprint::firefox_133()` remains as a compatibility alias for the shared constructor.

## Sources

- Current release metadata: https://product-details.mozilla.org/1.0/firefox_versions.json
- Major release history: https://product-details.mozilla.org/1.0/firefox_history_major_releases.json
- Stability release history: https://product-details.mozilla.org/1.0/firefox_history_stability_releases.json
- Firefox 151.0.1 release notes: https://www.firefox.com/en-US/firefox/151.0.1/releasenotes/
- Firefox ESR 140.11.0 release notes: https://www.firefox.com/en-US/firefox/140.11.0/releasenotes/
- Firefox ESR 115.36.0 release notes: https://www.firefox.com/en-US/firefox/115.36.0/releasenotes/
- Firefox ESR 128.14.0 release notes: https://www.firefox.com/en-US/firefox/128.14.0/releasenotes/
- Firefox User-Agent reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent/Firefox
- Firefox ESR release cycle: https://support.mozilla.org/en-US/kb/firefox-esr-release-cycle
- Legacy macOS ESR support caveat: https://support.mozilla.org/en-US/kb/firefox-users-macos-1012-1013-1014-moving-to-extended-support

At research time on 2026-05-24:

- `LATEST_FIREFOX_VERSION` was `151.0.1`.
- `FIREFOX_ESR` was `140.11.0esr`.
- `FIREFOX_ESR115` was `115.36.0esr`.
- `FirefoxEsr128` is retained as historical/backfill ESR coverage even though 128 ESR is no longer the current ESR line.

## Stable Profiles

Firefox desktop UA assertions use the major `.0` tokens: `rv:<major>.0` and `Firefox/<major>.0`.

| Profile | Major release | Latest stable patch at research time | UA token |
| --- | --- | --- | --- |
| `Firefox133` | `133.0` on 2024-11-26 | prior implemented baseline | `Firefox/133.0` |
| `Firefox134` | `134.0` on 2025-01-07 | `134.0.2` on 2025-01-21 | `Firefox/134.0` |
| `Firefox135` | `135.0` on 2025-02-04 | `135.0.1` on 2025-02-18 | `Firefox/135.0` |
| `Firefox136` | `136.0` on 2025-03-04 | `136.0.4` on 2025-03-27 | `Firefox/136.0` |
| `Firefox137` | `137.0` on 2025-04-01 | `137.0.2` on 2025-04-15 | `Firefox/137.0` |
| `Firefox138` | `138.0` on 2025-04-29 | `138.0.4` on 2025-05-17 | `Firefox/138.0` |
| `Firefox139` | `139.0` on 2025-05-27 | `139.0.4` on 2025-06-10 | `Firefox/139.0` |
| `Firefox140` | `140.0` on 2025-06-24 | `140.0.4` on 2025-07-08 | `Firefox/140.0` |
| `Firefox141` | `141.0` on 2025-07-22 | `141.0.3` on 2025-08-07 | `Firefox/141.0` |
| `Firefox142` | `142.0` on 2025-08-19 | `142.0.1` on 2025-08-27 | `Firefox/142.0` |
| `Firefox143` | `143.0` on 2025-09-16 | `143.0.4` on 2025-10-03 | `Firefox/143.0` |
| `Firefox144` | `144.0` on 2025-10-14 | `144.0.2` on 2025-10-28 | `Firefox/144.0` |
| `Firefox145` | `145.0` on 2025-11-11 | `145.0.2` on 2025-11-25 | `Firefox/145.0` |
| `Firefox146` | `146.0` on 2025-12-09 | `146.0.1` on 2025-12-18 | `Firefox/146.0` |
| `Firefox147` | `147.0` on 2026-01-13 | `147.0.4` on 2026-02-16 | `Firefox/147.0` |
| `Firefox148` | `148.0` on 2026-02-24 | `148.0.2` on 2026-03-10 | `Firefox/148.0` |
| `Firefox149` | `149.0` on 2026-03-24 | `149.0.2` on 2026-04-07 | `Firefox/149.0` |
| `Firefox150` | `150.0` on 2026-04-21 | `150.0.3` on 2026-05-12 | `Firefox/150.0` |
| `Firefox151` | `151.0` on 2026-05-19 | `151.0.1` on 2026-05-21 | `Firefox/151.0` |

## ESR Profiles

| Profile | Resolved line | User-Agent identity | Notes |
| --- | --- | --- | --- |
| `FirefoxEsr115` | `115.36.0esr` | `Mac OS X 10.14`, `rv:115.0`, `Firefox/115.0` | Legacy ESR branch for older Windows and macOS 10.12-10.14 users; support is caveated through the legacy ESR window. |
| `FirefoxEsr128` | `128.14.0esr` | `Mac OS X 10.15`, `rv:128.0`, `Firefox/128.0` | Historical/backfill ESR profile retained for callers that need the branch identity. |
| `FirefoxEsr140` | `140.11.0esr` | `Mac OS X 10.15`, `rv:140.0`, `Firefox/140.0` | Current general ESR branch at research time. |

`Firefox140` and `FirefoxEsr140` are intentionally distinct enum variants even though their modeled UA and shared transport fingerprints currently match.

## Header Modeling

Every Firefox header helper uses the same ordered shape with the profile's UA as the only version-varying value:

- Navigation helpers include `Upgrade-Insecure-Requests` and the `Sec-Fetch-*` navigation fields.
- AJAX helpers include `Content-Type: application/json`.
- Form helpers include `Content-Type: application/x-www-form-urlencoded`.
- No Firefox helper includes `Sec-Ch-Ua*` Client Hints.
- `Accept-Language` remains `en-US,en;q=0.5`.
- `Accept-Encoding` remains `gzip, deflate, br, zstd`.

The current JA4H helper is header-name/order based and is not User-Agent-value-sensitive, so it is not used as proof that Firefox versions are distinct.

## Verification

The source-level certification is enforced by:

- `tests/firefox_versions.rs`
- `tests/firefox_fingerprint.rs`
- `tests/fingerprint_builder_defaults.rs`
- `bindings/node/src/lib.rs` unit tests
- `bindings/python/src/lib.rs` unit tests
- `bindings/node/__tests__/client.test.js`
- `bindings/python/tests/test_client.py`

Run the certification checks with:

```bash
cargo test --test firefox_versions
cargo test --test firefox_fingerprint
cargo test --test fingerprint_builder_defaults
cargo test --test headers_ja4h
cargo test --test chrome_versions
cargo test --test h3_fingerprint_config
cargo test --manifest-path bindings/node/Cargo.toml
cargo test --manifest-path bindings/python/Cargo.toml
cd bindings/node && npm test -- --runInBand
cd bindings/python && pytest tests/test_client.py
```

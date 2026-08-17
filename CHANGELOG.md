# Changelog

All notable changes to `tpdu` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.1] - 2026-08-17

Dependency and test-quality release. No API change, and no change to the bytes
this crate puts on the wire — the GSM-7 output is byte-for-byte identical to
1.0.0, verified against an independent dissector rather than against ourselves.

### Changed

- `gsm7` 0.3.0 -> 0.4.1 (the exact pin moves with it). A major bump of a
  **shipped** dependency, so it was reviewed rather than waved through: the whole
  upstream diff is a `bitstream-io` API migration (`read(7)` ->
  `read::<7, u8>()`, `write(bits, v)` -> `write::<BITS, I>(v)` with the old
  runtime-width form renamed `write_var`) plus a new `Gsm7Reader::new_with_bit_offset`.
  That signature change is what forced upstream's major; this crate only calls
  `write_str` and `into_writer`, neither of which moved.
  - The parts that decide on-wire bytes are unchanged, checked programmatically:
    the 128-entry `GSM7_CHARSET` is identical, the escape table is identical in
    both directions, and the `remainder == 7 -> pad with CR` rule of TS 23.038
    §6.1.2.3.1 is untouched.
  - `pack_gsm7` output is identical on 0.3.0 and 0.4.1 across all seven vectors
    now in `tests/gsm7_kat.rs`.
  - Brings `no_std_io2` into the dependency tree transitively (Apache-2.0 OR MIT).
    `cargo deny check` is clean on advisories, bans, licenses and sources.
- `pyo3` 0.29.0 -> 0.29.2 (patch; the `0.29` pin is unchanged).
- `criterion` 0.5.1 -> 0.8.2 (dev-only). This retires the RUSTSEC-2026-0204
  crossbeam-epoch exposure at its source instead of patching the lockfile again,
  which is what 1.0.0 had to do.

### Added

- `tests/gsm7_kat.rs` — GSM-7 known-answer vectors as **literals**, so nothing in
  this crate votes on whether they are right. Every other test here builds its
  expectation from our own public API, i.e. a round trip, which a change moving
  the packer and unpacker together passes while producing garbage on the wire.
  The vectors were validated by wrapping `pack_gsm7` output in RP-DATA inside a
  SIP MESSAGE with `application/vnd.3gpp.sms` and dissecting with `tshark` 4.6.4,
  which read all seven back as the intended text with no `[Malformed]` or
  `[Unknown]` field and independently confirmed TP-DCS and TP-UDL. Coverage spans
  the base alphabet, the national block, Greek, every escape character at two
  septets, and the 7-septet CR-pad boundary.
- `examples/gsm7_kat_emit.rs` — re-derives those vectors, so they can be
  rechecked against a different or newer dissector.

## [1.0.0] - 2026-07-02

Initial public release — a unified Rust crate (crates.io) and Rust-backed Python
wheel (PyPI) built from one source tree.

### Added

- **Codec** for 3GPP TS 23.040 / 23.038 / 24.011:
  - Decode RP-DATA (MS→Network) and SMS-SUBMIT TPDUs (`parse_rp_data`,
    `decode_sms_submit_tpdu`).
  - Encode SMS-DELIVER, RP-DATA (Network→MS), RP-ACK and SMS-SUBMIT-REPORT.
  - GSM 7-bit septet pack/unpack (`pack_gsm7` / `unpack_gsm7`), UCS-2 and
    User-Data-Header handling, BCD and GSM-7 alphanumeric addresses.
- **Fluent builders** on both surfaces for every constructable type, reached via
  `Type::builder(..)` (Rust) / `Type.builder(..)` (Python) — e.g.
  `SmsDeliver::builder(oa)…build()`. The `gsm7_text` / `ucs2_text` helpers pack
  the body and derive TP-UDL for you; data coding stays explicit (`.dcs(..)`).
  The public-field structs (Rust) and kwargs constructors (Python) remain.
- **Python bindings** (`import tpdu`) via PyO3, mirroring the Rust API, declared
  **free-threaded safe** (`gil_used = false`, PEP 703).
- `tpdu::Error` error type (implements `std::error::Error`).
- Criterion benches, a counting-allocator leak check, and a synthetic test
  vector suite (no captured traffic).

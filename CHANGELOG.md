# Changelog

All notable changes to `tpdu` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

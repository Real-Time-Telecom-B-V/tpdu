# Changelog

All notable changes to `tpdu` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] - 2026-10-09

Wire-correctness release. Several fields were read from, or written to, the
wrong place; each entry below says what was on the wire before. Two of the fixes
could not be made without changing a public type, hence the major version (see
*Changed*). Every fix and every new PDU is covered three ways: a byte vector
derived by hand from the specification, Wireshark reading back the bytes this
crate emits (`tests/support`, skipped when `tshark` is not installed), and a
decode of bytes this crate did not produce.

### Fixed

- **SMS-SUBMIT first octet** (TS 23.040 §9.2.3.3, §9.2.3.25). TP-VPF was taken
  as `first_octet >> 4`, which is TP-RP, TP-UDHI, TP-SRR and only the high bit
  of TP-VPF, and TP-RD as `first_octet >> 2 == 1`. TP-VPF is bits 4 and 3 and
  TP-RD is bit 2. As a result:
  - `21 ..` (TP-SRR, no validity period) failed to decode: TP-UDL was consumed
    as a validity period.
  - `41 ..` (TP-UDHI, no validity period) lost its text: the octet after TP-DCS
    was skipped and the header length was read as TP-UDL.
  - `19 ..` (absolute) had one of its seven TP-VP octets read and `09 ..`
    (enhanced) none, so everything after TP-DCS was shifted.
  - TP-RD read as set only for first octets `04`-`07`.

  Decoding was right only for a relative validity period, or for none with
  TP-RP, TP-UDHI and TP-SRR all clear.
- **GSM 7-bit text behind a user-data header** (TS 23.040 §9.2.3.24,
  §9.2.3.16). On decode the header was stripped from `tp_user_data` while
  `tp_udhi` stayed set, and the text was found by dropping `UDHL + 2`
  characters from an unpacking that started at bit 0, which is one septet short
  from a header length of 7 upwards. There was no way to encode one at all:
  packing header and text together as septets puts the header on the wire as
  text. `pack_gsm7_with_header` / `unpack_gsm7_with_header` now keep the header
  in octets, add the fill bits to the next septet boundary and count the header
  septets in TP-UDL, and the decoder keeps the header in `tp_user_data` as it
  already did for 8-bit and UCS-2 data.
- **7-bit data codings other than `0x00`** (TS 23.038 §4). Only TP-DCS `0x00`
  was treated as 7-bit, so a message class (`0x10`-`0x13`, `0xF0`-`0xF3`), the
  automatic-deletion group, a message-waiting indication or a reserved coding
  had its TP-UDL taken as an octet count: the SMS-SUBMIT failed to decode or
  came back as packed septets. All coding groups are now classified
  (`user_data_coding`).
- **7-bit text outside Latin-1.** Decoding an SMS-SUBMIT that contained a Greek
  capital or the euro sign failed outright, and accented letters came back as
  single Latin-1 bytes. `tp_user_data` is UTF-8 for 7-bit text.
- **Spare bits of packed 7-bit data** (TS 23.038 §6.1.2.1.1). A message of 1,
  9, 17, ... septets was emitted with bit 7 of its last octet set (`"a"` packed
  to `E1`, now `61`). The specification fills with zeros; the CR fill of
  §6.1.2.3.1 is a USSD rule. `unpack_gsm7` reads exactly the septets TP-UDL
  counts, so a peer's CR or zero fill after a 7-septet message is no longer a
  trailing character, and an escape followed by a code outside the extension
  table falls back to the default alphabet instead of failing the message.
- **Alphanumeric address length** (TS 23.040 §9.1.2.5). The length octet was
  twice the octet count, not the number of useful semi-octets: a 7-character
  sender went out with length 14 instead of 13, which a receiver reads as eight
  characters. Alphanumeric addresses were also not decoded (the septets were
  read as BCD digits).
- **Address digits** (TS 23.040 §9.1.2.3). `*` and `#` could not be encoded and
  decoded as `A` and `B`; they and `a`, `b`, `c` now map to semi-octets
  1010-1110. A type-of-number above 7 or numbering plan above 15 spilled into
  the neighbouring bits and is now an error, as is an address longer than the
  10 value octets the field allows.
- **A TP address with no digits.** Its type-of-address octet, which is always
  present, was not consumed, shifting the rest of the SMS-SUBMIT by one octet.
- **Time stamps** (TS 23.040 §9.2.3.11). A TP-SCTS string of odd length
  panicked, and one that was empty or short produced a TPDU with a truncated
  time stamp. Anything but 14 semi-octet digits is now an error.
- **RP-ACK from `RpAck::builder`** went out with an RP-User-Data length of 0 in
  front of a 9-octet SMS-SUBMIT-REPORT. The builder takes the length from the
  report and `encode()` refuses any other.
- **Lengths that did not match the data.** A TP-UDL that contradicts the
  TP-User-Data (for instance the packed octet count where septets are wanted),
  a TP-Parameter-Indicator that announces parameters that are not there, an
  RP-Message-Type for the other direction, and a TPDU or text too long for its
  one-octet length were all emitted as given, the last one with the length
  wrapped. `encode()` now returns an error for each.
- `parse_rp_data` reads the TPDU from the octets RP-User-Data says it has, and
  it and `decode_sms_submit_tpdu` turn down an RP message or TPDU of another
  type instead of reading it as an SMS-SUBMIT.
- README: the clause numbers given for SMS-SUBMIT-REPORT, RP-DATA MS→Network
  and RP-ACK were wrong.

### Added

- **RP-ERROR** in both directions (TS 24.011 §7.3.4): `RpErrorNetworkToMs` and
  `RpErrorMsToNetwork`, with RP-Cause, the optional diagnostic and the optional
  RP-User-Data.
- **SMS-STATUS-REPORT** (TS 23.040 §9.2.2.3): `SmsStatusReport`, and
  `RpDataNetworkToMsStatusReport` to carry it in RP-DATA.
- **SMS-DELIVER-REPORT** (TS 23.040 §9.2.2.1a): `SmsDeliverReport`, in both its
  RP-ACK and RP-ERROR layouts.
- **RP-SMMA** (TS 24.011 §7.3.2): `RpSmma`.
- Encoders for the mobile-originated side: `SmsSubmit::encode` and
  `RpDataMsToNetwork::encode`. Decoders for the mobile-terminated side:
  `SmsDeliver::decode` and `parse_rp_data_network_to_ms`, which returns an
  SMS-DELIVER or an SMS-STATUS-REPORT by TP-MTI.
- `pack_gsm7_with_header`, `unpack_gsm7_with_header`, `user_data_coding` /
  `UserDataCoding`, `timestamp_digits` (builds a time stamp from its parts, a
  negative time zone included), and on the builders `gsm7_text_with_header`,
  `validity_period_absolute` and `validity_period_enhanced`.
- The optional parameters of a report (TP-PID, TP-DCS, TP-UDL, TP-UD after
  TP-PI, §9.2.3.27).
- `PartialEq` / `Eq` on all PDU types.
- Python: all of the above in the same style, `parse_rp_error`,
  `parse_rp_smma`, `parse_sms_status_report`, `parse_rp_data_network_to_ms`,
  `SmsSubmit.encode()` and `SmsSubmit.tp_user_data_header`, and getters on
  `SmsDeliver`, `SmsSubmitReport` and `RpDataNetworkToMs`.

### Changed

These are the breaking changes.

- `SmsSubmit::tp_vpf` is the two-bit field of §9.2.3.3: `0` none, `2`
  relative, `3` absolute, `1` enhanced (`VALIDITY_PERIOD_FORMAT_*`). It used to
  read `1` or `3` for a relative validity period.
- `SmsSubmit::tp_validity_period` is `Option<ValidityPeriod>` (`Relative(u8)`,
  `Absolute(String)`, `Enhanced([u8; 7])`) instead of `Option<u8>`, which could
  not hold the two seven-octet formats. In Python it is an `int`, a `str` or
  `bytes` accordingly; the relative case is unchanged there.
- `SmsSubmit::tp_user_data` for 7-bit text is UTF-8 and, when TP-UDHI is set,
  starts with the header octets. `tp_user_data_raw` remains the field as on the
  wire and is what `SmsSubmit::encode` emits; the builder's text helpers fill
  both.
- `SmsSubmitReport` has new fields: `tp_failure_cause` and the optional
  parameters.
- A TP address of zero digits decodes to an address with an empty string, not
  `None`.
- `SMSAddress::encode` rejects digits other than `0`-`9`, `*`, `#`, `a`, `b`,
  `c` (it used to pass hexadecimal letters through), and an alphanumeric
  address in the RP form.
- `unpack_gsm7` fails when the buffer is too short for the septet count.
- Python: `SmsDeliver(...)`, its builder and `build_sms_deliver_tpdu` raise
  when the data coding is 7-bit and `user_data_length` is not given. It
  defaulted to the packed octet count, which is wrong from eight septets on.
- Python: `SmsSubmit.text()` no longer includes the header.

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

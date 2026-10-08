# tpdu

[![crates.io](https://img.shields.io/crates/v/tpdu.svg)](https://crates.io/crates/tpdu)
[![PyPI](https://img.shields.io/pypi/v/tpdu.svg)](https://pypi.org/project/tpdu/)
[![CI](https://github.com/Real-Time-Telecom-B-V/tpdu/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/tpdu/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust **SMS Transfer-layer PDU codec** implementing 3GPP **TS 23.040**
(SMS TPDU), **TS 23.038** (data coding / GSM 7-bit default alphabet) and
**TS 24.011** (RP layer). One source tree, one version, shipped two ways: a
Rust crate (`cargo add tpdu`) and a Rust-backed Python wheel (`pip install
tpdu`).

It is the bytes-in/bytes-out layer underneath SMS-over-IMS, SMPP and SS7
MO/MT-Forward-SM paths — no async, no I/O, no shared state.

## What it is

`tpdu` encodes and decodes the protocol data units that carry SMS between
handsets, IMS, and signalling cores:

- **RP-DATA** (MS→Network and Network→MS), **RP-ACK**, **RP-ERROR** and
  **RP-SMMA** — the relay layer used on the Gm interface (SIP MESSAGE body) and
  inside MAP / Diameter MO/MT-Forward-SM.
- **SMS-SUBMIT**, **SMS-DELIVER** and **SMS-STATUS-REPORT** TPDUs, and the
  **SMS-SUBMIT-REPORT** / **SMS-DELIVER-REPORT** that acknowledge them.
- **GSM 7-bit** default-alphabet septet packing (TS 23.038 §6.1.2.1.1) and
  **UCS-2** user data; the **User-Data-Header** (concatenation and other IEs),
  including the fill bits a header needs in front of 7-bit text.
- **BCD** and **GSM-7 alphanumeric** SMS addresses with TON/NPI.

Pure Rust, no async, no I/O — just bytes in, bytes out. The same codec is
exposed to Python (`import tpdu`) via PyO3.

## Install

### Rust

```sh
cargo add tpdu
```

### Python

```sh
pip install tpdu
```

The Python wheel bundles the compiled Rust extension — no Rust toolchain
required to install.

## Quick start — Rust

Parse an inbound MS→Network RP-DATA (e.g. the body of a UE-originated SIP
MESSAGE on Gm), and pack/unpack the GSM 7-bit user data:

```rust
use tpdu::{parse_rp_data, pack_gsm7, unpack_gsm7, SMSAddress};

// Build a synthetic RP-DATA carrying an SMS-SUBMIT for demonstration.
let dest = SMSAddress { ton: 1, npi: 1, address: "15550100".into() };
let (ud, septets) = pack_gsm7("hello tpdu")?;        // GSM-7 septet packing

let mut tpdu = vec![0x01, 0x01];                     // first octet (mti=1), TP-MR
tpdu.extend(dest.encode(false)?);                    // TP-DA (BCD)
tpdu.extend([0x00, 0x00, septets as u8]);            // TP-PID, TP-DCS=0, TP-UDL
tpdu.extend(ud);
let mut rp = vec![0x00, 0x01, 0x00, 0x00];           // RP-type=DATA, RP-MR, no RP-OA/DA
rp.push(tpdu.len() as u8);
rp.extend(tpdu);

let parsed = parse_rp_data(&rp)?;
assert_eq!(parsed.sms_submit.tp_user_data, b"hello tpdu");
assert_eq!(
    parsed.sms_submit.tp_destination_address,
    Some(SMSAddress { ton: 1, npi: 1, address: "15550100".into() }),
);
# Ok::<(), tpdu::Error>(())
```

Build an MT SMS-DELIVER wrapped in RP-DATA Network→MS and encode it to wire
bytes (drop into a SIP MESSAGE body with `Content-Type:
application/vnd.3gpp.sms`). Every constructable type has a fluent
`builder(..)`; the `gsm7_text` helper packs the body and derives TP-UDL, while
data coding stays explicit via `.dcs(..)`:

```rust
use tpdu::{RpDataNetworkToMs, SMSAddress, SmsDeliver};

let oa = SMSAddress::builder().ton(1).npi(1).address("15550199").build();
let deliver = SmsDeliver::builder(oa.clone())
    .mms(true)
    .dcs(0)                                          // GSM 7-bit
    .service_centre_timestamp("25010112000000")
    .gsm7_text("hello tpdu")                         // packs + sets TP-UDL
    .build()?;
let mt = RpDataNetworkToMs::builder(deliver)
    .originator_address(oa)
    .build();
let wire: Vec<u8> = mt.encode()?;
# assert_eq!(wire[0], 0x01);
# Ok::<(), tpdu::Error>(())
```

The public-field structs are still there when you want full control — the
builder is an additive convenience, not a replacement.

A part of a concatenated message in the 7-bit alphabet needs its header kept in
octets and the text packed behind fill bits (TS 23.040 §9.2.3.24).
`gsm7_text_with_header` does that and counts the header in TP-UDL:

```rust
use tpdu::{SMSAddress, SmsDeliver, UserDataHeader};

let oa = SMSAddress::builder().ton(1).npi(1).address("15550199").build();
// Concatenation: reference 0x2A, 2 parts, this is part 1.
let header = UserDataHeader::builder().value([0x00, 0x03, 0x2a, 0x02, 0x01]).build();
let part = SmsDeliver::builder(oa)
    .udhi(true)
    .dcs(0)
    .service_centre_timestamp("25010112000000")
    .gsm7_text_with_header(&header, "hello")
    .build()?;
assert_eq!(part.tp_user_data_length, 12);             // 7 header septets + 5
# Ok::<(), tpdu::Error>(())
```

Turning a mobile-originated message down, and telling the sender later what
became of one that was accepted:

```rust
use tpdu::{RpDataNetworkToMsStatusReport, RpErrorNetworkToMs, SMSAddress,
           SmsStatusReport, SmsSubmitReport};

// RP-ERROR, cause 21 (short message transfer rejected), with the
// SMS-SUBMIT-REPORT that says why: TP-FCS 0xC3, invalid SME address.
let report = SmsSubmitReport::builder()
    .failure_cause(0xc3)
    .service_centre_timestamp("25010112000000")
    .build();
let error = RpErrorNetworkToMs::builder(21)
    .message_reference(7)                            // RP-MR of the RP-DATA
    .sms_submit_report(report)
    .build()
    .encode()?;

// SMS-STATUS-REPORT for the SMS-SUBMIT that had TP-MR 42.
let recipient = SMSAddress::builder().ton(1).npi(1).address("15550100").build();
let status = SmsStatusReport::builder(recipient)
    .mr(42)
    .mms(true)
    .service_centre_timestamp("25010112000000")
    .discharge_time("25010112000500")
    .status(0x00)                                    // received by the SME
    .build();
let wire = RpDataNetworkToMsStatusReport::builder(status).build().encode()?;
# Ok::<(), tpdu::Error>(())
```

## Quick start — Python

The Python API is ergonomic and slightly higher-level than the Rust one
(keyword-only kwargs, sensible MT defaults, an auto-generated SCTS):

```python
import tpdu

# Pack GSM 7-bit and get back (packed_bytes, septet_count).
packed, septets = tpdu.pack_gsm7("hello tpdu")
assert tpdu.unpack_gsm7(packed, septets) == "hello tpdu"

# Parse an inbound MS→Network RP-DATA body (e.g. from a SIP MESSAGE on Gm).
rp = tpdu.parse_rp_data(rp_data_bytes)
print(rp.sms_submit.text())                     # decoded str for DCS 0 / 8
print(rp.sms_submit.tp_destination_address)     # Address(ton=1, npi=1, address='15550100')

# Build an MT SMS-DELIVER and encode it to wire bytes. Each class also has a
# fluent .builder(..); gsm7_text packs the body and sets TP-UDL for you.
oa = tpdu.Address.builder().ton(1).npi(1).address("15550199").build()
deliver = tpdu.SmsDeliver.builder(oa).dcs(0).gsm7_text("hello tpdu").build()
mt = tpdu.RpDataNetworkToMs.builder(deliver).build()
body = mt.encode()                              # -> bytes for the SIP MESSAGE body

# The kwargs constructors still work if you prefer them:
#   deliver = tpdu.SmsDeliver(oa, packed, tp_dcs=0, user_data_length=septets)
#   mt = tpdu.RpDataNetworkToMs(deliver, rp_message_reference=0)
```

Convenience helpers cover the common gateway paths:

```python
# Parse a bare SMS-SUBMIT TPDU (no RP wrapper) — e.g. an SMPP submit_sm body.
submit = tpdu.parse_sms_submit(tpdu_bytes)
msisdn = tpdu.destination_from_tpdu(tpdu_bytes)  # bare TP-DA digits

# Build an SMS-DELIVER straight from deliver_sm-shaped fields (UTC-now SCTS).
deliver_tpdu = tpdu.build_sms_deliver_tpdu(
    "15550199", source_addr_ton=1, source_addr_npi=1,
    short_message=packed, data_coding=0, user_data_length=septets,
)
```

> **Note on TP-UDL:** for a 7-bit data coding (DCS 0, and the codings that add
> a message class such as 0x10 or 0xF1) the User-Data-Length counts *septets*,
> not packed bytes — pass the `septets` returned by `pack_gsm7`. It cannot be
> worked out from the packed bytes, so the Python constructors raise when it is
> missing. For 8-bit and UCS-2 it counts octets and defaults to
> `len(user_data)`. `encode()` refuses a length that contradicts the user data.

The rest of the relay layer follows the same pattern:

```python
# RP-ERROR back to the UE, with the SMS-SUBMIT-REPORT that carries TP-FCS.
report = tpdu.SmsSubmitReport(tp_failure_cause=0xC3)
body = tpdu.RpErrorNetworkToMs(21, rp_message_reference=7, sms_submit_report=report).encode()

# What the UE answers to an MT message: RpErrorMsToNetwork or RpErrorNetworkToMs.
error = tpdu.parse_rp_error(rp_error_bytes)
print(error.rp_cause, error.rp_diagnostic)

# A status report for the SMS-SUBMIT that had TP-MR 42.
status = tpdu.SmsStatusReport(tpdu.Address("15550100"), tp_mr=42, tp_status=0x00)
body = tpdu.RpDataNetworkToMsStatusReport(status).encode()

# A part of a concatenated message in the 7-bit alphabet: header, fill bits, text.
user_data, septets = tpdu.pack_gsm7_with_header(bytes([5, 0, 3, 0x2A, 2, 1]), "hello")
```

## Standards coverage

Derived from the implementation — not aspirational.

| PDU / element | Direction | Codec | Notes |
|---|---|---|---|
| **SMS-SUBMIT** (TS 23.040 §9.2.2.2) | MO | encode / decode | TP-MTI/RP/UDHI/SRR/RD flags, TP-VPF with all four TP-VP formats (none, relative, absolute, enhanced), TP-MR, TP-DA, TP-PID, TP-DCS, TP-UD |
| **SMS-DELIVER** (TS 23.040 §9.2.2.1) | MT | encode / decode | TP-RP/UDHI/SRI/LP/MMS flags, TP-OA, TP-PID, TP-DCS, TP-SCTS, TP-UD |
| **SMS-STATUS-REPORT** (TS 23.040 §9.2.2.3) | MT | encode / decode | TP-UDHI/SRQ/LP/MMS flags, TP-MR, TP-RA, TP-SCTS, TP-DT, TP-ST, optional TP-PI and what it announces |
| **SMS-SUBMIT-REPORT** (TS 23.040 §9.2.2.2a) | MT | encode / decode | both layouts: for RP-ACK, and for RP-ERROR with TP-FCS; TP-PI, TP-SCTS, optional TP-PID / TP-DCS / TP-UD |
| **SMS-DELIVER-REPORT** (TS 23.040 §9.2.2.1a) | MO | encode / decode | both layouts: for RP-ACK, and for RP-ERROR with TP-FCS; TP-PI, optional TP-PID / TP-DCS / TP-UD |
| **RP-DATA** MS→Network (TS 24.011 §7.3.1.2) | MO | encode / decode | RP-MR, RP-OA / RP-DA, wrapped SMS-SUBMIT |
| **RP-DATA** Network→MS (TS 24.011 §7.3.1.1) | MT | encode / decode | RP-MR, RP-OA / RP-DA, wrapped SMS-DELIVER or SMS-STATUS-REPORT |
| **RP-ACK** Network→MS (TS 24.011 §7.3.3) | MT | encode | echoes inbound RP-MR; RP-User-Data IE carries SMS-SUBMIT-REPORT |
| **RP-ERROR** (TS 24.011 §7.3.4) | both | encode / decode | RP-Cause with optional diagnostic; RP-User-Data IE carries SMS-SUBMIT-REPORT (Network→MS) or SMS-DELIVER-REPORT (MS→Network) |
| **RP-SMMA** (TS 24.011 §7.3.2) | MO | encode / decode | RP-MR |
| **GSM 7-bit** (TS 23.038 §6.1.2.1.1, §6.2.1) | — | pack / unpack | default alphabet and its extension table (`^{}\[~]|€`, FF: 2 septets each); zero fill; with or without a user-data header |
| **TP-DCS** (TS 23.038 §4) | — | classify | every coding group: 7-bit, 8-bit, UCS-2 and compressed, message classes and message-waiting groups included |
| **UCS-2** | — | pass-through | user data carried verbatim; Python `.text()` decodes UTF-16BE |
| **User-Data-Header** (TS 23.040 §9.2.3.24) | — | encode / decode | UDHL + IE bytes (concatenation, etc.); fill bits to the septet boundary for 7-bit text |
| **SMS addresses** (TS 23.040 §9.1.2.5) | — | encode / decode | BCD digits incl. `*`, `#`, `a`, `b`, `c`, and GSM-7 alphanumeric (TON=5); TON/NPI preserved |
| **Time stamps** (TS 23.040 §9.2.3.11) | — | encode / decode | TP-SCTS, TP-DT and absolute TP-VP as 14 semi-octet digits; `timestamp_digits` builds them, negative time zones included |

Not covered: SMS-COMMAND, decoding an RP-ACK (either direction), the national
language shift tables of TS 23.038 §6.2.1.2 (the header elements pass through
as octets, the text is read with the default alphabet), and compressed user
data (TS 23.042), which is carried as octets and not unpacked.

Scope is deliberately the transfer and relay layers (TP / RP): there is no CP
layer, no network transport, and no async — those belong to the higher layers
that carry these PDUs.

## Public API at a glance

**Rust** — types `SMSAddress`, `UserDataHeader`, `ValidityPeriod`,
`UserDataCoding`, `SmsSubmit`, `SmsDeliver`, `SmsStatusReport`,
`SmsSubmitReport`, `SmsDeliverReport`, `RpDataMsToNetwork`,
`RpDataNetworkToMs`, `RpDataNetworkToMsStatusReport`,
`RpDataNetworkToMsMessage`, `RpAck`, `RpErrorNetworkToMs`,
`RpErrorMsToNetwork`, `RpSmma`, `Error`; functions `parse_rp_data`,
`parse_rp_data_network_to_ms`, `decode_sms_submit_tpdu`, `pack_gsm7`,
`unpack_gsm7`, `pack_gsm7_with_header`, `unpack_gsm7_with_header`,
`user_data_coding`, `timestamp_digits`. Each type exposes `.encode()`, the ones
that arrive from a peer a `decode(..)` (or one of the `parse_*` functions), and
every constructable type a fluent `::builder(..)`.

**Python** — classes `Address`, `UserDataHeader`, `SmsSubmit`, `SmsDeliver`,
`SmsStatusReport`, `SmsSubmitReport`, `SmsDeliverReport`, `RpData`,
`RpDataNetworkToMs`, `RpDataNetworkToMsStatusReport`, `RpAckNetworkToMs`,
`RpErrorNetworkToMs`, `RpErrorMsToNetwork`, `RpSmma`; functions
`parse_rp_data`, `parse_rp_data_network_to_ms`, `parse_sms_submit`,
`parse_sms_status_report`, `parse_rp_error`, `parse_rp_smma`,
`destination_from_tpdu`, `build_sms_deliver_tpdu`, `pack_gsm7`, `unpack_gsm7`,
`pack_gsm7_with_header`, `unpack_gsm7_with_header`, `user_data_coding`,
`timestamp_digits`. Constructable classes also expose a fluent `.builder(..)`.
The two surfaces are kept in lockstep but are not byte-identical APIs — the
Python side adds kwargs, defaults and `.text()` decoding.

## Cargo feature flags

| Feature | Effect |
|---|---|
| *(default)* | Pure Rust codec, no PyO3, no chrono. |
| `python` | Builds the PyO3 bindings (`tpdu::register`) + chrono for SCTS. Does **not** force `pyo3/extension-module`, so a host application that embeds CPython and links libpython itself can graft the `tpdu` submodule into its own namespace via `register`. |
| `extension-module` | Implies `python` and adds `pyo3/extension-module`. This is what maturin builds the standalone wheel with. |

### Free-threaded / GIL-free

The extension module is declared `#[pymodule(gil_used = false)]`: the codec is
pure and holds no shared mutable state, so importing it does **not** force the
GIL back on under free-threaded CPython (PEP 703). It is safe to call from
multiple Python threads concurrently.

## Building the Python wheel

For local development, [maturin](https://www.maturin.rs/) builds and installs
the extension into the current virtualenv:

```sh
maturin develop --features extension-module
```

Release wheels (manylinux / macOS / Windows, multiple CPython versions) are
built in CI; end users just `pip install tpdu`.

## Performance

`tpdu` is an allocation-light pure codec: no async, no I/O, no locks, no work
beyond walking the bytes. Encode/decode is a straight-line transform, so it runs
at millions of PDUs per second per core.

**Rust codec** (`cargo bench`, criterion, release, single core):

| Operation                          |    Time |  Throughput |
| ---------------------------------- | ------: | ----------: |
| Decode MO RP-DATA (SMS-SUBMIT)     | ~281 ns | ~3.6 M op/s |
| Encode MT RP-DATA (SMS-DELIVER)    | ~903 ns | ~1.1 M op/s |
| GSM-7 pack                         | ~562 ns | ~1.8 M op/s |
| GSM-7 unpack                       | ~297 ns | ~3.4 M op/s |

**Rust vs Python** — same operation, same inputs, same machine (`python
python/bench.py`, 500k iters). Because the work happens in Rust and the PyO3
boundary costs only tens of nanoseconds per call, the Python package runs at
roughly **80–95% of native Rust throughput**:

| Operation         |    Rust | Python 3.13 (GIL) | Python 3.14t (free-threaded) |
| ----------------- | ------: | ----------------: | ---------------------------: |
| GSM-7 pack        | 1.8 M/s |           1.7 M/s |                      1.3 M/s |
| GSM-7 unpack      | 3.4 M/s |           2.9 M/s |                      3.0 M/s |
| Decode MO RP-DATA | 3.6 M/s |           2.8 M/s |                      2.6 M/s |

Indicative numbers from one developer laptop — run `cargo bench` and
`python python/bench.py` on your own hardware. (Rust uses criterion; the Python
figures are a tight call loop, so they also carry the interpreter's per-call
overhead.)

## License

[MIT](LICENSE) © Real Time Telecom B.V.

Developed and maintained by [Real Time Telecom B.V.](https://realtime-telecom.nl)
— carrier-grade telecom infrastructure in Rust.

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

- **RP-DATA** (MS→Network and Network→MS) — the relay-layer wrapper used on the
  Gm interface (SIP MESSAGE body) and inside MAP / Diameter MO/MT-Forward-SM.
- **SMS-SUBMIT**, **SMS-DELIVER** and **SMS-SUBMIT-REPORT** TPDUs.
- **GSM 7-bit** default-alphabet septet packing (TS 23.038 §6.2.1) and **UCS-2**
  user data; the **User-Data-Header** (concatenation and other IEs).
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

> **Note on TP-UDL:** for GSM 7-bit (DCS=0) the User-Data-Length counts
> *septets*, not packed bytes — pass the `septets` returned by `pack_gsm7`. For
> 8-bit and UCS-2 it counts octets and defaults to `len(user_data)`.

## Standards coverage

Derived from the implementation — not aspirational.

| PDU / element | Direction | Codec | Notes |
|---|---|---|---|
| **SMS-SUBMIT** (TS 23.040 §9.2.2.2) | MO | decode | TP-MTI/RP/UDHI/SRR/RD/VPF flags, TP-MR, TP-DA, TP-PID, TP-DCS, optional TP-VP, TP-UD |
| **SMS-DELIVER** (TS 23.040 §9.2.2.1) | MT | encode | TP flags, TP-OA, TP-PID, TP-DCS, TP-SCTS, TP-UD |
| **SMS-SUBMIT-REPORT** (TS 23.040 §9.2.2.1a) | MT | encode | RP-ACK payload carrying TP-SCTS back to the UE |
| **RP-DATA** MS→Network (TS 24.011 §7.3.1.1) | MO | decode | RP-MR, optional RP-OA/RP-DA, wrapped SMS-SUBMIT |
| **RP-DATA** Network→MS (TS 24.011 §7.3.1.1) | MT | encode | RP-MR, optional RP-OA/RP-DA, wrapped SMS-DELIVER |
| **RP-ACK** Network→MS (TS 24.011 §7.3.2.1) | MT | encode | echoes inbound RP-MR; RP-User-Data IE carries SMS-SUBMIT-REPORT |
| **GSM 7-bit** (TS 23.038 §6.2.1) | — | pack / unpack | default alphabet, septet packing; extension chars (`^{}\[~]|€`, FF) count as 2 septets |
| **UCS-2** | — | pass-through | DCS=8 user data carried verbatim; Python `.text()` decodes UTF-16BE |
| **User-Data-Header** | — | encode / decode | UDHL + IE bytes (concatenation, etc.); surfaced when TP-UDHI is set |
| **SMS addresses** | — | encode / decode | BCD digits and GSM-7 alphanumeric (TON=5); TON/NPI preserved |

Scope is deliberately the transfer and relay layers (TP / RP): there is no CP
layer, no network transport, and no async — those belong to the higher layers
that carry these PDUs.

## Public API at a glance

**Rust** — types `SMSAddress`, `UserDataHeader`, `SmsSubmit`, `SmsDeliver`,
`SmsSubmitReport`, `RpDataMsToNetwork`, `RpDataNetworkToMs`, `RpAck`, `Error`;
functions `parse_rp_data`, `decode_sms_submit_tpdu`, `pack_gsm7`,
`unpack_gsm7`. Each encodable type exposes `.encode()`, and every constructable
type a fluent `::builder(..)`.

**Python** — classes `Address`, `UserDataHeader`, `SmsSubmit`, `SmsDeliver`,
`RpData`, `RpDataNetworkToMs`, `SmsSubmitReport`, `RpAckNetworkToMs`; functions
`parse_rp_data`, `parse_sms_submit`, `destination_from_tpdu`,
`build_sms_deliver_tpdu`, `pack_gsm7`, `unpack_gsm7`. Constructable classes also
expose a fluent `.builder(..)`. The two surfaces are kept in lockstep but are
not byte-identical APIs — the Python side adds kwargs, defaults and `.text()`
decoding.

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

//! Codec micro-benchmarks (criterion).
//!
//! Measures the hot paths the IP-SM-GW runs per message: decode an MO RP-DATA /
//! SMS-SUBMIT, encode an MT RP-DATA Network→MS, and GSM 7-bit pack/unpack.
//! `Throughput::Elements(1)` reports operations/sec so the numbers drop straight
//! into the README baseline table.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

use tpdu::{pack_gsm7, parse_rp_data, unpack_gsm7, RpDataNetworkToMs, SMSAddress, SmsDeliver};

/// Build a synthetic MO RP-DATA carrying an SMS-SUBMIT (fictional number,
/// neutral text) — assembled from the public API so no captured data is used.
fn sample_mo() -> Vec<u8> {
    let dest = SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550100".into(),
    };
    let (ud, septets) = pack_gsm7("benchmark").unwrap();
    let mut tpdu = vec![0x01u8, 0x01];
    tpdu.extend(dest.encode(false).unwrap());
    tpdu.push(0); // TP-PID
    tpdu.push(0); // TP-DCS
    tpdu.push(septets as u8);
    tpdu.extend(ud);
    let mut rp = vec![0x00u8, 0x01, 0x00, 0x00]; // type, MR, RP-OA/DA absent
    rp.push(tpdu.len() as u8);
    rp.extend(tpdu);
    rp
}

fn sample_mt() -> RpDataNetworkToMs {
    RpDataNetworkToMs {
        rp_message_type: 0x01,
        rp_message_reference: 0,
        rp_originator_address: Some(SMSAddress {
            ton: 1,
            npi: 1,
            address: "15555550100".to_string(),
        }),
        rp_destination_address: None,
        sms_deliver: SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_mti: 0,
            tp_originating_address: SMSAddress {
                ton: 1,
                npi: 1,
                address: "15555550100".to_string(),
            },
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: "25010112000000".to_string(),
            tp_user_data_length: 4,
            tp_user_data: vec![0xd4, 0xf2, 0x9c, 0x0e],
        },
    }
}

fn bench_codec(c: &mut Criterion) {
    let mo = sample_mo();

    let mut g = c.benchmark_group("rp_data");
    g.throughput(Throughput::Elements(1));

    g.bench_function("decode_mo_submit", |b| {
        b.iter(|| parse_rp_data(black_box(&mo)).unwrap())
    });

    let mt = sample_mt();
    g.bench_function("encode_mt_deliver", |b| {
        b.iter(|| black_box(&mt).encode().unwrap())
    });
    g.finish();

    let text = "Hello world! This is a GSM 7-bit packed message.";
    let (packed, septets) = pack_gsm7(text).unwrap();
    let mut g = c.benchmark_group("gsm7");
    g.throughput(Throughput::Elements(1));
    g.bench_function("pack", |b| b.iter(|| pack_gsm7(black_box(text)).unwrap()));
    g.bench_function("unpack", |b| {
        b.iter(|| unpack_gsm7(black_box(&packed), black_box(septets)).unwrap())
    });
    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);

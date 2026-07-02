//! Integration tests against the public API. Everything is built synthetically
//! from the public encoders — fictional 555-01xx numbers, neutral text, no
//! captured traffic.

use std::io::Cursor;

use tpdu::{
    decode_sms_submit_tpdu, pack_gsm7, parse_rp_data, unpack_gsm7, RpDataNetworkToMs, SMSAddress,
    SmsDeliver,
};

/// Build a bare SMS-SUBMIT TPDU (mti=1, no VP, DCS=0) for `dest`/`text`.
fn submit_tpdu(dest: &SMSAddress, text: &str) -> Vec<u8> {
    let (ud, septets) = pack_gsm7(text).unwrap();
    let mut t = vec![0x01, 0x01]; // first byte (mti=1, vpf=0), TP-MR
    t.extend(dest.encode(false).unwrap());
    t.push(0); // TP-PID
    t.push(0); // TP-DCS (GSM 7-bit)
    t.push(septets as u8); // TP-UDL
    t.extend(ud);
    t
}

/// Wrap a TPDU in RP-DATA MS→Network (no RP addresses).
fn rp_data_mo(tpdu: &[u8]) -> Vec<u8> {
    let mut d = vec![0x00, 0x01, 0x00, 0x00]; // type, MR, RP-OA absent, RP-DA absent
    d.push(tpdu.len() as u8);
    d.extend_from_slice(tpdu);
    d
}

#[test]
fn parse_rp_data_public_api() {
    let dest = SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550100".into(),
    };
    let rp = rp_data_mo(&submit_tpdu(&dest, "hello tpdu"));
    let parsed = parse_rp_data(&rp).unwrap();
    assert_eq!(parsed.sms_submit.tp_user_data, b"hello tpdu");
    assert_eq!(parsed.sms_submit.tp_destination_address, Some(dest));
}

#[test]
fn parse_bare_sms_submit_tpdu() {
    let dest = SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550101".into(),
    };
    let tpdu = submit_tpdu(&dest, "bare");
    let mut cursor = Cursor::new(tpdu.as_slice());
    let submit = decode_sms_submit_tpdu(&mut cursor).unwrap();
    assert_eq!(submit.tp_user_data, b"bare");
    assert_eq!(submit.tp_mti, 1);
}

#[test]
fn truncated_input_errors_not_panics() {
    assert!(parse_rp_data(&[0x00]).is_err());
    assert!(parse_rp_data(&[]).is_err());
}

#[test]
fn gsm7_extension_chars_count_two_septets() {
    // '€' and '{' '}' are GSM-7 extension chars → 2 septets each.
    let (_, septets) = pack_gsm7("€{}").unwrap();
    assert_eq!(septets, 6);
}

#[test]
fn gsm7_roundtrip_varied() {
    for input in [
        "",
        "A",
        "ping",
        "Hello world!",
        "@A€{}",
        "The quick brown fox jumps over the lazy dog 1234567890",
        "Symbols: @ £ $ ¥ è é ù ì ò Ç Ø ø Å å Δ Φ Γ Λ Ω Π Ψ Σ Θ Ξ",
    ] {
        let (bytes, septets) = pack_gsm7(input).unwrap();
        let decoded = unpack_gsm7(&bytes, septets).unwrap();
        assert_eq!(decoded, input, "roundtrip failed for {input:?}");
    }
}

#[test]
fn mt_deliver_encodes() {
    let oa = SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550199".into(),
    };
    let (ud, septets) = pack_gsm7("delivered").unwrap();
    let mt = RpDataNetworkToMs {
        rp_message_type: 0x01,
        rp_message_reference: 0,
        rp_originator_address: Some(oa.clone()),
        rp_destination_address: None,
        sms_deliver: SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_mti: 0x00,
            tp_originating_address: oa,
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
            tp_user_data_length: septets as u8,
            tp_user_data: ud.clone(),
        },
    };
    let encoded = mt.encode().unwrap();
    assert_eq!(encoded[0], 0x01); // RP-DATA n→ms
    assert!(encoded.ends_with(&ud));
}

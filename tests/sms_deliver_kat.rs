//! Known-answer vectors for the SMS-DELIVER first octet.
//!
//! Written out by hand from TS 23.040 §9.2.2.1 and read back by Wireshark (see
//! `support`), so neither direction is checked against the other.
//!
//! First octet of an SMS-DELIVER, bit by bit (TS 23.040):
//!
//! | bit | field   | clause    |
//! |-----|---------|-----------|
//! | 7   | TP-RP   | §9.2.3.17 |
//! | 6   | TP-UDHI | §9.2.3.23 |
//! | 5   | TP-SRI  | §9.2.3.4  |
//! | 4   | unused  |           |
//! | 3   | TP-LP   | §9.2.3.28 |
//! | 2   | TP-MMS  | §9.2.3.2  |
//! | 1-0 | TP-MTI  | §9.2.3.1  |
//!
//! All numbers are fictional (555-01xx).

mod support;

use tpdu::{RpDataNetworkToMs, SMSAddress, SmsDeliver};

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

fn address(digits: &str) -> SMSAddress {
    SMSAddress {
        ton: 1,
        npi: 1,
        address: digits.into(),
    }
}

/// 2025-01-01 12:00:00 at GMT: each pair of digits swapped into one octet.
const SCTS_DIGITS: &str = "25010112000000";
const SCTS: &str = "52 10 10 21 00 00 00";

/// One flag at a time: the first octet, its name, and the TP-UDL and
/// TP-User-Data that go with it. The data is 8-bit, "hi", behind a
/// one-element header (UDHL 2, IEI 0x70, length 0) when TP-UDHI is set.
const FLAGS: &[(u8, &str, &str)] = &[
    (0x80, "TP-RP", "02 68 69"),
    (0x40, "TP-UDHI", "05 02 70 00 68 69"),
    (0x20, "TP-SRI", "02 68 69"),
    (0x08, "TP-LP", "02 68 69"),
    (0x04, "TP-MMS", "02 68 69"),
];

/// The TPDU for one row of `FLAGS`: first octet, TP-OA 15550101 (8 digits,
/// international E.164, 51 55 10 10), TP-PID 0x00, TP-DCS 0x04 (8-bit),
/// TP-SCTS, TP-UDL and TP-UD.
fn wire(first_octet: u8, user_data: &str) -> Vec<u8> {
    octets(&format!(
        "{first_octet:02x} 08 91 51 55 10 10 00 04 {SCTS} {user_data}"
    ))
}

#[test]
fn every_first_octet_flag_encodes_where_the_specification_puts_it() {
    for (first_octet, name, user_data) in FLAGS {
        let user_data_octets = octets(user_data);
        let deliver = SmsDeliver {
            tp_rp: *first_octet == 0x80,
            tp_udhi: *first_octet == 0x40,
            tp_sri: *first_octet == 0x20,
            tp_lp: *first_octet == 0x08,
            tp_mms: *first_octet == 0x04,
            tp_mti: 0,
            tp_originating_address: address("15550101"),
            tp_pid: 0,
            tp_dcs: 4,
            tp_service_centre_timestamp: SCTS_DIGITS.into(),
            tp_user_data_length: user_data_octets[0],
            tp_user_data: user_data_octets[1..].to_vec(),
        };
        assert_eq!(
            deliver.encode().expect("encode"),
            wire(*first_octet, user_data),
            "{name}"
        );
    }
}

#[test]
fn every_first_octet_flag_decodes_from_where_the_specification_puts_it() {
    for (first_octet, name, user_data) in FLAGS {
        let deliver = SmsDeliver::decode(&wire(*first_octet, user_data)).expect("decode");
        assert_eq!(deliver.tp_rp, *first_octet == 0x80, "{name}");
        assert_eq!(deliver.tp_udhi, *first_octet == 0x40, "{name}");
        assert_eq!(deliver.tp_sri, *first_octet == 0x20, "{name}");
        assert_eq!(deliver.tp_lp, *first_octet == 0x08, "{name}");
        assert_eq!(deliver.tp_mms, *first_octet == 0x04, "{name}");
        assert_eq!(deliver.tp_mti, 0, "{name}");
        assert_eq!(deliver.tp_originating_address, address("15550101"));
        assert_eq!(deliver.tp_pid, 0, "{name}");
        assert_eq!(deliver.tp_dcs, 4, "{name}");
        assert_eq!(deliver.tp_service_centre_timestamp, SCTS_DIGITS);
        assert_eq!(deliver.tp_user_data, octets(user_data)[1..], "{name}");
    }
    // TP-MTI 10 from the network is an SMS-STATUS-REPORT.
    assert!(SmsDeliver::decode(&wire(0x02, "02 68 69")).is_err());
}

#[test]
fn wireshark_reads_every_first_octet_flag() {
    let deliver = |builder: tpdu::SmsDeliverBuilder| {
        let deliver = builder
            .dcs(0)
            .service_centre_timestamp(SCTS_DIGITS)
            .gsm7_text("hello")
            .build()
            .expect("build");
        RpDataNetworkToMs::builder(deliver)
            .message_reference(9)
            .originator_address(address("15550199"))
            .build()
            .encode()
            .expect("encode")
    };
    let oa = || SmsDeliver::builder(address("15550101"));
    // Two messages that between them show each flag set once and clear once.
    support::assert_dissects(
        &deliver(oa().rp(true).sri(true)),
        &[
            ("gsm_a.rp.msg_type", "0x01"),
            ("gsm_a.rp.rp_message_reference", "0x09"),
            ("gsm_a.dtap.clg_party_bcd_num", "15550199"),
            ("gsm_sms.tp-rp", "True"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp-sri", "True"),
            ("gsm_sms.tp-lp", "False"),
            ("gsm_sms.tp-mms", "False"),
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.tp-oa", "15550101"),
            ("gsm_sms.tp-pid", "0"),
            ("gsm_sms.tp-dcs", "0"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
            ("gsm_sms.tp.user_data_length", "5"),
            ("gsm_sms.sms_text", "hello"),
        ],
    );
    support::assert_dissects(
        &deliver(oa().lp(true).mms(true)),
        &[
            ("gsm_sms.tp-rp", "False"),
            ("gsm_sms.tp-sri", "False"),
            ("gsm_sms.tp-lp", "True"),
            ("gsm_sms.tp-mms", "True"),
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.sms_text", "hello"),
        ],
    );
}

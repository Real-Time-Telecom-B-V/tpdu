//! Known-answer vectors for address fields, time stamps and TP-PID.
//!
//! Hand-derived from TS 23.040 §9.1.2.3 (semi-octets), §9.1.2.5 (address
//! fields), §9.2.3.11 (time stamps) and TS 24.011 §8.2.5.1 (RP addresses), and
//! read back by Wireshark where our encoder emits them.
//!
//! All numbers are fictional (555-01xx).

mod support;

use std::io::Cursor;

use tpdu::{
    decode_sms_submit_tpdu, parse_rp_data, timestamp_digits, RpDataNetworkToMs, SMSAddress,
    SmsDeliver,
};

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

fn address(ton: u8, npi: u8, digits: &str) -> SMSAddress {
    SMSAddress {
        ton,
        npi,
        address: digits.into(),
    }
}

fn deliver_in_rp_data(deliver: SmsDeliver) -> Vec<u8> {
    RpDataNetworkToMs::builder(deliver)
        .originator_address(address(1, 1, "15550199"))
        .build()
        .encode()
        .expect("encode")
}

// ── Numeric addresses ────────────────────────────────────────────────────────

#[test]
fn an_odd_number_of_digits_is_filled_with_1111() {
    // §9.1.2.3: "the bits with bit numbers 4 to 7 within the last octet are
    // fill bits and shall always be set to '1111'", and §9.1.2.5: the length
    // "excludes any semi octet containing only fill bits". Nine digits
    // 155501234: 51 55 10 32 F4, length 9.
    let nine = address(1, 1, "155501234");
    assert_eq!(
        nine.encode(false).expect("encode"),
        octets("09 91 51 55 10 32 f4")
    );
    // The RP form (TS 24.011 §8.2.5.1) counts the octets after the length
    // octet instead: the type octet and five of digits make 6.
    assert_eq!(
        nine.encode(true).expect("encode"),
        octets("06 91 51 55 10 32 f4")
    );
}

#[test]
fn star_and_hash_are_semi_octets_1010_and_1011() {
    // §9.1.2.3: "1010='*', 1011='#', 1100='a', 1101='b', 1110='c'". The
    // service code *100# as an unknown-type number in the ISDN plan (0x81):
    // semi-octets A 1 0 0 B, paired low nibble first: 1A 00 FB.
    let code = address(0, 1, "*100#");
    assert_eq!(
        code.encode(false).expect("encode"),
        octets("05 81 1a 00 fb")
    );
    // a, b and c are the three remaining values: C D E and a fill nibble.
    assert_eq!(
        address(0, 1, "abc").encode(false).expect("encode"),
        octets("03 81 dc fe")
    );
    // Anything else has no semi-octet.
    assert!(address(0, 1, "12x4").encode(false).is_err());
    assert!(address(0, 1, "+15550100").encode(false).is_err());
}

#[test]
fn a_destination_with_star_and_hash_decodes() {
    // SMS-SUBMIT, no flags, TP-MR 1, TP-DA *100# as above, TP-PID 0, TP-DCS 4
    // (8-bit), TP-UDL 2, "hi".
    let tpdu = octets("01 01 05 81 1a 00 fb 00 04 02 68 69");
    let submit = decode_sms_submit_tpdu(&mut Cursor::new(tpdu.as_slice())).expect("decode");
    assert_eq!(submit.tp_destination_address, Some(address(0, 1, "*100#")));
    assert_eq!(submit.tp_user_data, b"hi");
    assert_eq!(submit.encode().expect("encode"), tpdu);
}

#[test]
fn an_address_of_no_digits_still_has_its_type_octet() {
    // §9.1.2.5: an address field is "an Address-Length field of one octet, a
    // Type-of-Address field of one octet, and one Address-Value field of
    // variable length", and §9.2.2.2 gives TP-DA as 2 to 12 octets. With a
    // length of zero the type octet is still there and TP-PID comes after it.
    let tpdu = octets("01 01 00 81 00 04 02 68 69");
    let submit = decode_sms_submit_tpdu(&mut Cursor::new(tpdu.as_slice())).expect("decode");
    assert_eq!(submit.tp_destination_address, Some(address(0, 1, "")));
    assert_eq!(submit.tp_pid, 0);
    assert_eq!(submit.tp_dcs, 4);
    assert_eq!(submit.tp_user_data, b"hi");
    assert_eq!(submit.encode().expect("encode"), tpdu);
}

#[test]
fn rp_addresses_decode_by_octet_count() {
    // RP-DATA MS to network: type 0, RP-MR 1, RP-OA empty (length 0), RP-DA of
    // length 6 (type 0x91 and the nine digits 155500001 as 51 55 00 00 F1),
    // then 13 octets of TPDU.
    let wire = octets(
        "00 01 00 06 91 51 55 00 00 f1 0d \
         01 01 08 91 51 55 10 00 00 04 02 68 69",
    );
    let parsed = parse_rp_data(&wire).expect("parse");
    assert_eq!(parsed.rp_originator_address, None);
    assert_eq!(
        parsed.rp_destination_address,
        Some(address(1, 1, "155500001"))
    );
    assert_eq!(parsed.encode().expect("encode"), wire);
}

#[test]
fn type_and_plan_must_fit_their_bit_fields() {
    // Type-of-number is three bits and the numbering plan four; a larger
    // value would spill into the neighbouring field or the extension bit.
    assert!(address(8, 1, "15550100").encode(false).is_err());
    assert!(address(1, 16, "15550100").encode(false).is_err());
    // §9.1.2.5: "The maximum length of the full address field ... is 12
    // octets", so ten octets of value: twenty digits fit, twenty-one do not.
    assert!(address(1, 1, "12345678901234567890").encode(false).is_ok());
    assert!(address(1, 1, "123456789012345678901")
        .encode(false)
        .is_err());
}

// ── Alphanumeric addresses ───────────────────────────────────────────────────

#[test]
fn an_alphanumeric_address_counts_useful_semi_octets() {
    // §9.1.2.5: "The Address-Length field is an integer representation of the
    // number of useful semi-octets within the Address-Value field". Seven
    // characters are 49 bits: 13 semi-octets (ceil(49 / 4)), not the 14 of
    // seven whole octets, which a receiver would read as eight characters.
    //
    // E=0x45 x=0x78 a=0x61 m=0x6D p=0x70 l=0x6C e=0x65 pack to
    // 45 7C B8 0D 67 97 01. Type octet 0xD0: alphanumeric, plan 0000.
    let name = address(5, 0, "Example");
    assert_eq!(
        name.encode(false).expect("encode"),
        octets("0d d0 45 7c b8 0d 67 97 01")
    );
    // Four characters are 28 bits, exactly 7 semi-octets.
    assert_eq!(
        address(5, 0, "TPDU").encode(false).expect("encode"),
        octets("07 d0 54 28 b1 0a")
    );
    // One character is 7 bits in 2 semi-octets, with the spare bit clear.
    assert_eq!(
        address(5, 0, "A").encode(false).expect("encode"),
        octets("02 d0 41")
    );
    // Eleven characters fill the ten octets an address value may have.
    assert!(address(5, 0, "ABCDEFGHIJK").encode(false).is_ok());
    assert!(address(5, 0, "ABCDEFGHIJKL").encode(false).is_err());
}

#[test]
fn an_alphanumeric_originator_decodes() {
    // SMS-DELIVER, TP-MMS set, TP-OA "Example" as above, TP-PID 0, TP-DCS 4,
    // TP-SCTS 2025-01-01 12:00:00 GMT, TP-UDL 2, "hi".
    let tpdu = octets("04 0d d0 45 7c b8 0d 67 97 01 00 04 52 10 10 21 00 00 00 02 68 69");
    let deliver = SmsDeliver::decode(&tpdu).expect("decode");
    assert_eq!(deliver.tp_originating_address, address(5, 0, "Example"));
    assert_eq!(deliver.tp_user_data, b"hi");
    assert_eq!(deliver.encode().expect("encode"), tpdu);

    // Length 14, as a sender that counts whole octets would put it: 14 * 4 / 7
    // is eight septets, and the eighth is the zero fill, '@'. That is what
    // such a sender puts on the wire, so that is what it reads as.
    let tpdu = octets("04 0e d0 45 7c b8 0d 67 97 01 00 04 52 10 10 21 00 00 00 02 68 69");
    let deliver = SmsDeliver::decode(&tpdu).expect("decode");
    assert_eq!(deliver.tp_originating_address.address, "Example@");
}

#[test]
fn wireshark_reads_an_alphanumeric_originator() {
    for name in ["Example", "TPDU", "A"] {
        let deliver = SmsDeliver::builder(address(5, 0, name))
            .dcs(0)
            .service_centre_timestamp("25010112000000")
            .gsm7_text("hello")
            .build()
            .expect("build");
        support::assert_dissects(
            &deliver_in_rp_data(deliver),
            &[
                ("gsm_sms.dis_field_addr.num_type", "5"),
                ("gsm_sms.tp-oa", name),
                ("gsm_sms.sms_text", "hello"),
            ],
        );
    }
}

#[test]
fn wireshark_reads_odd_and_special_digits() {
    for (ton, digits) in [(1u8, "155501234"), (0, "*100#")] {
        let deliver = SmsDeliver::builder(address(ton, 1, digits))
            .dcs(0)
            .service_centre_timestamp("25010112000000")
            .gsm7_text("hello")
            .build()
            .expect("build");
        support::assert_dissects(
            &deliver_in_rp_data(deliver),
            &[
                ("gsm_sms.dis_field_addr.num_type", &ton.to_string()),
                ("gsm_sms.dis_field_addr.num_plan", "1"),
                ("gsm_sms.tp-oa", digits),
                ("gsm_sms.sms_text", "hello"),
            ],
        );
    }
}

// ── Time stamps ──────────────────────────────────────────────────────────────

#[test]
fn the_time_zone_sign_is_bit_3_of_the_seventh_octet() {
    // §9.2.3.11: "The Time Zone indicates the difference, expressed in
    // quarters of an hour, between the local time and GMT. In the first of the
    // two semi-octets, the first bit (bit 3 of the seventh octet of the
    // TP-Service-Centre-Time-Stamp field) represents the algebraic sign of
    // this difference (0: positive, 1: negative)." The specification's own
    // example is the UK in summer, GMT+1h, coded 01000000.
    assert_eq!(
        timestamp_digits(26, 8, 17, 12, 0, 0, 4).expect("digits"),
        "26081712000004"
    );
    // GMT-5h is 20 quarters: digits 2 and 0, with the sign in the top bit of
    // the first one, 2 | 8 = A.
    assert_eq!(
        timestamp_digits(26, 8, 17, 12, 0, 0, -20).expect("digits"),
        "260817120000A0"
    );
    // GMT-1h: 0 | 8 and 4.
    assert_eq!(
        timestamp_digits(26, 8, 17, 12, 0, 0, -4).expect("digits"),
        "26081712000084"
    );
    assert!(timestamp_digits(26, 13, 1, 0, 0, 0, 0).is_err());
    assert!(timestamp_digits(26, 1, 1, 24, 0, 0, 0).is_err());
    assert!(timestamp_digits(26, 1, 1, 0, 0, 0, 80).is_err());
}

fn deliver_at(timestamp: &str) -> SmsDeliver {
    SmsDeliver::builder(address(1, 1, "15550101"))
        .dcs(4)
        .service_centre_timestamp(timestamp)
        .user_data(*b"hi")
        .user_data_length(2)
        .build()
        .expect("build")
}

#[test]
fn time_stamps_encode_as_swapped_semi_octets() {
    // 26 08 17 12 00 00 swap to 62 80 71 21 00 00. The time zone octet is
    // 0x40 for GMT+1h (digits 0 4) and 0x0A for GMT-5h (digits A 0): bit 3 of
    // the octet is the sign and the tens digit sits in the low nibble.
    let east = deliver_at("26081712000004").encode().expect("encode");
    assert_eq!(
        east,
        octets("00 08 91 51 55 10 10 00 04 62 80 71 21 00 00 40 02 68 69")
    );
    let west = deliver_at("260817120000A0").encode().expect("encode");
    assert_eq!(
        west,
        octets("00 08 91 51 55 10 10 00 04 62 80 71 21 00 00 0a 02 68 69")
    );
    // And back, from the hand-built bytes.
    let decoded = SmsDeliver::decode(&octets(
        "00 08 91 51 55 10 10 00 04 62 80 71 21 00 00 0a 02 68 69",
    ))
    .expect("decode");
    assert_eq!(decoded.tp_service_centre_timestamp, "260817120000A0");
}

#[test]
fn a_time_stamp_that_is_not_fourteen_digits_is_refused() {
    // Thirteen digits used to index past the end of the string, and none at
    // all produced a TPDU with no TP-SCTS in it.
    assert!(deliver_at("2608171200000").encode().is_err());
    assert!(deliver_at("").encode().is_err());
    assert!(deliver_at("26081712000000 ").encode().is_err());
    assert!(deliver_at("2608171200000Z").encode().is_err());
}

#[test]
fn wireshark_applies_the_time_zone_we_encoded() {
    // 12:00:00 local on 2026-08-17 in three zones, shown by Wireshark in UTC.
    for (quarters, utc) in [
        (0i8, "2026-08-17T12:00:00.000000000+0000"),
        (4, "2026-08-17T11:00:00.000000000+0000"),
        (-20, "2026-08-17T17:00:00.000000000+0000"),
        // GMT+5h45m, a zone that needs the quarter-hour resolution.
        (23, "2026-08-17T06:15:00.000000000+0000"),
    ] {
        let digits = timestamp_digits(26, 8, 17, 12, 0, 0, quarters).expect("digits");
        let deliver = SmsDeliver::builder(address(1, 1, "15550101"))
            .dcs(0)
            .service_centre_timestamp(digits)
            .gsm7_text("hello")
            .build()
            .expect("build");
        support::assert_dissects(
            &deliver_in_rp_data(deliver),
            &[
                ("gsm_sms.scts.year", "26"),
                ("gsm_sms.scts.month", "8"),
                ("gsm_sms.scts.day", "17"),
                ("gsm_sms.scts.hour", "12"),
                ("gsm_sms.scts.minutes", "0"),
                ("gsm_sms.scts.seconds", "0"),
                ("gsm_sms.scts", utc),
            ],
        );
    }
}

// ── TP-PID ───────────────────────────────────────────────────────────────────

#[test]
fn wireshark_reads_the_protocol_identifier_we_encoded() {
    // TP-PID is one octet carried as given (§9.2.3.9). 0x00 is plain
    // SME-to-SME, 0x41 "Replace Short Message Type 1" and 0x7F "(U)SIM Data
    // download", both in the 01xxxxxx group.
    for pid in [0x00u8, 0x41, 0x7f] {
        let deliver = SmsDeliver::builder(address(1, 1, "15550101"))
            .pid(pid)
            .dcs(0)
            .service_centre_timestamp("25010112000000")
            .gsm7_text("hello")
            .build()
            .expect("build");
        let tpdu = deliver.encode().expect("encode");
        // First octet, six octets of TP-OA, then TP-PID.
        assert_eq!(tpdu[7], pid);
        support::assert_dissects(
            &deliver_in_rp_data(deliver),
            &[
                ("gsm_sms.tp-pid", &pid.to_string()),
                ("gsm_sms.sms_text", "hello"),
            ],
        );
    }
}

//! Known-answer vectors for the SMS-SUBMIT first octet and TP-Validity-Period.
//!
//! Every vector here is written out by hand from TS 23.040, never produced by
//! this crate, so the decoder is checked against bytes it had no part in and
//! the encoder against bytes it has to reproduce. The bytes the encoder emits
//! are then read back by Wireshark (see `support`), which shares none of our
//! code.
//!
//! First octet of an SMS-SUBMIT, bit by bit (TS 23.040):
//!
//! | bit | field   | clause    |
//! |-----|---------|-----------|
//! | 7   | TP-RP   | §9.2.3.17 |
//! | 6   | TP-UDHI | §9.2.3.23 |
//! | 5   | TP-SRR  | §9.2.3.5  |
//! | 4-3 | TP-VPF  | §9.2.3.3  |
//! | 2   | TP-RD   | §9.2.3.25 |
//! | 1-0 | TP-MTI  | §9.2.3.1  |
//!
//! TP-VPF, bit 4 then bit 3 (§9.2.3.3): `0 0` no TP-VP, `1 0` relative (one
//! octet), `0 1` enhanced (seven octets), `1 1` absolute (seven octets).
//!
//! All numbers are fictional (555-01xx) and the text is neutral.

mod support;

use std::io::Cursor;

use tpdu::{
    decode_sms_submit_tpdu, parse_rp_data, RpDataMsToNetwork, SMSAddress, SmsSubmit,
    UserDataHeader, ValidityPeriod, VALIDITY_PERIOD_FORMAT_ABSOLUTE,
    VALIDITY_PERIOD_FORMAT_ENHANCED, VALIDITY_PERIOD_FORMAT_NONE, VALIDITY_PERIOD_FORMAT_RELATIVE,
};

/// TP-MR 0x2A, then TP-DA: 8 digits (0x08), international E.164 (0x91), and
/// 15550100 in semi-octets, each pair swapped: 51 55 10 00.
const MR_AND_DESTINATION: &str = "2a 08 91 51 55 10 00";
/// TP-PID 0x00, TP-DCS 0x04 (general group, 8-bit data).
const PID_AND_DCS_8BIT: &str = "00 04";
/// TP-UDL 2 octets, "hi".
const USER_DATA_HI: &str = "02 68 69";
/// TP-UDL 8 octets: a concatenation header (UDHL 5, IEI 00, length 3,
/// reference 0x42, 2 parts, part 1) and then "hi".
const USER_DATA_HEADER_HI: &str = "08 05 00 03 42 02 01 68 69";

/// Relative TP-VP 0xA7 = 167: (167 - 166) x 1 day (§9.2.3.12.1).
const VP_RELATIVE: &str = "a7";
/// Absolute TP-VP, coded like TP-SCTS (§9.2.3.12.2): 2026-10-31 23:59:00 at
/// GMT+1h. Semi-octets swap within each octet, so 26 -> 62, 10 -> 01,
/// 31 -> 13, 23 -> 32, 59 -> 95, 00 -> 00, and 4 quarter hours -> 40.
const VP_ABSOLUTE: &str = "62 01 13 32 95 00 40";
const VP_ABSOLUTE_DIGITS: &str = "26103123590004";
/// Enhanced TP-VP (§9.2.3.12.3): functionality indicator 0x01 (no extension,
/// not single shot, format 001 = "as specified for the relative case"), the
/// relative value 0xA7, then five unused octets set to zero.
const VP_ENHANCED: &str = "01 a7 00 00 00 00 00";
const VP_ENHANCED_OCTETS: [u8; 7] = [0x01, 0xa7, 0, 0, 0, 0, 0];

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

fn destination() -> SMSAddress {
    SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550100".into(),
    }
}

fn decode(tpdu: &[u8]) -> SmsSubmit {
    decode_sms_submit_tpdu(&mut Cursor::new(tpdu)).expect("decode SMS-SUBMIT")
}

/// Wrap a TPDU in RP-DATA MS to network by hand (TS 24.011 §7.3.1.2): type 0,
/// RP-MR 1, empty RP-OA, empty RP-DA, then the TPDU behind its length.
fn in_rp_data(tpdu: &[u8]) -> Vec<u8> {
    let mut rp = vec![0x00, 0x01, 0x00, 0x00, tpdu.len() as u8];
    rp.extend_from_slice(tpdu);
    rp
}

/// The four validity-period formats: TP-VPF value, TP-VP octets, decoded form.
fn validity_periods() -> [(u8, &'static str, Option<ValidityPeriod>); 4] {
    [
        (VALIDITY_PERIOD_FORMAT_NONE, "", None),
        (
            VALIDITY_PERIOD_FORMAT_RELATIVE,
            VP_RELATIVE,
            Some(ValidityPeriod::Relative(0xa7)),
        ),
        (
            VALIDITY_PERIOD_FORMAT_ABSOLUTE,
            VP_ABSOLUTE,
            Some(ValidityPeriod::Absolute(VP_ABSOLUTE_DIGITS.into())),
        ),
        (
            VALIDITY_PERIOD_FORMAT_ENHANCED,
            VP_ENHANCED,
            Some(ValidityPeriod::Enhanced(VP_ENHANCED_OCTETS)),
        ),
    ]
}

#[test]
fn the_format_constants_are_the_two_bit_values_of_clause_9_2_3_3() {
    // "bit4 bit3: 0 0 TP-VP field not present; 1 0 relative format; 0 1
    // enhanced format; 1 1 absolute format".
    assert_eq!(VALIDITY_PERIOD_FORMAT_NONE, 0b00);
    assert_eq!(VALIDITY_PERIOD_FORMAT_RELATIVE, 0b10);
    assert_eq!(VALIDITY_PERIOD_FORMAT_ENHANCED, 0b01);
    assert_eq!(VALIDITY_PERIOD_FORMAT_ABSOLUTE, 0b11);
}

#[test]
fn status_report_request_without_validity_period_decodes() {
    // 0x21 = 0010 0001: TP-SRR (bit 5) and TP-MTI 01, TP-VPF 00. TP-PID is
    // followed directly by TP-UDL, there is no TP-VP octet to read.
    let tpdu = octets("21 2a 08 91 51 55 10 00 00 04 02 68 69");
    let submit = decode(&tpdu);
    assert!(submit.tp_srr);
    assert!(!submit.tp_udhi && !submit.tp_rp && !submit.tp_rd);
    assert_eq!(submit.tp_vpf, VALIDITY_PERIOD_FORMAT_NONE);
    assert_eq!(submit.tp_validity_period, None);
    assert_eq!(submit.tp_user_data_length, 2);
    assert_eq!(submit.tp_user_data, b"hi");
}

#[test]
fn header_without_validity_period_keeps_its_text() {
    // 0x41 = 0100 0001: TP-UDHI (bit 6) and TP-MTI 01, TP-VPF 00.
    let tpdu = octets("41 2a 08 91 51 55 10 00 00 04 08 05 00 03 42 02 01 68 69");
    let submit = decode(&tpdu);
    assert!(submit.tp_udhi);
    assert_eq!(submit.tp_validity_period, None);
    assert_eq!(submit.tp_user_data_length, 8);
    assert_eq!(
        submit.tp_user_data_header,
        Some(UserDataHeader {
            user_data_header_length: 5,
            user_data_header_value: vec![0x00, 0x03, 0x42, 0x02, 0x01],
        })
    );
    assert_eq!(submit.tp_user_data, octets("05 00 03 42 02 01 68 69"));
}

#[test]
fn reject_duplicates_is_bit_2_whatever_the_other_bits_are() {
    // 0x05 = 0000 0101: TP-RD alone. 0x35 = 0011 0101: TP-RD with TP-SRR and a
    // relative validity period. 0x31 = 0011 0001: the same without TP-RD.
    assert!(decode(&octets("05 2a 08 91 51 55 10 00 00 04 02 68 69")).tp_rd);
    assert!(decode(&octets("35 2a 08 91 51 55 10 00 00 04 a7 02 68 69")).tp_rd);
    assert!(!decode(&octets("31 2a 08 91 51 55 10 00 00 04 a7 02 68 69")).tp_rd);
}

#[test]
fn relative_validity_period_is_one_octet() {
    // 0x11 = 0001 0001: TP-VPF bit 4 set, bit 3 clear.
    let submit = decode(&octets("11 2a 08 91 51 55 10 00 00 04 a7 02 68 69"));
    assert_eq!(submit.tp_vpf, VALIDITY_PERIOD_FORMAT_RELATIVE);
    assert_eq!(
        submit.tp_validity_period,
        Some(ValidityPeriod::Relative(0xa7))
    );
    assert_eq!(submit.tp_user_data, b"hi");
}

#[test]
fn absolute_validity_period_is_seven_octets() {
    // 0x19 = 0001 1001: TP-VPF bits 4 and 3 both set.
    let submit = decode(&octets(
        "19 2a 08 91 51 55 10 00 00 04 62 01 13 32 95 00 40 02 68 69",
    ));
    assert_eq!(submit.tp_vpf, VALIDITY_PERIOD_FORMAT_ABSOLUTE);
    assert_eq!(
        submit.tp_validity_period,
        Some(ValidityPeriod::Absolute("26103123590004".into()))
    );
    assert_eq!(submit.tp_user_data_length, 2);
    assert_eq!(submit.tp_user_data, b"hi");
}

#[test]
fn enhanced_validity_period_is_seven_octets() {
    // 0x09 = 0000 1001: TP-VPF bit 4 clear, bit 3 set.
    let submit = decode(&octets(
        "09 2a 08 91 51 55 10 00 00 04 01 a7 00 00 00 00 00 02 68 69",
    ));
    assert_eq!(submit.tp_vpf, VALIDITY_PERIOD_FORMAT_ENHANCED);
    assert_eq!(
        submit.tp_validity_period,
        Some(ValidityPeriod::Enhanced([0x01, 0xa7, 0, 0, 0, 0, 0]))
    );
    assert_eq!(submit.tp_user_data_length, 2);
    assert_eq!(submit.tp_user_data, b"hi");
}

#[test]
fn every_first_octet_decodes_and_encodes_to_the_hand_built_bytes() {
    // All sixteen settings of TP-RP / TP-UDHI / TP-SRR / TP-RD against all
    // four validity-period formats. The expected bytes are assembled here from
    // the bit positions in the table at the top of this file and the literal
    // pieces above, not by the crate.
    for flags in 0u8..16 {
        let (rp, udhi, srr, rd) = (
            flags & 8 != 0,
            flags & 4 != 0,
            flags & 2 != 0,
            flags & 1 != 0,
        );
        for (vpf, vp, validity_period) in validity_periods() {
            let first_octet = (rp as u8) << 7
                | (udhi as u8) << 6
                | (srr as u8) << 5
                | vpf << 3
                | (rd as u8) << 2
                | 0b01;
            let user_data = if udhi {
                USER_DATA_HEADER_HI
            } else {
                USER_DATA_HI
            };
            let wire = octets(&format!(
                "{first_octet:02x} {MR_AND_DESTINATION} {PID_AND_DCS_8BIT} {vp} {user_data}"
            ));

            let submit = decode(&wire);
            let context = format!("first octet 0x{first_octet:02x}");
            assert_eq!(submit.tp_rp, rp, "TP-RP, {context}");
            assert_eq!(submit.tp_udhi, udhi, "TP-UDHI, {context}");
            assert_eq!(submit.tp_srr, srr, "TP-SRR, {context}");
            assert_eq!(submit.tp_rd, rd, "TP-RD, {context}");
            assert_eq!(submit.tp_vpf, vpf, "TP-VPF, {context}");
            assert_eq!(submit.tp_mti, 1, "TP-MTI, {context}");
            assert_eq!(submit.tp_mr, 0x2a, "TP-MR, {context}");
            assert_eq!(
                submit.tp_destination_address,
                Some(destination()),
                "{context}"
            );
            assert_eq!(submit.tp_pid, 0, "TP-PID, {context}");
            assert_eq!(submit.tp_dcs, 4, "TP-DCS, {context}");
            assert_eq!(submit.tp_validity_period, validity_period, "{context}");
            assert_eq!(
                submit.tp_user_data,
                octets(&user_data[3..]),
                "TP-UD, {context}"
            );
            assert_eq!(submit.tp_user_data_header.is_some(), udhi, "{context}");

            // Build the same message field by field and compare with the
            // hand-built bytes.
            let built = SmsSubmit {
                tp_rp: rp,
                tp_udhi: udhi,
                tp_srr: srr,
                tp_mti: 1,
                tp_rd: rd,
                tp_vpf: vpf,
                tp_mr: 0x2a,
                tp_destination_address: Some(destination()),
                tp_pid: 0,
                tp_dcs: 4,
                tp_validity_period: validity_period,
                tp_user_data_length: if udhi { 8 } else { 2 },
                tp_user_data_raw: octets(&user_data[3..]),
                tp_user_data_header: None,
                tp_user_data: Vec::new(),
            };
            assert_eq!(built.encode().expect("encode"), wire, "encode, {context}");
        }
    }
}

#[test]
fn every_flag_set_with_an_absolute_validity_period() {
    // 0xFD = 1111 1101: TP-RP, TP-UDHI, TP-SRR, TP-VPF 11, TP-RD, TP-MTI 01.
    let wire =
        octets("fd 2a 08 91 51 55 10 00 00 04 62 01 13 32 95 00 40 08 05 00 03 42 02 01 68 69");
    let submit = decode(&wire);
    assert!(submit.tp_rp && submit.tp_udhi && submit.tp_srr && submit.tp_rd);
    assert_eq!(submit.tp_vpf, VALIDITY_PERIOD_FORMAT_ABSOLUTE);
    assert_eq!(submit.encode().expect("encode"), wire);
}

#[test]
fn rp_data_from_a_mobile_station_decodes_with_each_validity_period() {
    for (vpf, vp, validity_period) in validity_periods() {
        // TP-SRR set throughout, the case that used to shift the layout.
        let first_octet = 0x21 | vpf << 3;
        let tpdu = octets(&format!(
            "{first_octet:02x} {MR_AND_DESTINATION} {PID_AND_DCS_8BIT} {vp} {USER_DATA_HI}"
        ));
        let parsed = parse_rp_data(&in_rp_data(&tpdu)).expect("parse RP-DATA");
        assert_eq!(parsed.rp_message_reference, 1);
        assert_eq!(parsed.sms_submit.tp_validity_period, validity_period);
        assert_eq!(parsed.sms_submit.tp_user_data, b"hi");
    }
}

#[test]
fn a_tpdu_that_is_not_an_sms_submit_is_turned_down() {
    // TP-MTI 10 from a mobile station is an SMS-COMMAND (§9.2.3.1), whose
    // layout is different: reading it as an SMS-SUBMIT would invent fields.
    let tpdu = octets("02 2a 00 00 00 00 00");
    assert!(decode_sms_submit_tpdu(&mut Cursor::new(tpdu.as_slice())).is_err());
}

#[test]
fn encode_refuses_a_format_that_disagrees_with_the_validity_period() {
    let mut submit = decode(&octets("11 2a 08 91 51 55 10 00 00 04 a7 02 68 69"));
    submit.tp_vpf = VALIDITY_PERIOD_FORMAT_ABSOLUTE;
    assert!(submit.encode().is_err());
    submit.tp_vpf = VALIDITY_PERIOD_FORMAT_NONE;
    assert!(submit.encode().is_err());
}

#[test]
fn wireshark_reads_back_each_validity_period_format() {
    // GSM 7-bit text so that Wireshark shows the message itself: a shifted
    // layout would turn it into something else. "hello" packs to
    // E8 32 9B FD 06 (five septets).
    let submit = |builder: tpdu::SmsSubmitBuilder| {
        let submit = builder
            .srr(true)
            .rd(true)
            .mr(0x2a)
            .destination_address(destination())
            .dcs(0)
            .gsm7_text("hello")
            .build()
            .expect("build");
        RpDataMsToNetwork::builder(submit)
            .message_reference(1)
            .destination_address(SMSAddress {
                ton: 1,
                npi: 1,
                address: "15550000".into(),
            })
            .build()
            .encode()
            .expect("encode")
    };
    let common = [
        ("gsm_a.rp.msg_type", "0x00"),
        ("gsm_a.dtap.cld_party_bcd_num", "15550000"),
        ("gsm_sms.tp-mti", "1"),
        ("gsm_sms.tp-rp", "False"),
        ("gsm_sms.tp-udhi", "False"),
        ("gsm_sms.tp-srr", "True"),
        ("gsm_sms.tp-rd", "True"),
        ("gsm_sms.tp-mr", "42"),
        ("gsm_sms.tp-da", "15550100"),
        ("gsm_sms.tp.user_data_length", "5"),
        ("gsm_sms.sms_text", "hello"),
    ];
    let with = |extra: &[(&'static str, &'static str)]| [&common[..], extra].concat();

    support::assert_dissects(
        &submit(SmsSubmit::builder()),
        &with(&[("gsm_sms.tp-vpf", "0")]),
    );
    support::assert_dissects(
        &submit(SmsSubmit::builder().vpf(2).validity_period(0xa7)),
        &with(&[
            ("gsm_sms.tp-vpf", "2"),
            ("gsm_sms.vp.validity_period", "167"),
        ]),
    );
    support::assert_dissects(
        &submit(
            SmsSubmit::builder()
                .vpf(3)
                .validity_period_absolute(VP_ABSOLUTE_DIGITS),
        ),
        &with(&[
            ("gsm_sms.tp-vpf", "3"),
            // 23:59 at GMT+1h is 22:59 UTC.
            (
                "gsm_sms.vp.validity_period.absolute",
                "2026-10-31T22:59:00.000000000+0000",
            ),
        ]),
    );
    // Enhanced format, with a functionality indicator of 0x43: no extension,
    // single shot (bit 6), format 011 = relative as hours, minutes and seconds
    // in semi-octets, here 01:30:00 -> 10 03 00, then three unused octets.
    //
    // The indicator used elsewhere in this file, 0x01 ("as the relative
    // case"), is deliberately not given to Wireshark: its dissector steps over
    // one octet instead of seven for that one sub-format and then reads the
    // validity value again as TP-UDL. §9.2.3.12.3 leaves no doubt ("The
    // TP-Validity Period comprises 7 octets. The presence of all octets is
    // mandatory although they may not all be used"), so that sub-format rests
    // on the hand-built vectors alone.
    support::assert_dissects(
        &submit(
            SmsSubmit::builder()
                .vpf(1)
                .validity_period_enhanced([0x43, 0x10, 0x03, 0, 0, 0, 0]),
        ),
        &with(&[
            ("gsm_sms.tp-vpf", "1"),
            ("gsm_sms.vp.validity_period_format", "3"),
            ("gsm_sms.vp.single_shot_sm", "True"),
            ("gsm_sms.vp.validity_period.hour", "1"),
            ("gsm_sms.vp.validity_period.minutes", "30"),
            ("gsm_sms.vp.validity_period.seconds", "0"),
        ]),
    );
}

#[test]
fn wireshark_reads_back_every_flag() {
    // Reply path and header set, the other two clear: the complement of the
    // test above, so each flag is seen both ways.
    let header = UserDataHeader {
        user_data_header_length: 5,
        user_data_header_value: vec![0x00, 0x03, 0x42, 0x02, 0x01],
    };
    let submit = SmsSubmit::builder()
        .rp(true)
        .udhi(true)
        .mr(7)
        .destination_address(destination())
        .dcs(0)
        .gsm7_text_with_header(header, "hello")
        .build()
        .expect("build");
    let wire = RpDataMsToNetwork::builder(submit)
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_sms.tp-rp", "True"),
            ("gsm_sms.tp-udhi", "True"),
            ("gsm_sms.tp-srr", "False"),
            ("gsm_sms.tp-rd", "False"),
            ("gsm_sms.tp-vpf", "0"),
            ("gsm_sms.tp-mr", "7"),
            ("gsm_sms.tp.user_data_length", "12"),
            ("gsm_sms.dis_field_udh.user_data_header_length", "5"),
            ("gsm_sms.udh.mm.msg_id", "66"),
            ("gsm_sms.udh.mm.msg_parts", "2"),
            ("gsm_sms.udh.mm.msg_part", "1"),
        ],
    );
}

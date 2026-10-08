//! Known-answer vectors for TP-User-Data: 7-bit text behind a user-data
//! header, the data coding schemes that select the 7-bit alphabet, and what
//! TP-UDL counts for each coding.
//!
//! The vectors are derived by hand from the packing rule of TS 23.038
//! §6.1.2.1.1 and the header rule of TS 23.040 §9.2.3.24. Neither
//! specification prints a worked octet string for a header followed by 7-bit
//! text (figure 9.2.3.24 (a) is a layout diagram), so each derivation is spelt
//! out next to its vector.
//!
//! Packing, §6.1.2.1.1: septets are laid end to end starting at bit 0 of the
//! first octet, low bits first ("The bit number zero is always transmitted
//! first"), and the octets are completed "with zeros on the left".
//!
//! Header, §9.2.3.24: "If 7 bit data is used and the TP-UD-Header does not
//! finish on a septet boundary then fill bits are inserted after the last
//! Information Element Data octet up to the next septet boundary so that there
//! is an integral number of septets for the entire TP-UD header."
//!
//! Length, §9.2.3.16: "If a TP-User-Data-Header field is present, then the
//! TP-User-Data-Length value is the sum of the number of septets in the
//! TP-User-Data-Header field (including any padding) and the number of septets
//! in the TP-User-Data field which follows."

mod support;

use std::io::Cursor;

use tpdu::{
    decode_sms_submit_tpdu, pack_gsm7, pack_gsm7_with_header, unpack_gsm7, unpack_gsm7_with_header,
    user_data_coding, RpDataNetworkToMs, SMSAddress, SmsDeliver, SmsSubmit, UserDataCoding,
    UserDataHeader,
};

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

fn decode_submit(tpdu: &str) -> SmsSubmit {
    let tpdu = octets(tpdu);
    decode_sms_submit_tpdu(&mut Cursor::new(tpdu.as_slice())).expect("decode SMS-SUBMIT")
}

fn originator() -> SMSAddress {
    SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550101".into(),
    }
}

/// Concatenation header: UDHL 5, IEI 00 (8-bit reference), IE length 3,
/// reference 0x2A, 2 parts, part 1 (TS 23.040 §9.2.3.24.1).
const CONCATENATION_HEADER: [u8; 6] = [0x05, 0x00, 0x03, 0x2a, 0x02, 0x01];

/// The header above followed by "hello".
///
/// The header is 6 octets = 48 bits. The next septet boundary is 49 bits (7
/// septets), so one fill bit follows it and the text starts at bit 1 of the
/// seventh octet. With h=0x68 e=0x65 l=0x6C l=0x6C o=0x6F:
///
/// ```text
/// octet 6: fill 0 | h<<1                 = 0xD0
/// octet 7: e | (l & 0x01)<<7             = 0x65
/// octet 8: l>>1 | (l & 0x03)<<6          = 0x36
/// octet 9: l>>2 | (o & 0x07)<<5          = 0xFB
/// octet 10: o>>3                         = 0x0D
/// ```
///
/// TP-UDL = 7 header septets + 5 text septets = 12.
const HEADER_AND_HELLO: &str = "05 00 03 2a 02 01 d0 65 36 fb 0d";

#[test]
fn text_behind_a_header_starts_on_a_septet_boundary() {
    let (user_data, length) = pack_gsm7_with_header(&CONCATENATION_HEADER, "hello").expect("pack");
    assert_eq!(user_data, octets(HEADER_AND_HELLO));
    assert_eq!(length, 12);
}

#[test]
fn a_header_that_ends_on_a_septet_boundary_needs_no_fill() {
    // UDHL 6 with a 16-bit concatenation reference (IEI 08, length 4,
    // reference 0x002A, 2 parts, part 1): 7 octets = 56 bits = exactly 8
    // septets. The text is then packed as if it stood alone:
    // "hello" = E8 32 9B FD 06. TP-UDL = 8 + 5 = 13.
    let header = octets("06 08 04 00 2a 02 01");
    let (user_data, length) = pack_gsm7_with_header(&header, "hello").expect("pack");
    assert_eq!(user_data, octets("06 08 04 00 2a 02 01 e8 32 9b fd 06"));
    assert_eq!(length, 13);
}

#[test]
fn a_longer_header_takes_more_fill_bits() {
    // UDHL 8: the 8-bit concatenation element and a UDH source indicator
    // (IEI 07, length 1, value 01). 9 octets = 72 bits, the next septet
    // boundary is 77 bits (11 septets), so 5 fill bits. "hi", h=0x68 i=0x69:
    //
    //   octet 9:  fill 00000 | (h & 0x07)<<5        = 0x00
    //   octet 10: h>>3 | (i & 0x0F)<<4              = 0x9D
    //   octet 11: i>>4                              = 0x06
    //
    // TP-UDL = 11 + 2 = 13.
    let header = octets("08 00 03 2a 02 01 07 01 01");
    let (user_data, length) = pack_gsm7_with_header(&header, "hi").expect("pack");
    assert_eq!(user_data, octets("08 00 03 2a 02 01 07 01 01 00 9d 06"));
    assert_eq!(length, 13);

    let (decoded_header, text) =
        unpack_gsm7_with_header(&octets("08 00 03 2a 02 01 07 01 01 00 9d 06"), 13)
            .expect("unpack");
    assert_eq!(decoded_header, header);
    assert_eq!(text, "hi");
}

#[test]
fn a_header_with_no_text_still_counts_its_fill_bits() {
    // 48 header bits need a seventh octet to hold the fill bit of the seventh
    // septet: TP-UDL 7 septets is ceil(49 / 8) = 7 octets.
    let (user_data, length) = pack_gsm7_with_header(&CONCATENATION_HEADER, "").expect("pack");
    assert_eq!(user_data, octets("05 00 03 2a 02 01 00"));
    assert_eq!(length, 7);
}

#[test]
fn a_header_whose_length_octet_is_wrong_is_refused() {
    assert!(pack_gsm7_with_header(&[0x05, 0x00, 0x03], "hello").is_err());
    assert!(pack_gsm7_with_header(&[], "hello").is_err());
}

#[test]
fn unpacking_splits_header_and_text() {
    let (header, text) = unpack_gsm7_with_header(&octets(HEADER_AND_HELLO), 12).expect("unpack");
    assert_eq!(header, CONCATENATION_HEADER);
    assert_eq!(text, "hello");
    // A TP-UDL smaller than the header itself cannot be right.
    assert!(unpack_gsm7_with_header(&octets(HEADER_AND_HELLO), 6).is_err());
}

#[test]
fn an_sms_submit_with_a_header_and_7_bit_text_keeps_both() {
    // First octet 0x41: TP-UDHI and TP-MTI 01, no validity period. TP-DCS 00.
    // TP-UDL 0x0C = 12 septets, then the vector above.
    let submit = decode_submit(&format!(
        "41 2a 08 91 51 55 10 00 00 00 0c {HEADER_AND_HELLO}"
    ));
    assert!(submit.tp_udhi);
    assert_eq!(submit.tp_user_data_length, 12);
    assert_eq!(
        submit.tp_user_data_header,
        Some(UserDataHeader {
            user_data_header_length: 5,
            user_data_header_value: vec![0x00, 0x03, 0x2a, 0x02, 0x01],
        })
    );
    // The readable form starts with the header, as TP-UDHI says, for 7-bit
    // text just as for every other coding.
    assert_eq!(
        submit.tp_user_data,
        [&CONCATENATION_HEADER[..], b"hello"].concat()
    );
    assert_eq!(submit.tp_user_data_raw, octets(HEADER_AND_HELLO));
    // And it goes back out as it came in.
    assert_eq!(
        submit.encode().expect("encode"),
        octets(&format!(
            "41 2a 08 91 51 55 10 00 00 00 0c {HEADER_AND_HELLO}"
        ))
    );
}

#[test]
fn the_data_coding_scheme_table_of_ts_23_038_clause_4() {
    use UserDataCoding::{Compressed, EightBit, Gsm7Bit, Ucs2};
    let table: &[(u8, UserDataCoding)] = &[
        // General group 00xx: bits 3-2 are the character set, 00 = 7-bit,
        // 01 = 8-bit, 10 = UCS2, 11 reserved (reserved codings "shall be
        // assumed to be the GSM 7 bit default alphabet").
        (0x00, Gsm7Bit),
        (0x04, EightBit),
        (0x08, Ucs2),
        (0x0c, Gsm7Bit),
        // Bit 4 set: bits 1-0 are a message class, the character set is
        // unchanged. Class 0 ("flash") to class 3.
        (0x10, Gsm7Bit),
        (0x11, Gsm7Bit),
        (0x12, Gsm7Bit),
        (0x13, Gsm7Bit),
        (0x14, EightBit),
        (0x18, Ucs2),
        // Bit 5 set: compressed, TP-UDL counts octets after compression.
        (0x20, Compressed),
        (0x28, Compressed),
        (0x30, Compressed),
        // 01xx, marked for automatic deletion: "coded exactly the same as
        // Group 00xx".
        (0x40, Gsm7Bit),
        (0x44, EightBit),
        (0x48, Ucs2),
        (0x51, Gsm7Bit),
        (0x60, Compressed),
        // 1000..1011 are reserved coding groups.
        (0x80, Gsm7Bit),
        (0xb4, Gsm7Bit),
        // 1100 and 1101, message waiting: "coded in the GSM 7 bit default
        // alphabet". 1110: "the uncompressed UCS2 character set".
        (0xc8, Gsm7Bit),
        (0xd0, Gsm7Bit),
        (0xe8, Ucs2),
        // 1111: bit 2 is the message coding, 0 = 7-bit, 1 = 8-bit.
        (0xf0, Gsm7Bit),
        (0xf1, Gsm7Bit),
        (0xf3, Gsm7Bit),
        (0xf4, EightBit),
        (0xf7, EightBit),
    ];
    for (dcs, coding) in table {
        assert_eq!(user_data_coding(*dcs), *coding, "TP-DCS 0x{dcs:02x}");
    }
}

#[test]
fn seven_bit_text_with_a_message_class_is_unpacked() {
    // "hellohello" is the widely published vector E8 32 9B FD 46 97 D9 EC 37:
    // ten septets in nine octets. TP-UDL 0x0A counts septets for every one of
    // these codings: class 0 and class 1 in the general group, class 1 in
    // group 1111, and a message-waiting indication.
    for dcs in ["10", "11", "f1", "c8"] {
        let submit = decode_submit(&format!(
            "01 2a 08 91 51 55 10 00 00 {dcs} 0a e8 32 9b fd 46 97 d9 ec 37"
        ));
        assert_eq!(submit.tp_user_data_length, 10, "TP-DCS 0x{dcs}");
        assert_eq!(submit.tp_user_data, b"hellohello", "TP-DCS 0x{dcs}");
        assert_eq!(submit.tp_user_data_raw.len(), 9, "TP-DCS 0x{dcs}");
    }
}

#[test]
fn eight_bit_and_ucs2_with_a_message_class_count_octets() {
    // TP-DCS 0xF5: group 1111, 8-bit data, class 1. TP-UDL 2 octets.
    let submit = decode_submit("01 2a 08 91 51 55 10 00 00 f5 02 68 69");
    assert_eq!(submit.tp_user_data, b"hi");
    // TP-DCS 0x18: general group, UCS2, class 0. "hi" in UTF-16BE, 4 octets.
    let submit = decode_submit("01 2a 08 91 51 55 10 00 00 18 04 00 68 00 69");
    assert_eq!(submit.tp_user_data, octets("00 68 00 69"));
}

#[test]
fn seven_bit_text_outside_latin_1_decodes_as_utf_8() {
    // a = 0x61, the euro sign is the escape 0x1B then 0x65 (§6.2.1.1), and
    // the Greek capital delta is 0x10:
    //
    //   octet 0: 0x61 | (0x1B & 0x01)<<7      = 0xE1
    //   octet 1: 0x1B>>1 | (0x65 & 0x03)<<6   = 0x4D
    //   octet 2: 0x65>>2 | (0x10 & 0x07)<<5   = 0x19
    //   octet 3: 0x10>>3                      = 0x02
    //
    // Four septets, three characters.
    let submit = decode_submit("01 2a 08 91 51 55 10 00 00 00 04 e1 4d 19 02");
    assert_eq!(submit.tp_user_data, "a€Δ".as_bytes());

    // c=0x63 a=0x61 f=0x66 and e with acute accent = 0x05: E3 B0 B9 00.
    let submit = decode_submit("01 2a 08 91 51 55 10 00 00 00 04 e3 b0 b9 00");
    assert_eq!(submit.tp_user_data, "café".as_bytes());
}

#[test]
fn spare_bits_are_zero_as_clause_6_1_2_1_1_draws_them() {
    // "one character in one octet: 0 1a 1b 1c 1d 1e 1f 1g".
    assert_eq!(pack_gsm7("a").expect("pack"), (vec![0x61], 1));
    // Nine septets leave one spare bit in the eighth octet. '9' = 0x39 is the
    // last septet and fills bits 0-6 of that octet, bit 7 stays clear.
    assert_eq!(
        pack_gsm7("123456789").expect("pack"),
        (octets("31 d9 8c 56 b3 dd 70 39"), 9)
    );
    // "seven characters in seven octets": the last octet is 0000000 7a.
    assert_eq!(
        pack_gsm7("1234567").expect("pack"),
        (octets("31 d9 8c 56 b3 dd 00"), 7)
    );
}

#[test]
fn unpacking_stops_at_the_septet_count() {
    // Seven septets in seven octets leave seven spare bits. A sender that
    // fills them with CR (0x0D), as the USSD rule of §6.1.2.3.1 has it, must
    // not hand us an eighth character: TP-UDL says seven.
    assert_eq!(
        unpack_gsm7(&octets("31 d9 8c 56 b3 dd 1a"), 7).expect("unpack"),
        "1234567"
    );
    // Nor may zero fill turn into a trailing '@' (septet 0x00)...
    assert_eq!(
        unpack_gsm7(&octets("31 d9 8c 56 b3 dd 00"), 7).expect("unpack"),
        "1234567"
    );
    // ...while a real '@' as the eighth septet is kept.
    assert_eq!(
        unpack_gsm7(&octets("31 d9 8c 56 b3 dd 00"), 8).expect("unpack"),
        "1234567@"
    );
    // Too few octets for the count is an error, not a shorter text.
    assert!(unpack_gsm7(&octets("31 d9 8c"), 7).is_err());
}

#[test]
fn an_escape_the_extension_table_does_not_define_falls_back() {
    // §6.2.1.1: for a code with no symbol in the extension table "the MS
    // shall display ... the character shown in the main GSM 7 bit default
    // alphabet table". Escape then 0x61: 0x1B | (0x61 & 1)<<7 = 0x9B,
    // 0x61>>1 = 0x30.
    assert_eq!(unpack_gsm7(&octets("9b 30"), 2).expect("unpack"), "a");
    // A lone escape as the last septet reads as a space (§6.2.1 NOTE 1).
    assert_eq!(unpack_gsm7(&octets("1b"), 1).expect("unpack"), " ");
    // Escape escape is "reserved for the extension to another extension
    // table" and displays a space: a=0x61, 0x1B, 0x1B, b=0x62 pack to
    // E1 CD 46 0C.
    assert_eq!(
        unpack_gsm7(&octets("e1 cd 46 0c"), 4).expect("unpack"),
        "a b"
    );
}

#[test]
fn ucs2_and_8_bit_text_behind_a_header_count_octets() {
    // §9.2.3.24: "If 16 bit (USC2) data is used then padding octets are not
    // necessary." / "If 8 bit data is used then padding is not necessary."
    // TP-UDL is the header octets plus the data octets (§9.2.3.16).
    //
    // UCS2: 6 header octets + "hi" as 00 68 00 69 = 10.
    let submit = decode_submit("41 2a 08 91 51 55 10 00 00 08 0a 05 00 03 2a 02 01 00 68 00 69");
    assert_eq!(submit.tp_user_data, octets("05 00 03 2a 02 01 00 68 00 69"));
    assert_eq!(
        submit
            .tp_user_data_header
            .map(|h| h.user_data_header_length),
        Some(5)
    );
    // 8-bit: 6 header octets + "hi" = 8.
    let submit = decode_submit("41 2a 08 91 51 55 10 00 00 04 08 05 00 03 2a 02 01 68 69");
    assert_eq!(submit.tp_user_data, octets("05 00 03 2a 02 01 68 69"));
}

#[test]
fn encode_refuses_a_length_that_contradicts_the_user_data() {
    let deliver = |dcs: u8, length: u8, user_data: &str| {
        SmsDeliver::builder(originator())
            .dcs(dcs)
            .service_centre_timestamp("26081712000000")
            .user_data(octets(user_data))
            .user_data_length(length)
            .build()
            .expect("build")
            .encode()
    };
    // Ten septets are nine octets: right.
    assert!(deliver(0x00, 10, "e8 32 9b fd 46 97 d9 ec 37").is_ok());
    // Counting the nine packed octets as the length would cut off a character.
    assert!(deliver(0x00, 9, "e8 32 9b fd 46 97 d9 ec 37").is_err());
    // The same for a 7-bit coding with a message class.
    assert!(deliver(0xf1, 10, "e8 32 9b fd 46 97 d9 ec 37").is_ok());
    assert!(deliver(0xf1, 9, "e8 32 9b fd 46 97 d9 ec 37").is_err());
    // 8-bit and UCS2 count octets.
    assert!(deliver(0x04, 2, "68 69").is_ok());
    assert!(deliver(0x04, 3, "68 69").is_err());
    assert!(deliver(0x08, 4, "00 68 00 69").is_ok());
    assert!(deliver(0x08, 2, "00 68 00 69").is_err());
}

fn deliver_in_rp_data(deliver: SmsDeliver) -> Vec<u8> {
    RpDataNetworkToMs::builder(deliver)
        .message_reference(3)
        .originator_address(SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550199".into(),
        })
        .build()
        .encode()
        .expect("encode")
}

#[test]
fn wireshark_reads_7_bit_text_behind_a_header() {
    let header = UserDataHeader {
        user_data_header_length: 5,
        user_data_header_value: vec![0x00, 0x03, 0x2a, 0x02, 0x01],
    };
    let deliver = SmsDeliver::builder(originator())
        .udhi(true)
        .mms(true)
        .dcs(0)
        .service_centre_timestamp("26081712000000")
        .gsm7_text_with_header(&header, "hello")
        .build()
        .expect("build");
    let tpdu = deliver.encode().expect("encode");
    // The TP-UD our encoder emitted is the hand-derived vector.
    assert!(tpdu.ends_with(&octets(&format!("0c {HEADER_AND_HELLO}"))));

    support::assert_dissects(
        &deliver_in_rp_data(deliver),
        &[
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.tp-udhi", "True"),
            ("gsm_sms.tp-dcs", "0"),
            ("gsm_sms.tp.user_data_length", "12"),
            ("gsm_sms.dis_field_udh.user_data_header_length", "5"),
            ("gsm_sms.ie_identifier", "0x00"),
            ("gsm_sms.udh.mm.msg_id", "42"),
            ("gsm_sms.udh.mm.msg_parts", "2"),
            ("gsm_sms.udh.mm.msg_part", "1"),
            ("gsm_sms.dis_field_udh.gsm.fill_bits", "0x00"),
            ("gsm_sms.sms_text", "hello"),
        ],
    );
}

#[test]
fn wireshark_reads_7_bit_text_behind_a_header_that_needs_five_fill_bits() {
    // A lone UDH source indicator is not enough for Wireshark to treat the
    // message as a fragment, so the text shows up directly.
    let header = UserDataHeader {
        user_data_header_length: 8,
        user_data_header_value: vec![0x00, 0x03, 0x2a, 0x01, 0x01, 0x07, 0x01, 0x01],
    };
    let deliver = SmsDeliver::builder(originator())
        .udhi(true)
        .dcs(0)
        .service_centre_timestamp("26081712000000")
        .gsm7_text_with_header(&header, "hi")
        .build()
        .expect("build");
    support::assert_dissects(
        &deliver_in_rp_data(deliver),
        &[
            ("gsm_sms.tp.user_data_length", "13"),
            ("gsm_sms.dis_field_udh.user_data_header_length", "8"),
            ("gsm_sms.sms_text", "hi"),
        ],
    );
}

#[test]
fn wireshark_reads_7_bit_text_with_a_message_class() {
    for (dcs, class) in [(0x10u8, "0x00"), (0xf1, "0x01")] {
        let deliver = SmsDeliver::builder(originator())
            .dcs(dcs)
            .service_centre_timestamp("26081712000000")
            .gsm7_text("hellohello")
            .build()
            .expect("build");
        support::assert_dissects(
            &deliver_in_rp_data(deliver),
            &[
                ("gsm_sms.tp-dcs", &dcs.to_string()),
                ("gsm_sms.dcs.message_class", class),
                ("gsm_sms.tp.user_data_length", "10"),
                ("gsm_sms.sms_text", "hellohello"),
            ],
        );
    }
}

#[test]
fn wireshark_reads_ucs2_and_8_bit_data_behind_a_header() {
    let header = octets("05 00 03 2a 01 01");
    // UCS2: "hi" preceded by the header, TP-UDL 10 octets.
    let deliver = SmsDeliver::builder(originator())
        .udhi(true)
        .dcs(0x08)
        .service_centre_timestamp("26081712000000")
        .user_data([header.as_slice(), &octets("00 68 00 69")].concat())
        .user_data_length(10)
        .build()
        .expect("build");
    support::assert_dissects(
        &deliver_in_rp_data(deliver),
        &[
            ("gsm_sms.tp-udhi", "True"),
            ("gsm_sms.tp.user_data_length", "10"),
            ("gsm_sms.dis_field_udh.user_data_header_length", "5"),
            ("gsm_sms.sms_text", "hi"),
        ],
    );
    // 8-bit: an application port header (IEI 05, 16-bit ports 16000 and
    // 16001, which no dissector claims) in front of two octets, TP-UDL 9.
    let deliver = SmsDeliver::builder(originator())
        .udhi(true)
        .dcs(0x04)
        .service_centre_timestamp("26081712000000")
        .user_data(octets("06 05 04 3e 80 3e 81 68 69"))
        .user_data_length(9)
        .build()
        .expect("build");
    support::assert_dissects(
        &deliver_in_rp_data(deliver),
        &[
            ("gsm_sms.tp.user_data_length", "9"),
            ("gsm_sms.dis_field_udh.user_data_header_length", "6"),
            ("gsm_sms.ie_identifier", "0x05"),
            ("gsm_sms.destination_port", "16000"),
            ("gsm_sms.originator_port", "16001"),
        ],
    );
}

#[test]
fn wireshark_reads_the_spare_bit_free_packing() {
    // Nine septets, the count that used to leave a stray bit in the last
    // octet. Wireshark goes by TP-UDL and reads the text either way, so the
    // literal vector above is what pins the bit; this shows the corrected
    // bytes are still the same message to a third party.
    let deliver = SmsDeliver::builder(originator())
        .dcs(0)
        .service_centre_timestamp("26081712000000")
        .gsm7_text("123456789")
        .build()
        .expect("build");
    support::assert_dissects(
        &deliver_in_rp_data(deliver),
        &[
            ("gsm_sms.tp.user_data_length", "9"),
            ("gsm_sms.sms_text", "123456789"),
        ],
    );
}

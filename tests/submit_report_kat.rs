//! Known-answer vectors for SMS-SUBMIT-REPORT and the RP-ACK that carries it.
//!
//! Written out by hand from TS 23.040 §9.2.2.2a / §9.2.3.27 and TS 24.011
//! §7.3.3, and read back by Wireshark (see `support`).

mod support;

use tpdu::{RpAck, SmsSubmitReport, FAILURE_CAUSE_UNSPECIFIED};

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

/// 2025-01-01 12:00:00 at GMT, which goes on the wire as 52 10 10 21 00 00 00.
const SCTS_DIGITS: &str = "25010112000000";

/// SMS-SUBMIT-REPORT for RP-ACK with every optional parameter (§9.2.2.2a
/// (ii), §9.2.3.27): first octet 0x01 (TP-MTI 01), TP-PI 0x07 (TP-UDL, TP-DCS
/// and TP-PID present), TP-SCTS, TP-PID 0x00, TP-DCS 0x00, TP-UDL 2 septets,
/// "hi" packed as E8 34 (h=0x68 | (i & 1)<<7 = 0xE8, i>>1 = 0x34).
const WITH_PARAMETERS: &str = "01 07 52 10 10 21 00 00 00 00 00 02 e8 34";

/// SMS-SUBMIT-REPORT for RP-ERROR (§9.2.2.2a (i)): TP-FCS 0xC3 "Invalid SME
/// address" sits between the first octet and TP-PI.
const FOR_RP_ERROR: &str = "01 c3 00 52 10 10 21 00 00 00";

#[test]
fn optional_parameters_follow_the_time_stamp() {
    let report = SmsSubmitReport::decode_for_rp_ack(&octets(WITH_PARAMETERS)).expect("decode");
    assert_eq!(report.tp_failure_cause, None);
    assert_eq!(report.tp_parameter_indicator, 0x07);
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);
    assert_eq!(report.tp_pid, Some(0));
    assert_eq!(report.tp_dcs, Some(0));
    assert_eq!(report.tp_user_data_length, Some(2));
    assert_eq!(report.tp_user_data, octets("e8 34"));
    assert_eq!(report.encode().expect("encode"), octets(WITH_PARAMETERS));

    // TP-UDL without TP-DCS: "the receiving entity shall for TP-DCS assume a
    // value of 0x00, i.e. the 7bit default alphabet", so 2 is two septets.
    let report = SmsSubmitReport::decode_for_rp_ack(&octets("01 04 52 10 10 21 00 00 00 02 e8 34"))
        .expect("decode");
    assert_eq!(report.tp_dcs, None);
    assert_eq!(report.tp_user_data, octets("e8 34"));
}

#[test]
fn the_failure_cause_sits_between_the_first_octet_and_the_indicator() {
    let report = SmsSubmitReport::decode_for_rp_error(&octets(FOR_RP_ERROR)).expect("decode");
    assert_eq!(report.tp_failure_cause, Some(0xc3));
    assert_eq!(report.tp_parameter_indicator, 0);
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);

    let built = SmsSubmitReport::builder()
        .failure_cause(0xc3)
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    assert_eq!(built.encode().expect("encode"), octets(FOR_RP_ERROR));
}

#[test]
fn unused_first_octet_bits_make_the_cause_unspecified() {
    // §9.2.2.2a (i): "Bits 7 and 5 - 2 in octet 1 are presently unused ... If
    // any of these bits is non-zero, the receiver shall not examine the other
    // field and shall treat the TP-Failure-Cause as 'Unspecified error
    // cause'." 0x85 has bit 7 and bit 2 set.
    let report = SmsSubmitReport::decode_for_rp_error(&octets("85 c3 00 52 10 10 21 00 00 00"))
        .expect("decode");
    assert_eq!(report.tp_failure_cause, Some(FAILURE_CAUSE_UNSPECIFIED));
    // (ii), the RP-ACK layout: "the receiver shall ignore them".
    let report =
        SmsSubmitReport::decode_for_rp_ack(&octets("85 00 52 10 10 21 00 00 00")).expect("decode");
    assert_eq!(report.tp_failure_cause, None);
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);
}

#[test]
fn an_indicator_that_disagrees_with_the_parameters_is_refused() {
    // TP-PI announces a TP-PID that is not supplied: the receiver would read
    // the next octet as one.
    let report = SmsSubmitReport::builder()
        .parameter_indicator(0x01)
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    assert!(report.encode().is_err());
    // And the other way round.
    let report = SmsSubmitReport::builder()
        .pid(0)
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    assert!(report.encode().is_err());
}

/// TS 24.011 table 7.7: RP-Message-Type 3, RP-Message-Reference 7,
/// RP-User-Data (IEI 0x41, length 9) holding the SMS-SUBMIT-REPORT for RP-ACK:
/// first octet 0x01, TP-PI 0x00, TP-SCTS.
const RP_ACK: &str = "03 07 41 09 01 00 52 10 10 21 00 00 00";

#[test]
fn rp_ack_from_the_builder_has_the_right_user_data_length() {
    let report = SmsSubmitReport::builder()
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    let ack = RpAck::builder(report).message_reference(7).build();
    assert_eq!(ack.rp_user_data_element_length, 9);
    assert_eq!(ack.encode().expect("encode"), octets(RP_ACK));
}

#[test]
fn rp_ack_refuses_what_it_cannot_put_on_the_wire() {
    let report = SmsSubmitReport::builder()
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    // A length other than the report's.
    let ack = RpAck::builder(report.clone())
        .user_data_element_length(0)
        .build();
    assert!(ack.encode().is_err());
    // An element identifier other than RP-User-Data.
    let ack = RpAck::builder(report.clone())
        .user_data_element_id(0x42)
        .build();
    assert!(ack.encode().is_err());
    // The report layout that belongs in an RP-ERROR.
    let failure = SmsSubmitReport::decode_for_rp_error(&octets(FOR_RP_ERROR)).expect("decode");
    assert!(RpAck::builder(failure).build().encode().is_err());
    // A report whose time stamp cannot be encoded.
    let no_time = SmsSubmitReport::builder().build();
    assert!(RpAck::builder(no_time).build().encode().is_err());
}

#[test]
fn wireshark_reads_rp_ack() {
    let report = SmsSubmitReport::builder()
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    let wire = RpAck::builder(report)
        .message_reference(7)
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x03"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.elem_id", "0x41"),
            ("gsm_sms.tp-mti", "1"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp.parameter_indicator", "0x00"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
        ],
    );
}

#[test]
fn wireshark_reads_rp_ack_with_optional_parameters() {
    let report = SmsSubmitReport::decode_for_rp_ack(&octets(WITH_PARAMETERS)).expect("decode");
    let wire = RpAck::builder(report)
        .message_reference(7)
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x03"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_sms.tp-mti", "1"),
            ("gsm_sms.tp.parameter_indicator", "0x07"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
            ("gsm_sms.tp-pid", "0"),
            ("gsm_sms.tp-dcs", "0"),
            ("gsm_sms.tp.user_data_length", "2"),
            ("gsm_sms.sms_text", "hi"),
        ],
    );
}

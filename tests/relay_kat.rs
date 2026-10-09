//! Known-answer vectors for RP-ERROR, RP-SMMA, SMS-STATUS-REPORT and
//! SMS-DELIVER-REPORT.
//!
//! Every vector is written out by hand from TS 24.011 §7.3 / §8.2 and TS 23.040
//! §9.2.2, so the decoders meet bytes this crate did not produce and the
//! encoders have to reproduce them. What the encoders emit is then read back by
//! Wireshark (see `support`).
//!
//! RP-Message-Type, TS 24.011 table 8.3: 0 RP-DATA ms->n, 1 RP-DATA n->ms,
//! 2 RP-ACK ms->n, 3 RP-ACK n->ms, 4 RP-ERROR ms->n, 5 RP-ERROR n->ms,
//! 6 RP-SMMA ms->n.
//!
//! All numbers are fictional (555-01xx).

mod support;

use tpdu::{
    parse_rp_data_network_to_ms, RpDataNetworkToMsMessage, RpDataNetworkToMsStatusReport,
    RpErrorMsToNetwork, RpErrorNetworkToMs, RpSmma, SMSAddress, SmsDeliver, SmsDeliverReport,
    SmsStatusReport, SmsSubmitReport, FAILURE_CAUSE_UNSPECIFIED,
};

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

/// 2025-01-01 12:00:00 at GMT. Each pair of digits is swapped into one octet:
/// 52 10 10 21 00 00 00.
const SCTS_DIGITS: &str = "25010112000000";
/// Five seconds later: 52 10 10 21 00 50 00.
const DISCHARGE_DIGITS: &str = "25010112000500";

// ── RP-ERROR, network to mobile station ──────────────────────────────────────

/// TS 24.011 table 7.8: RP-Message-Type 5, RP-Message-Reference 7, RP-Cause
/// as LV (length 1, cause 21 "Short message transfer rejected" = 0x15), then
/// RP-User-Data as TLV (IEI 0x41, length 10) holding the SMS-SUBMIT-REPORT for
/// RP-ERROR of TS 23.040 §9.2.2.2a: first octet 0x01 (TP-MTI 01), TP-FCS 0xC3
/// "Invalid SME address", TP-PI 0x00, TP-SCTS.
const RP_ERROR_TO_MS: &str = "05 07 01 15 41 0a 01 c3 00 52 10 10 21 00 00 00";

fn submit_report_for_rp_error() -> SmsSubmitReport {
    SmsSubmitReport::builder()
        .failure_cause(0xc3)
        .service_centre_timestamp(SCTS_DIGITS)
        .build()
}

#[test]
fn rp_error_to_the_mobile_station_encodes_to_the_hand_built_bytes() {
    let error = RpErrorNetworkToMs::builder(21)
        .message_reference(7)
        .sms_submit_report(submit_report_for_rp_error())
        .build();
    assert_eq!(error.encode().expect("encode"), octets(RP_ERROR_TO_MS));
}

#[test]
fn rp_error_to_the_mobile_station_decodes() {
    let error = RpErrorNetworkToMs::decode(&octets(RP_ERROR_TO_MS)).expect("decode");
    assert_eq!(error.rp_message_type, 5);
    assert_eq!(error.rp_message_reference, 7);
    assert_eq!(error.rp_cause, 21);
    assert_eq!(error.rp_diagnostic, None);
    let report = error.sms_submit_report.expect("SMS-SUBMIT-REPORT");
    assert_eq!(report.tp_failure_cause, Some(0xc3));
    assert_eq!(report.tp_parameter_indicator, 0);
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);
}

#[test]
fn rp_error_with_a_diagnostic_and_no_user_data() {
    // RP-Cause of length 2: cause 111 "Protocol error, unspecified" = 0x6F,
    // then one diagnostic octet. RP-User-Data is optional and absent.
    let wire = octets("05 2a 02 6f 01");
    let error = RpErrorNetworkToMs::decode(&wire).expect("decode");
    assert_eq!(error.rp_message_reference, 0x2a);
    assert_eq!(error.rp_cause, 111);
    assert_eq!(error.rp_diagnostic, Some(1));
    assert_eq!(error.sms_submit_report, None);

    let built = RpErrorNetworkToMs::builder(111)
        .message_reference(0x2a)
        .diagnostic(1)
        .build();
    assert_eq!(built.encode().expect("encode"), wire);
}

#[test]
fn rp_error_refuses_what_it_cannot_put_on_the_wire() {
    // The cause value has seven bits (figure 8.8, "0 ext | Cause value").
    assert!(RpErrorNetworkToMs::builder(0x80).build().encode().is_err());
    // An RP-ERROR carries the report layout that has a TP-Failure-Cause.
    let without_cause = SmsSubmitReport::builder()
        .service_centre_timestamp(SCTS_DIGITS)
        .build();
    assert!(RpErrorNetworkToMs::builder(21)
        .sms_submit_report(without_cause)
        .build()
        .encode()
        .is_err());
    // And the message type is the one for this direction.
    assert!(RpErrorNetworkToMs::builder(21)
        .message_type(4)
        .build()
        .encode()
        .is_err());
    assert!(RpErrorNetworkToMs::decode(&octets("04 07 01 16")).is_err());
}

#[test]
fn wireshark_reads_rp_error_to_the_mobile_station() {
    let wire = RpErrorNetworkToMs::builder(21)
        .message_reference(7)
        .sms_submit_report(submit_report_for_rp_error())
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x05"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.cause", "21"),
            ("gsm_a.rp.elem_id", "0x41"),
            ("gsm_sms.tp-mti", "1"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp-fcs", "0xc3"),
            ("gsm_sms.tp.parameter_indicator", "0x00"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
        ],
    );

    let wire = RpErrorNetworkToMs::builder(111)
        .message_reference(0x2a)
        .diagnostic(1)
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x05"),
            ("gsm_a.rp.rp_message_reference", "0x2a"),
            ("gsm_a.rp.cause", "111"),
            ("gsm_a.rp.diagnostic_field", "01"),
        ],
    );
}

// ── RP-ERROR, mobile station to network ──────────────────────────────────────

/// RP-Message-Type 4, RP-Message-Reference 7, RP-Cause of length 2 (cause 22
/// "Memory capacity exceeded" = 0x16, diagnostic 0x00), RP-User-Data (IEI
/// 0x41, length 3) holding the SMS-DELIVER-REPORT for RP-ERROR of TS 23.040
/// §9.2.2.1a: first octet 0x00 (TP-MTI 00), TP-FCS 0xD3 "Memory Capacity
/// Exceeded", TP-PI 0x00.
const RP_ERROR_FROM_MS: &str = "04 07 02 16 00 41 03 00 d3 00";

#[test]
fn rp_error_from_the_mobile_station_decodes() {
    let error = RpErrorMsToNetwork::decode(&octets(RP_ERROR_FROM_MS)).expect("decode");
    assert_eq!(error.rp_message_type, 4);
    assert_eq!(error.rp_message_reference, 7);
    assert_eq!(error.rp_cause, 22);
    assert_eq!(error.rp_diagnostic, Some(0));
    assert_eq!(
        error.sms_deliver_report,
        Some(SmsDeliverReport {
            tp_udhi: false,
            tp_failure_cause: Some(0xd3),
            tp_parameter_indicator: 0,
            tp_pid: None,
            tp_dcs: None,
            tp_user_data_length: None,
            tp_user_data: Vec::new(),
        })
    );

    // The shortest form: the cause alone.
    let error = RpErrorMsToNetwork::decode(&octets("04 07 01 16")).expect("decode");
    assert_eq!(error.rp_cause, 22);
    assert_eq!(error.rp_diagnostic, None);
    assert_eq!(error.sms_deliver_report, None);
}

#[test]
fn rp_error_from_the_mobile_station_encodes_to_the_hand_built_bytes() {
    let error = RpErrorMsToNetwork::builder(22)
        .message_reference(7)
        .diagnostic(0)
        .sms_deliver_report(SmsDeliverReport::builder().failure_cause(0xd3).build())
        .build();
    assert_eq!(error.encode().expect("encode"), octets(RP_ERROR_FROM_MS));

    let bare = RpErrorMsToNetwork::builder(22).message_reference(7).build();
    assert_eq!(bare.encode().expect("encode"), octets("04 07 01 16"));
}

#[test]
fn the_extension_bit_of_the_cause_octet_is_not_part_of_the_cause() {
    // Figure 8.8: bit 8 of the cause octet is "0 ext". A peer that sets it
    // still means cause 22.
    let error = RpErrorMsToNetwork::decode(&octets("04 07 01 96")).expect("decode");
    assert_eq!(error.rp_cause, 22);
}

#[test]
fn wireshark_reads_rp_error_from_the_mobile_station() {
    let wire = RpErrorMsToNetwork::builder(22)
        .message_reference(7)
        .diagnostic(0)
        .sms_deliver_report(SmsDeliverReport::builder().failure_cause(0xd3).build())
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x04"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.cause", "22"),
            ("gsm_a.rp.diagnostic_field", "00"),
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.tp-fcs", "0xd3"),
            ("gsm_sms.tp.parameter_indicator", "0x00"),
        ],
    );
}

// ── SMS-DELIVER-REPORT ───────────────────────────────────────────────────────

#[test]
fn deliver_report_layouts() {
    // For RP-ACK (§9.2.2.1a (ii)): first octet and TP-PI, nothing else.
    let report = SmsDeliverReport::decode_for_rp_ack(&octets("00 00")).expect("decode");
    assert_eq!(report.tp_failure_cause, None);
    assert_eq!(report.encode().expect("encode"), octets("00 00"));
    // With TP-UDHI (bit 6) and a TP-PID (TP-PI bit 0): 0x40, 0x01, 0x7F.
    let report = SmsDeliverReport::decode_for_rp_ack(&octets("40 01 7f")).expect("decode");
    assert!(report.tp_udhi);
    assert_eq!(report.tp_pid, Some(0x7f));
    assert_eq!(report.encode().expect("encode"), octets("40 01 7f"));
    // For RP-ERROR (i): TP-FCS sits between the first octet and TP-PI.
    let report = SmsDeliverReport::decode_for_rp_error(&octets("00 d3 00")).expect("decode");
    assert_eq!(report.tp_failure_cause, Some(0xd3));
    assert_eq!(report.encode().expect("encode"), octets("00 d3 00"));
    // §9.2.2.1a (i): with an unused bit of the first octet set (here bit 7 and
    // bit 2) the receiver "shall not examine the other field and shall treat
    // the TP-Failure-Cause as 'Unspecified error cause'".
    let report = SmsDeliverReport::decode_for_rp_error(&octets("84 d3 00")).expect("decode");
    assert_eq!(report.tp_failure_cause, Some(FAILURE_CAUSE_UNSPECIFIED));
    // A TP-PI that announces a TP-PID which is not supplied is refused.
    assert!(SmsDeliverReport::builder()
        .parameter_indicator(0x01)
        .build()
        .encode()
        .is_err());
}

// ── RP-SMMA ──────────────────────────────────────────────────────────────────

#[test]
fn rp_smma_is_two_octets() {
    // TS 24.011 table 7.6: RP-Message-Type 6 and RP-Message-Reference.
    let smma = RpSmma::decode(&octets("06 09")).expect("decode");
    assert_eq!(smma.rp_message_type, 6);
    assert_eq!(smma.rp_message_reference, 9);
    assert_eq!(
        RpSmma::builder()
            .message_reference(9)
            .build()
            .encode()
            .expect("encode"),
        octets("06 09")
    );
    assert!(RpSmma::decode(&octets("02 09")).is_err());
    assert!(RpSmma::decode(&octets("06")).is_err());
}

#[test]
fn wireshark_reads_rp_smma() {
    let wire = RpSmma::builder()
        .message_reference(9)
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x06"),
            ("gsm_a.rp.rp_message_reference", "0x09"),
        ],
    );
}

// ── SMS-STATUS-REPORT ────────────────────────────────────────────────────────

/// TS 23.040 §9.2.2.3. First octet 0x06: TP-MTI 10, TP-MMS (bit 2) set, and
/// TP-LP (bit 3), TP-SRQ (bit 5), TP-UDHI (bit 6) clear. TP-MR 0x2A. TP-RA:
/// 8 digits, international E.164, 15550100. TP-SCTS, TP-DT, then TP-ST 0x00
/// "Short message received by the SME". No TP-PI.
const STATUS_REPORT: &str = "06 2a 08 91 51 55 10 00 52 10 10 21 00 00 00 52 10 10 21 00 50 00 00";

/// The same report about an SMS-COMMAND that the service centre gave up on:
/// first octet 0x2E adds TP-SRQ (bit 5) and TP-LP (bit 3); TP-ST 0x46 "SM
/// Validity Period Expired"; TP-PI 0x07 followed by TP-PID 0x00, TP-DCS 0x00,
/// TP-UDL 2 septets and "hi" packed as E8 34.
const STATUS_REPORT_WITH_PARAMETERS: &str =
    "2e 2a 08 91 51 55 10 00 52 10 10 21 00 00 00 52 10 10 21 00 50 00 46 07 00 00 02 e8 34";

fn status_report() -> SmsStatusReport {
    SmsStatusReport::builder(address("15550100"))
        .mms(true)
        .mr(0x2a)
        .service_centre_timestamp(SCTS_DIGITS)
        .discharge_time(DISCHARGE_DIGITS)
        .status(0x00)
        .build()
}

#[test]
fn status_report_encodes_to_the_hand_built_bytes() {
    assert_eq!(
        status_report().encode().expect("encode"),
        octets(STATUS_REPORT)
    );

    let with_parameters = SmsStatusReport::builder(address("15550100"))
        .srq(true)
        .lp(true)
        .mms(true)
        .mr(0x2a)
        .service_centre_timestamp(SCTS_DIGITS)
        .discharge_time(DISCHARGE_DIGITS)
        .status(0x46)
        .parameter_indicator(0x07)
        .pid(0)
        .dcs(0)
        .user_data_length(2)
        .user_data(octets("e8 34"))
        .build();
    assert_eq!(
        with_parameters.encode().expect("encode"),
        octets(STATUS_REPORT_WITH_PARAMETERS)
    );
}

#[test]
fn status_report_decodes() {
    let report = SmsStatusReport::decode(&octets(STATUS_REPORT)).expect("decode");
    assert_eq!(report, status_report());
    assert!(report.tp_mms && !report.tp_lp && !report.tp_srq && !report.tp_udhi);
    assert_eq!(report.tp_mr, 0x2a);
    assert_eq!(report.tp_recipient_address, address("15550100"));
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);
    assert_eq!(report.tp_discharge_time, DISCHARGE_DIGITS);
    assert_eq!(report.tp_status, 0);
    assert_eq!(report.tp_parameter_indicator, None);

    let report = SmsStatusReport::decode(&octets(STATUS_REPORT_WITH_PARAMETERS)).expect("decode");
    assert!(report.tp_mms && report.tp_lp && report.tp_srq && !report.tp_udhi);
    assert_eq!(report.tp_status, 0x46);
    assert_eq!(report.tp_parameter_indicator, Some(0x07));
    assert_eq!(report.tp_pid, Some(0));
    assert_eq!(report.tp_dcs, Some(0));
    assert_eq!(report.tp_user_data_length, Some(2));
    assert_eq!(report.tp_user_data, octets("e8 34"));

    // TP-MTI 00 is an SMS-DELIVER, not a status report.
    assert!(SmsStatusReport::decode(&octets("04 2a 00 80")).is_err());
}

/// RP-DATA network to MS (TS 24.011 table 7.4): type 1, RP-MR 5, RP-OA as LV
/// (length 5: type 0x91 and 15550199 as 51 55 10 99), empty RP-DA, then
/// RP-User-Data as LV: 0x17 = 23 octets of the status report above.
fn status_report_in_rp_data() -> Vec<u8> {
    octets(&format!("01 05 05 91 51 55 10 99 00 17 {STATUS_REPORT}"))
}

#[test]
fn rp_data_carrying_a_status_report_encodes_to_the_hand_built_bytes() {
    let rp = RpDataNetworkToMsStatusReport::builder(status_report())
        .message_reference(5)
        .originator_address(address("15550199"))
        .build();
    assert_eq!(rp.encode().expect("encode"), status_report_in_rp_data());
}

#[test]
fn rp_data_from_the_network_is_told_apart_by_its_tp_mti() {
    match parse_rp_data_network_to_ms(&status_report_in_rp_data()).expect("parse") {
        RpDataNetworkToMsMessage::StatusReport(rp) => {
            assert_eq!(rp.rp_message_type, 1);
            assert_eq!(rp.rp_message_reference, 5);
            assert_eq!(rp.rp_originator_address, Some(address("15550199")));
            assert_eq!(rp.rp_destination_address, None);
            assert_eq!(rp.sms_status_report, status_report());
        }
        other => panic!("expected a status report, got {other:?}"),
    }

    // An SMS-DELIVER (§9.2.2.1) in the same wrapper. First octet 0x24: TP-SRI
    // (bit 5) and TP-MMS (bit 2), TP-MTI 00. TP-OA 15550101. TP-PID 0x00,
    // TP-DCS 0x00, TP-SCTS, TP-UDL 5 septets, "hello" = E8 32 9B FD 06.
    // 1 + 6 + 1 + 1 + 7 + 1 + 5 = 22 = 0x16 octets.
    let wire = octets(
        "01 06 05 91 51 55 10 99 00 16 \
         24 08 91 51 55 10 10 00 00 52 10 10 21 00 00 00 05 e8 32 9b fd 06",
    );
    match parse_rp_data_network_to_ms(&wire).expect("parse") {
        RpDataNetworkToMsMessage::Deliver(rp) => {
            assert_eq!(rp.rp_message_reference, 6);
            let deliver: &SmsDeliver = &rp.sms_deliver;
            assert!(deliver.tp_sri && deliver.tp_mms);
            assert!(!deliver.tp_rp && !deliver.tp_udhi && !deliver.tp_lp);
            assert_eq!(deliver.tp_originating_address, address("15550101"));
            assert_eq!(deliver.tp_service_centre_timestamp, SCTS_DIGITS);
            assert_eq!(deliver.tp_user_data_length, 5);
            assert_eq!(deliver.tp_user_data, octets("e8 32 9b fd 06"));
            // And our encoder puts the same bytes back.
            assert_eq!(rp.encode().expect("encode"), wire);
        }
        other => panic!("expected an SMS-DELIVER, got {other:?}"),
    }

    // RP-DATA in the other direction is not for this parser.
    assert!(parse_rp_data_network_to_ms(&octets("00 01 00 00 00")).is_err());
}

#[test]
fn wireshark_reads_a_status_report() {
    let wire = RpDataNetworkToMsStatusReport::builder(status_report())
        .message_reference(5)
        .originator_address(address("15550199"))
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x01"),
            ("gsm_a.rp.rp_message_reference", "0x05"),
            ("gsm_a.dtap.clg_party_bcd_num", "15550199"),
            ("gsm_sms.tp-mti", "2"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp-srq", "False"),
            ("gsm_sms.tp-lp", "False"),
            ("gsm_sms.tp-mms", "True"),
            ("gsm_sms.tp-mr", "42"),
            ("gsm_sms.tp-ra", "15550100"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
            (
                "gsm_sms.discharge_time",
                "2025-01-01T12:00:05.000000000+0000",
            ),
            // TP-ST 0x00, which Wireshark shows in its three parts: bit 7,
            // the class in bits 6-5 and the reason in bits 4-0.
            ("gsm_sms.dis_field.definition", "False"),
            ("gsm_sms.dis_field.st_error", "0"),
            ("gsm_sms.dis.field_st_reason", "0"),
        ],
    );
}

#[test]
fn wireshark_reads_a_status_report_with_optional_parameters() {
    let report = SmsStatusReport::decode(&octets(STATUS_REPORT_WITH_PARAMETERS)).expect("decode");
    let wire = RpDataNetworkToMsStatusReport::builder(report)
        .originator_address(address("15550199"))
        .build()
        .encode()
        .expect("encode");
    support::assert_dissects(
        &wire,
        &[
            ("gsm_sms.tp-mti", "2"),
            ("gsm_sms.tp-srq", "True"),
            ("gsm_sms.tp-lp", "True"),
            ("gsm_sms.tp-mms", "True"),
            // TP-ST 0x46 = 0 10 00110: permanent error, reason 6.
            ("gsm_sms.dis_field.definition", "False"),
            ("gsm_sms.dis_field.st_error", "2"),
            ("gsm_sms.dis.field_st_reason", "6"),
            ("gsm_sms.tp.parameter_indicator", "0x07"),
            ("gsm_sms.tp-pid", "0"),
            ("gsm_sms.tp-dcs", "0"),
            ("gsm_sms.tp.user_data_length", "2"),
            ("gsm_sms.sms_text", "hi"),
        ],
    );
}

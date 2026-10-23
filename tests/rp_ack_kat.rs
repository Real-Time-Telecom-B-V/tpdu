//! Known-answer vectors for RP-ACK in both directions (TS 24.011 §7.3.3,
//! §8.2).
//!
//! RP-ACK is RP-Message-Type (§8.2.2), RP-Message-Reference (§8.2.3) and an
//! optional RP-User-Data, a TLV with IEI 0x41 (§8.2.5.3) holding the TPDU: an
//! SMS-DELIVER-REPORT from the mobile station, an SMS-SUBMIT-REPORT from the
//! network (table 7.7). Every vector is written out
//! by hand from those clauses and TS 23.040 §9.2.2.1a / §9.2.2.2a, so the
//! decoders meet bytes this crate did not produce and the encoders have to
//! reproduce them. What the encoders emit is then read back by Wireshark (see
//! `support`).

mod support;

use tpdu::{RpAck, RpAckMsToNetwork, RpAckNetworkToMs, SmsDeliverReport, SmsSubmitReport};

fn octets(hex_with_spaces: &str) -> Vec<u8> {
    hex::decode(hex_with_spaces.replace(' ', "")).expect("vector hex")
}

/// 2025-01-01 12:00:00 at GMT: 52 10 10 21 00 00 00 on the wire.
const SCTS_DIGITS: &str = "25010112000000";

// ── RP-ACK, mobile station to network ────────────────────────────────────────

/// RP-Message-Type 2, RP-Message-Reference 7, nothing else.
const ACK_FROM_MS: &str = "02 07";

/// RP-Message-Type 2, RP-Message-Reference 7, RP-User-Data (IEI 0x41, length
/// 2) holding the SMS-DELIVER-REPORT for RP-ACK: first octet 0x00 (TP-MTI 00,
/// TP-UDHI clear), TP-PI 0x00.
const ACK_FROM_MS_WITH_REPORT: &str = "02 07 41 02 00 00";

/// RP-Message-Type 2, RP-Message-Reference 0x2A, RP-User-Data of length 7: an
/// SMS-DELIVER-REPORT with TP-PI 0x07 (TP-UDL, TP-DCS and TP-PID present),
/// TP-PID 0x00, TP-DCS 0x08 (UCS-2), TP-UDL 2 octets, "A" as 00 41.
const ACK_FROM_MS_WITH_PARAMETERS: &str = "02 2a 41 07 00 07 00 08 02 00 41";

fn delivery_report_with_parameters() -> SmsDeliverReport {
    SmsDeliverReport::builder()
        .parameter_indicator(0x07)
        .pid(0x00)
        .dcs(0x08)
        .user_data_length(2)
        .user_data([0x00, 0x41])
        .build()
}

#[test]
fn rp_ack_from_the_mobile_station_without_user_data_encodes_to_the_hand_built_bytes() {
    let ack = RpAckMsToNetwork::builder().message_reference(7).build();
    let wire = ack.encode().expect("encode");
    assert_eq!(wire, octets(ACK_FROM_MS));
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x02"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.elem_id", ""),
        ],
    );
}

#[test]
fn rp_ack_from_the_mobile_station_with_a_report_encodes_to_the_hand_built_bytes() {
    let ack = RpAckMsToNetwork::builder()
        .message_reference(7)
        .sms_deliver_report(SmsDeliverReport::builder().build())
        .build();
    let wire = ack.encode().expect("encode");
    assert_eq!(wire, octets(ACK_FROM_MS_WITH_REPORT));
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x02"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.elem_id", "0x41"),
            ("gsm_a.len", "2"),
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp.parameter_indicator", "0x00"),
        ],
    );
}

#[test]
fn rp_ack_from_the_mobile_station_with_report_parameters_encodes_to_the_hand_built_bytes() {
    let ack = RpAckMsToNetwork::builder()
        .message_reference(0x2a)
        .sms_deliver_report(delivery_report_with_parameters())
        .build();
    let wire = ack.encode().expect("encode");
    assert_eq!(wire, octets(ACK_FROM_MS_WITH_PARAMETERS));
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x02"),
            ("gsm_a.rp.rp_message_reference", "0x2a"),
            ("gsm_a.rp.elem_id", "0x41"),
            ("gsm_a.len", "7"),
            ("gsm_sms.tp-mti", "0"),
            ("gsm_sms.tp.parameter_indicator", "0x07"),
            ("gsm_sms.tp-pid", "0"),
            ("gsm_sms.tp-dcs", "8"),
            ("gsm_sms.sms_text", "A"),
        ],
    );
}

#[test]
fn rp_ack_from_the_mobile_station_decodes() {
    let ack = RpAckMsToNetwork::decode(&octets(ACK_FROM_MS)).expect("decode");
    assert_eq!(ack.rp_message_type, 2);
    assert_eq!(ack.rp_message_reference, 7);
    assert_eq!(ack.sms_deliver_report, None);

    let ack = RpAckMsToNetwork::decode(&octets(ACK_FROM_MS_WITH_REPORT)).expect("decode");
    assert_eq!(ack.rp_message_reference, 7);
    let report = ack.sms_deliver_report.expect("SMS-DELIVER-REPORT");
    assert!(!report.tp_udhi);
    assert_eq!(report.tp_failure_cause, None);
    assert_eq!(report.tp_parameter_indicator, 0);
    assert_eq!(report.tp_user_data, Vec::<u8>::new());

    let ack = RpAckMsToNetwork::decode(&octets(ACK_FROM_MS_WITH_PARAMETERS)).expect("decode");
    assert_eq!(ack.rp_message_reference, 0x2a);
    let report = ack.sms_deliver_report.expect("SMS-DELIVER-REPORT");
    assert_eq!(report.tp_parameter_indicator, 0x07);
    assert_eq!(report.tp_pid, Some(0x00));
    assert_eq!(report.tp_dcs, Some(0x08));
    assert_eq!(report.tp_user_data_length, Some(2));
    assert_eq!(report.tp_user_data, octets("00 41"));
}

// ── RP-ACK, network to mobile station ────────────────────────────────────────

/// RP-Message-Type 3, RP-Message-Reference 7, nothing else.
const ACK_TO_MS: &str = "03 07";

/// RP-Message-Type 3, RP-Message-Reference 7, RP-User-Data (IEI 0x41, length
/// 9) holding the SMS-SUBMIT-REPORT for RP-ACK: first octet 0x01 (TP-MTI 01),
/// TP-PI 0x00, TP-SCTS.
const ACK_TO_MS_WITH_REPORT: &str = "03 07 41 09 01 00 52 10 10 21 00 00 00";

fn submission_report() -> SmsSubmitReport {
    SmsSubmitReport::builder()
        .service_centre_timestamp(SCTS_DIGITS)
        .build()
}

#[test]
fn rp_ack_to_the_mobile_station_without_user_data_encodes_to_the_hand_built_bytes() {
    let ack = RpAckNetworkToMs::builder().message_reference(7).build();
    let wire = ack.encode().expect("encode");
    assert_eq!(wire, octets(ACK_TO_MS));
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x03"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.elem_id", ""),
        ],
    );
}

#[test]
fn rp_ack_to_the_mobile_station_with_a_report_encodes_to_the_hand_built_bytes() {
    let ack = RpAckNetworkToMs::builder()
        .message_reference(7)
        .sms_submit_report(submission_report())
        .build();
    let wire = ack.encode().expect("encode");
    assert_eq!(wire, octets(ACK_TO_MS_WITH_REPORT));
    support::assert_dissects(
        &wire,
        &[
            ("gsm_a.rp.msg_type", "0x03"),
            ("gsm_a.rp.rp_message_reference", "0x07"),
            ("gsm_a.rp.elem_id", "0x41"),
            ("gsm_a.len", "9"),
            ("gsm_sms.tp-mti", "1"),
            ("gsm_sms.tp-udhi", "False"),
            ("gsm_sms.tp.parameter_indicator", "0x00"),
            ("gsm_sms.scts", "2025-01-01T12:00:00.000000000+0000"),
        ],
    );
}

#[test]
fn rp_ack_to_the_mobile_station_decodes() {
    let ack = RpAckNetworkToMs::decode(&octets(ACK_TO_MS)).expect("decode");
    assert_eq!(ack.rp_message_type, 3);
    assert_eq!(ack.rp_message_reference, 7);
    assert_eq!(ack.sms_submit_report, None);

    let ack = RpAckNetworkToMs::decode(&octets(ACK_TO_MS_WITH_REPORT)).expect("decode");
    assert_eq!(ack.rp_message_reference, 7);
    let report = ack.sms_submit_report.expect("SMS-SUBMIT-REPORT");
    assert_eq!(report.tp_failure_cause, None);
    assert_eq!(report.tp_parameter_indicator, 0);
    assert_eq!(report.tp_service_centre_timestamp, SCTS_DIGITS);
}

#[test]
fn the_older_rp_ack_type_encodes_the_same_bytes() {
    let ack = RpAck::builder(submission_report())
        .message_reference(7)
        .build();
    let converted = RpAckNetworkToMs::from(ack.clone());
    assert_eq!(
        converted.encode().expect("encode"),
        ack.encode().expect("encode")
    );
    assert_eq!(
        converted.encode().expect("encode"),
        octets(ACK_TO_MS_WITH_REPORT)
    );
}

// ── Round trips (in addition to the vectors above) ───────────────────────────

#[test]
fn rp_acks_survive_a_round_trip() {
    for ack in [
        RpAckMsToNetwork::builder().message_reference(0xff).build(),
        RpAckMsToNetwork::builder()
            .message_reference(1)
            .sms_deliver_report(delivery_report_with_parameters())
            .build(),
    ] {
        let wire = ack.encode().expect("encode");
        assert_eq!(RpAckMsToNetwork::decode(&wire).expect("decode"), ack);
    }
    for ack in [
        RpAckNetworkToMs::builder().message_reference(0).build(),
        RpAckNetworkToMs::builder()
            .message_reference(200)
            .sms_submit_report(submission_report())
            .build(),
    ] {
        let wire = ack.encode().expect("encode");
        assert_eq!(RpAckNetworkToMs::decode(&wire).expect("decode"), ack);
    }
}

// ── What the decoders turn down ──────────────────────────────────────────────

#[test]
fn an_rp_ack_for_the_other_direction_is_refused() {
    assert!(RpAckMsToNetwork::decode(&octets(ACK_TO_MS)).is_err());
    assert!(RpAckMsToNetwork::decode(&octets(ACK_TO_MS_WITH_REPORT)).is_err());
    assert!(RpAckNetworkToMs::decode(&octets(ACK_FROM_MS)).is_err());
    assert!(RpAckNetworkToMs::decode(&octets(ACK_FROM_MS_WITH_REPORT)).is_err());
}

#[test]
fn other_rp_messages_are_refused() {
    // RP-DATA, RP-ERROR and RP-SMMA headers.
    for message in ["00 07", "01 07", "04 07 01 15", "05 07 01 15", "06 07"] {
        assert!(
            RpAckMsToNetwork::decode(&octets(message)).is_err(),
            "{message}"
        );
        assert!(
            RpAckNetworkToMs::decode(&octets(message)).is_err(),
            "{message}"
        );
    }
}

#[test]
fn a_truncated_header_is_refused() {
    assert!(RpAckMsToNetwork::decode(&[]).is_err());
    assert!(RpAckMsToNetwork::decode(&[0x02]).is_err());
    assert!(RpAckNetworkToMs::decode(&[]).is_err());
    assert!(RpAckNetworkToMs::decode(&[0x03]).is_err());
}

#[test]
fn a_truncated_or_mislengthed_user_data_element_is_refused() {
    for (direction, message) in [
        (2, "02 07 41"),          // IEI with no length
        (2, "02 07 41 03 00 00"), // length 3, two octets follow
        (2, "02 07 41 01 00 00"), // length 1, two octets follow
        (2, "02 07 41 00"),       // empty RP-User-Data, no TPDU in it
        (3, "03 07 41"),
        (3, "03 07 41 0a 01 00 52 10 10 21 00 00 00"),
        (3, "03 07 41 08 01 00 52 10 10 21 00 00 00"),
        (3, "03 07 41 00"),
    ] {
        let result = match direction {
            2 => RpAckMsToNetwork::decode(&octets(message)).map(|_| ()),
            _ => RpAckNetworkToMs::decode(&octets(message)).map(|_| ()),
        };
        assert!(result.is_err(), "{message}");
    }
}

// ── The non-imperative part (TS 24.007 §11.2.4) ──────────────────────────────
//
// RP-User-Data is the only IE TS 24.011 table 7.7 lists for RP-ACK. The
// receiver "shall be prepared for the non-imperative part of the message to
// contain standard IEs that are not specified", and for SMS an unknown IEI
// with bit 8 set is a one-octet IE (type 1 or 2) while one with bit 8 clear is
// TLV (type 4), whose length octet says how far to skip.

#[test]
fn an_unknown_tlv_element_is_skipped() {
    // IEI 0x42, length 1, value AA, then the RP-User-Data of
    // ACK_FROM_MS_WITH_REPORT.
    let ack = RpAckMsToNetwork::decode(&octets("02 07 42 01 aa 41 02 00 00")).expect("decode");
    assert_eq!(ack.rp_message_reference, 7);
    assert_eq!(
        ack.sms_deliver_report,
        Some(SmsDeliverReport::builder().build())
    );
    // An empty unknown element, after the RP-User-Data this time.
    let ack = RpAckNetworkToMs::decode(&octets("03 07 41 09 01 00 52 10 10 21 00 00 00 7f 00"))
        .expect("decode");
    assert_eq!(ack.sms_submit_report, Some(submission_report()));
    // Only unknown elements: an RP-ACK without RP-User-Data.
    let ack = RpAckMsToNetwork::decode(&octets("02 07 42 02 00 00")).expect("decode");
    assert_eq!(ack.sms_deliver_report, None);
}

#[test]
fn an_unknown_element_with_bit_8_set_is_one_octet() {
    // 0xC5 (type 1, IEI 0xC and value 5) and 0xA0 (type 2) carry no length.
    let ack = RpAckMsToNetwork::decode(&octets("02 07 c5 41 02 00 00 a0")).expect("decode");
    assert_eq!(
        ack.sms_deliver_report,
        Some(SmsDeliverReport::builder().build())
    );
    let ack = RpAckNetworkToMs::decode(&octets("03 07 ff")).expect("decode");
    assert_eq!(ack.sms_submit_report, None);
}

#[test]
fn a_repeated_rp_user_data_counts_once() {
    // TS 24.011 has no rule for a repeated IE; TS 24.008 §8.6.3 does: "only
    // the contents of the information element appearing first shall be
    // handled and all subsequent repetitions ... shall be ignored". The second
    // one here is not even a valid SMS-DELIVER-REPORT.
    let ack = RpAckMsToNetwork::decode(&octets("02 07 41 02 00 00 41 01 ff")).expect("decode");
    assert_eq!(
        ack.sms_deliver_report,
        Some(SmsDeliverReport::builder().build())
    );
}

#[test]
fn an_element_that_runs_past_the_message_is_refused() {
    for message in [
        "02 07 42",                // unknown IEI with no length octet
        "02 07 42 03 00 00",       // unknown element of 3, two octets follow
        "02 07 41 02 00 00 42",    // the same after a good RP-User-Data
        "02 07 41 02 00 00 42 01", // and with its value missing
    ] {
        assert!(
            RpAckMsToNetwork::decode(&octets(message)).is_err(),
            "{message}"
        );
    }
    // IEI 0x01 with length 0x15 and nothing behind it.
    assert!(RpAckNetworkToMs::decode(&octets("03 07 01 15")).is_err());
}

#[test]
fn a_tpdu_of_the_wrong_type_is_refused() {
    // An SMS-SUBMIT-REPORT inside an RP-ACK from the mobile station, and an
    // SMS-DELIVER-REPORT inside one from the network.
    assert!(RpAckMsToNetwork::decode(&octets("02 07 41 09 01 00 52 10 10 21 00 00 00")).is_err());
    assert!(RpAckNetworkToMs::decode(&octets("03 07 41 02 00 00")).is_err());
}

// ── What the encoders turn down ──────────────────────────────────────────────

#[test]
fn the_encoders_refuse_what_they_cannot_put_on_the_wire() {
    // The RP-Message-Type of the other direction.
    assert!(RpAckMsToNetwork::builder()
        .message_type(3)
        .build()
        .encode()
        .is_err());
    assert!(RpAckNetworkToMs::builder()
        .message_type(2)
        .build()
        .encode()
        .is_err());

    // The report layout that belongs in an RP-ERROR.
    assert!(RpAckMsToNetwork::builder()
        .sms_deliver_report(SmsDeliverReport::builder().failure_cause(0xd3).build())
        .build()
        .encode()
        .is_err());
    assert!(RpAckNetworkToMs::builder()
        .sms_submit_report(
            SmsSubmitReport::builder()
                .failure_cause(0xc3)
                .service_centre_timestamp(SCTS_DIGITS)
                .build()
        )
        .build()
        .encode()
        .is_err());

    // A report that does not encode: TP-PID given but not announced in TP-PI.
    assert!(RpAckMsToNetwork::builder()
        .sms_deliver_report(SmsDeliverReport::builder().pid(0).build())
        .build()
        .encode()
        .is_err());
    // An SMS-SUBMIT-REPORT without a time stamp.
    assert!(RpAckNetworkToMs::builder()
        .sms_submit_report(
            SmsSubmitReport::builder()
                .service_centre_timestamp("")
                .build()
        )
        .build()
        .encode()
        .is_err());
}

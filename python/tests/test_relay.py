"""Known-answer tests for RP-ERROR, RP-SMMA, SMS-STATUS-REPORT and
SMS-DELIVER-REPORT on the Python surface.

Every expected byte string is written out by hand from 3GPP TS 24.011 §7.3 and
TS 23.040 §9.2.2 (the derivations are in the Rust `tests/relay_kat.rs`, which
also has Wireshark read the same bytes back). All numbers are fictional
(555-01xx).
"""

import pytest

import tpdu


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# 2025-01-01 12:00:00 at GMT, each pair of digits swapped into one octet.
SCTS_DIGITS = "25010112000000"
SCTS = "52 10 10 21 00 00 00"


# ── RP-ERROR ────────────────────────────────────────────────────────────

# Type 5, RP-MR 7, RP-Cause (length 1, cause 21), RP-User-Data (IEI 0x41,
# length 10): SMS-SUBMIT-REPORT with TP-FCS 0xC3, TP-PI 0, TP-SCTS.
RP_ERROR_TO_MS = h(f"05 07 01 15 41 0a 01 c3 00 {SCTS}")
# Type 4, RP-MR 7, RP-Cause (length 2, cause 22, diagnostic 0), RP-User-Data
# (length 3): SMS-DELIVER-REPORT with TP-FCS 0xD3, TP-PI 0.
RP_ERROR_FROM_MS = h("04 07 02 16 00 41 03 00 d3 00")


def test_rp_error_network_to_ms():
    report = tpdu.SmsSubmitReport(tp_failure_cause=0xC3, scts=SCTS_DIGITS)
    error = tpdu.RpErrorNetworkToMs(21, rp_message_reference=7, sms_submit_report=report)
    assert error.encode() == RP_ERROR_TO_MS

    built = (
        tpdu.RpErrorNetworkToMs.builder(21)
        .message_reference(7)
        .sms_submit_report(
            tpdu.SmsSubmitReport.builder().failure_cause(0xC3).scts(SCTS_DIGITS).build()
        )
        .build()
    )
    assert built.encode() == RP_ERROR_TO_MS

    parsed = tpdu.parse_rp_error(RP_ERROR_TO_MS)
    assert isinstance(parsed, tpdu.RpErrorNetworkToMs)
    assert parsed.rp_message_type == 5
    assert parsed.rp_message_reference == 7
    assert parsed.rp_cause == 21
    assert parsed.rp_diagnostic is None
    assert parsed.sms_submit_report.tp_failure_cause == 0xC3
    assert parsed.sms_submit_report.scts == SCTS_DIGITS


def test_rp_error_without_user_data():
    error = tpdu.RpErrorNetworkToMs(111, rp_message_reference=0x2A, rp_diagnostic=1)
    assert error.encode() == h("05 2a 02 6f 01")
    with pytest.raises(ValueError):
        tpdu.RpErrorNetworkToMs(0x80, rp_message_reference=1).encode()
    # The report of an RP-ERROR needs its failure cause.
    with pytest.raises(ValueError):
        tpdu.RpErrorNetworkToMs(
            21, rp_message_reference=1, sms_submit_report=tpdu.SmsSubmitReport(scts=SCTS_DIGITS)
        ).encode()


def test_rp_error_ms_to_network():
    parsed = tpdu.parse_rp_error(RP_ERROR_FROM_MS)
    assert isinstance(parsed, tpdu.RpErrorMsToNetwork)
    assert parsed.rp_message_type == 4
    assert parsed.rp_message_reference == 7
    assert parsed.rp_cause == 22
    assert parsed.rp_diagnostic == 0
    assert parsed.sms_deliver_report.tp_failure_cause == 0xD3

    bare = tpdu.parse_rp_error(h("04 07 01 16"))
    assert bare.rp_cause == 22
    assert bare.rp_diagnostic is None
    assert bare.sms_deliver_report is None

    built = tpdu.RpErrorMsToNetwork(
        22,
        rp_message_reference=7,
        rp_diagnostic=0,
        sms_deliver_report=tpdu.SmsDeliverReport(tp_failure_cause=0xD3),
    )
    assert built.encode() == RP_ERROR_FROM_MS
    fluent = (
        tpdu.RpErrorMsToNetwork.builder(22)
        .message_reference(7)
        .diagnostic(0)
        .sms_deliver_report(tpdu.SmsDeliverReport.builder().failure_cause(0xD3).build())
        .build()
    )
    assert fluent.encode() == RP_ERROR_FROM_MS

    with pytest.raises(ValueError):
        tpdu.parse_rp_error(h("06 09"))


def test_sms_deliver_report_for_rp_ack():
    assert tpdu.SmsDeliverReport().encode() == h("00 00")
    assert tpdu.SmsDeliverReport(tp_udhi=True, tp_parameter_indicator=1, tp_pid=0x7F).encode() == h(
        "40 01 7f"
    )
    with pytest.raises(ValueError):
        tpdu.SmsDeliverReport(tp_parameter_indicator=1).encode()


# ── RP-SMMA ─────────────────────────────────────────────────────────────


def test_rp_smma():
    assert tpdu.RpSmma(rp_message_reference=9).encode() == h("06 09")
    assert tpdu.RpSmma.builder().message_reference(9).build().encode() == h("06 09")
    parsed = tpdu.parse_rp_smma(h("06 09"))
    assert parsed.rp_message_type == 6
    assert parsed.rp_message_reference == 9
    with pytest.raises(ValueError):
        tpdu.parse_rp_smma(h("02 09"))


# ── SMS-STATUS-REPORT ───────────────────────────────────────────────────

# 0x06: TP-MTI 10 and TP-MMS. TP-MR 0x2A, TP-RA 15550100, TP-SCTS, TP-DT five
# seconds later, TP-ST 0x00.
STATUS_REPORT = h(f"06 2a 08 91 51 55 10 00 {SCTS} 52 10 10 21 00 50 00 00")
# RP-DATA network to MS: type 1, RP-MR 5, RP-OA 15550199, empty RP-DA, 23
# octets of TPDU.
STATUS_REPORT_IN_RP_DATA = h("01 05 05 91 51 55 10 99 00 17") + STATUS_REPORT


def test_sms_status_report():
    ra = tpdu.Address("15550100")
    report = tpdu.SmsStatusReport(
        ra, tp_mr=0x2A, tp_status=0, scts=SCTS_DIGITS, discharge_time="25010112000500"
    )
    assert report.encode() == STATUS_REPORT

    fluent = (
        tpdu.SmsStatusReport.builder(ra)
        .mr(0x2A)
        .status(0)
        .scts(SCTS_DIGITS)
        .discharge_time("25010112000500")
        .build()
    )
    assert fluent.encode() == STATUS_REPORT

    parsed = tpdu.parse_sms_status_report(STATUS_REPORT)
    assert parsed.tp_mr == 0x2A
    assert parsed.tp_recipient_address.address == "15550100"
    assert parsed.scts == SCTS_DIGITS
    assert parsed.discharge_time == "25010112000500"
    assert parsed.tp_status == 0
    assert parsed.tp_mms is True
    assert parsed.tp_srq is False and parsed.tp_lp is False and parsed.tp_udhi is False
    assert parsed.tp_parameter_indicator is None


def test_sms_status_report_with_optional_parameters():
    # 0x2E adds TP-SRQ (bit 5) and TP-LP (bit 3). TP-ST 0x46, TP-PI 0x07,
    # TP-PID 0, TP-DCS 0, TP-UDL 2 septets, "hi" packed as E8 34.
    wire = h(f"2e 2a 08 91 51 55 10 00 {SCTS} 52 10 10 21 00 50 00 46 07 00 00 02 e8 34")
    parsed = tpdu.parse_sms_status_report(wire)
    assert parsed.tp_srq is True and parsed.tp_lp is True
    assert parsed.tp_status == 0x46
    assert parsed.tp_parameter_indicator == 0x07
    assert (parsed.tp_pid, parsed.tp_dcs, parsed.tp_user_data_length) == (0, 0, 2)
    assert parsed.tp_user_data == h("e8 34")
    assert parsed.encode() == wire


def test_rp_data_carrying_a_status_report():
    report = tpdu.parse_sms_status_report(STATUS_REPORT)
    sc = tpdu.Address("15550199")
    rp = tpdu.RpDataNetworkToMsStatusReport(
        report, rp_message_reference=5, rp_originator_address=sc
    )
    assert rp.encode() == STATUS_REPORT_IN_RP_DATA
    fluent = (
        tpdu.RpDataNetworkToMsStatusReport.builder(report)
        .message_reference(5)
        .originator_address(sc)
        .build()
    )
    assert fluent.encode() == STATUS_REPORT_IN_RP_DATA

    parsed = tpdu.parse_rp_data_network_to_ms(STATUS_REPORT_IN_RP_DATA)
    assert isinstance(parsed, tpdu.RpDataNetworkToMsStatusReport)
    assert parsed.rp_message_reference == 5
    assert parsed.rp_originator_address.address == "15550199"
    assert parsed.rp_destination_address is None
    assert parsed.sms_status_report.tp_mr == 0x2A


def test_rp_data_carrying_a_deliver():
    # 0x24: TP-SRI and TP-MMS. TP-OA 15550101, TP-PID 0, TP-DCS 0, TP-SCTS,
    # TP-UDL 5 septets, "hello".
    wire = h(f"01 06 05 91 51 55 10 99 00 16 24 08 91 51 55 10 10 00 00 {SCTS} 05 e8 32 9b fd 06")
    parsed = tpdu.parse_rp_data_network_to_ms(wire)
    assert isinstance(parsed, tpdu.RpDataNetworkToMs)
    assert parsed.rp_message_reference == 6
    deliver = parsed.sms_deliver
    assert deliver.tp_sri is True and deliver.tp_mms is True
    assert deliver.tp_rp is False and deliver.tp_udhi is False and deliver.tp_lp is False
    assert deliver.tp_originating_address.address == "15550101"
    assert deliver.scts == SCTS_DIGITS
    assert deliver.tp_user_data_length == 5
    assert deliver.text() == "hello"
    assert parsed.encode() == wire

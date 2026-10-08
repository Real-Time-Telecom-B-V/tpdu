"""Known-answer tests for the Python surface.

Every expected byte string here is written out by hand from 3GPP TS 23.040,
TS 23.038 and TS 24.011 (the derivations are in the Rust `tests/*_kat.rs`
files, which also have Wireshark read the same bytes back). Nothing is built by
the codec and then fed back to it. All numbers are fictional (555-01xx).
"""

import pytest

import tpdu


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# TP-MR 0x2A, TP-DA 15550100 (8 digits, international E.164), TP-PID 0.
MR_DA_PID = "2a 08 91 51 55 10 00 00"
# 2025-01-01 12:00:00 at GMT, each pair of digits swapped into one octet.
SCTS_DIGITS = "25010112000000"
SCTS = "52 10 10 21 00 00 00"


# ── SMS-SUBMIT first octet and TP-Validity-Period ───────────────────────


def test_status_report_request_without_validity_period():
    # 0x21: TP-SRR (bit 5), TP-VPF 00, TP-MTI 01. TP-DCS 4 (8-bit), "hi".
    submit = tpdu.parse_sms_submit(h(f"21 {MR_DA_PID} 04 02 68 69"))
    assert submit.tp_srr is True
    assert submit.tp_vpf == 0
    assert submit.tp_validity_period is None
    assert submit.tp_user_data == b"hi"


def test_header_without_validity_period_keeps_its_text():
    # 0x41: TP-UDHI (bit 6), TP-VPF 00.
    submit = tpdu.parse_sms_submit(h(f"41 {MR_DA_PID} 04 08 05 00 03 42 02 01 68 69"))
    assert submit.tp_udhi is True
    assert submit.tp_user_data_header == h("05 00 03 42 02 01")
    assert submit.tp_user_data == h("05 00 03 42 02 01 68 69")


@pytest.mark.parametrize(
    "first_octet, validity_period, vpf, expected",
    [
        ("01", "", 0, None),
        # bit 4 set, bit 3 clear: relative, one octet.
        ("11", "a7", 2, 0xA7),
        # bits 4 and 3 set: absolute, seven octets coded like TP-SCTS.
        ("19", "62 01 13 32 95 00 40", 3, "26103123590004"),
        # bit 4 clear, bit 3 set: enhanced, seven octets as received.
        ("09", "01 a7 00 00 00 00 00", 1, h("01 a7 00 00 00 00 00")),
    ],
)
def test_validity_period_formats(first_octet, validity_period, vpf, expected):
    wire = h(f"{first_octet} {MR_DA_PID} 04 {validity_period} 02 68 69")
    submit = tpdu.parse_sms_submit(wire)
    assert submit.tp_vpf == vpf
    assert submit.tp_validity_period == expected
    assert submit.tp_user_data_length == 2
    assert submit.tp_user_data == b"hi"
    assert submit.encode() == wire


def test_reject_duplicates_is_bit_2():
    assert tpdu.parse_sms_submit(h(f"35 {MR_DA_PID} 04 a7 02 68 69")).tp_rd is True
    assert tpdu.parse_sms_submit(h(f"31 {MR_DA_PID} 04 a7 02 68 69")).tp_rd is False


# ── GSM 7-bit user data ─────────────────────────────────────────────────

# Concatenation header (reference 0x2A, part 1 of 2), one fill bit, "hello".
HEADER = h("05 00 03 2a 02 01")
HEADER_AND_HELLO = h("05 00 03 2a 02 01 d0 65 36 fb 0d")


def test_pack_gsm7_with_header():
    assert tpdu.pack_gsm7_with_header(HEADER, "hello") == (HEADER_AND_HELLO, 12)
    assert tpdu.unpack_gsm7_with_header(HEADER_AND_HELLO, 12) == (HEADER, "hello")
    with pytest.raises(ValueError):
        tpdu.pack_gsm7_with_header(b"\x05\x00", "hello")


def test_sms_submit_with_header_and_7_bit_text():
    wire = h(f"41 {MR_DA_PID} 00 0c") + HEADER_AND_HELLO
    submit = tpdu.parse_sms_submit(wire)
    assert submit.tp_udhi is True
    assert submit.tp_user_data_header == HEADER
    # The header is in the bytes whenever tp_udhi says so.
    assert submit.tp_user_data == HEADER + b"hello"
    assert submit.tp_user_data_raw == HEADER_AND_HELLO
    assert submit.text() == "hello"


@pytest.mark.parametrize("dcs", ["10", "11", "f1", "c8"])
def test_7_bit_text_with_a_message_class(dcs):
    # Ten septets "hellohello" in nine octets.
    wire = h(f"01 {MR_DA_PID} {dcs} 0a e8 32 9b fd 46 97 d9 ec 37")
    submit = tpdu.parse_sms_submit(wire)
    assert submit.tp_user_data == b"hellohello"
    assert submit.text() == "hellohello"


def test_7_bit_text_outside_latin_1():
    # a, the euro sign (escape 0x1B then 0x65) and a Greek capital delta.
    submit = tpdu.parse_sms_submit(h(f"01 {MR_DA_PID} 00 04 e1 4d 19 02"))
    assert submit.text() == "a€Δ"


def test_ucs2_text_skips_the_header():
    wire = h(f"41 {MR_DA_PID} 08 0a 05 00 03 2a 02 01 00 68 00 69")
    submit = tpdu.parse_sms_submit(wire)
    assert submit.tp_user_data == h("05 00 03 2a 02 01 00 68 00 69")
    assert submit.text() == "hi"


def test_user_data_coding():
    assert tpdu.user_data_coding(0x00) == "gsm7"
    assert tpdu.user_data_coding(0x10) == "gsm7"
    assert tpdu.user_data_coding(0xF1) == "gsm7"
    assert tpdu.user_data_coding(0x04) == "8bit"
    assert tpdu.user_data_coding(0xF5) == "8bit"
    assert tpdu.user_data_coding(0x08) == "ucs2"
    assert tpdu.user_data_coding(0x20) == "compressed"


def test_spare_bits_are_zero():
    assert tpdu.pack_gsm7("a") == (b"\x61", 1)
    assert tpdu.pack_gsm7("123456789") == (h("31 d9 8c 56 b3 dd 70 39"), 9)
    # A CR in the spare bits of a seven-septet message is not an eighth char.
    assert tpdu.unpack_gsm7(h("31 d9 8c 56 b3 dd 1a"), 7) == "1234567"


def test_deliver_builder_with_header():
    oa = tpdu.Address("15550101")
    deliver = (
        tpdu.SmsDeliver.builder(oa)
        .udhi(True)
        .dcs(0)
        .scts(SCTS_DIGITS)
        .gsm7_text_with_header(HEADER, "hello")
        .build()
    )
    # 0x44: TP-UDHI and TP-MMS. TP-OA, TP-PID, TP-DCS, TP-SCTS, TP-UDL 12.
    assert deliver.encode() == h(f"44 08 91 51 55 10 10 00 00 {SCTS} 0c") + HEADER_AND_HELLO
    assert deliver.text() == "hello"


def test_7_bit_user_data_needs_its_length():
    oa = tpdu.Address("15550101")
    packed, septets = tpdu.pack_gsm7("hellohello")
    with pytest.raises(ValueError):
        tpdu.SmsDeliver(oa, packed, tp_dcs=0, scts=SCTS_DIGITS)
    with pytest.raises(ValueError):
        tpdu.build_sms_deliver_tpdu("15550101", short_message=packed, scts=SCTS_DIGITS)
    # A length that contradicts the bytes is turned down at encode().
    wrong = tpdu.SmsDeliver(oa, packed, tp_dcs=0, scts=SCTS_DIGITS, user_data_length=len(packed))
    with pytest.raises(ValueError):
        wrong.encode()
    right = tpdu.SmsDeliver(oa, packed, tp_dcs=0, scts=SCTS_DIGITS, user_data_length=septets)
    assert right.encode().endswith(b"\x0a" + packed)
    # Octet-counted codings still default to the byte count.
    assert tpdu.SmsDeliver(oa, b"hi", tp_dcs=4, scts=SCTS_DIGITS).encode().endswith(b"\x02hi")


# ── Addresses and time stamps ───────────────────────────────────────────


def test_alphanumeric_originator():
    # Seven characters are 49 bits: 13 useful semi-octets, not 14.
    deliver = tpdu.SmsDeliver(
        tpdu.Address("Example", ton=5, npi=0), b"hi", tp_dcs=4, tp_mms=False, scts=SCTS_DIGITS
    )
    assert deliver.encode() == h(f"00 0d d0 45 7c b8 0d 67 97 01 00 04 {SCTS} 02 68 69")


def test_star_and_hash_digits():
    submit = tpdu.parse_sms_submit(h("01 01 05 81 1a 00 fb 00 04 02 68 69"))
    assert submit.tp_destination_address.address == "*100#"


def test_timestamp_digits():
    assert tpdu.timestamp_digits(26, 8, 17, 12, 0, 0) == "26081712000000"
    assert tpdu.timestamp_digits(26, 8, 17, 12, 0, 0, 4) == "26081712000004"
    # GMT-5h: the sign is the top bit of the first time-zone digit.
    assert tpdu.timestamp_digits(26, 8, 17, 12, 0, 0, -20) == "260817120000A0"
    oa = tpdu.Address("15550101")
    deliver = tpdu.SmsDeliver(oa, b"hi", tp_dcs=4, tp_mms=False, scts="260817120000A0")
    assert deliver.encode() == h("00 08 91 51 55 10 10 00 04 62 80 71 21 00 00 0a 02 68 69")
    with pytest.raises(ValueError):
        tpdu.SmsDeliver(oa, b"hi", tp_dcs=4, scts="2608171200000").encode()


# ── RP-ACK ──────────────────────────────────────────────────────────────


def test_rp_ack_carries_the_report_length():
    report = tpdu.SmsSubmitReport(scts=SCTS_DIGITS)
    ack = tpdu.RpAckNetworkToMs(report, rp_message_reference=7)
    assert ack.encode() == h(f"03 07 41 09 01 00 {SCTS}")

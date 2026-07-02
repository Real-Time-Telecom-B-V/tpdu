"""Python binding tests for `tpdu`.

All data is synthetic (fictional 555-01xx numbers, neutral text) and built from
the public API — no captured traffic. These verify the Python surface mirrors
the Rust codec and that the module is free-threaded safe.
"""

import sys
import sysconfig

import pytest

import tpdu


def _bcd(num: str) -> bytes:
    """Encode digit string as swapped-nibble BCD (odd length padded with F)."""
    if len(num) % 2:
        num += "F"
    out = bytearray()
    for i in range(0, len(num), 2):
        lo = int(num[i], 16)
        hi = 0xF if num[i + 1] == "F" else int(num[i + 1], 16)
        out.append((hi << 4) | lo)
    return bytes(out)


def _submit(dest: str, text: str) -> bytes:
    """Assemble a synthetic SMS-SUBMIT TPDU (mti=1, no VP, DCS=0)."""
    ud, septets = tpdu.pack_gsm7(text)
    body = bytes([0x01, 0x01, len(dest), 0x91]) + _bcd(dest) + bytes([0, 0, septets])
    return body + ud


def _rp_mo(tpdu_bytes: bytes) -> bytes:
    """Wrap a TPDU in RP-DATA MS->Network (no RP addresses)."""
    return bytes([0x00, 0x01, 0x00, 0x00, len(tpdu_bytes)]) + tpdu_bytes


@pytest.mark.parametrize(
    "text", ["", "ping", "hello tpdu", "Symbols @ {} [] | ~ ^ €", "voorbeeld"]
)
def test_gsm7_roundtrip(text):
    packed, septets = tpdu.pack_gsm7(text)
    assert isinstance(packed, bytes)
    assert tpdu.unpack_gsm7(packed, septets) == text


def test_parse_rp_data_mo():
    dest = "15550100"
    rp = _rp_mo(_submit(dest, "ping"))
    parsed = tpdu.parse_rp_data(rp)
    assert parsed.sms_submit.tp_user_data == b"ping"
    assert parsed.sms_submit.tp_destination_address.address == dest
    assert parsed.sms_submit.text() == "ping"


def test_parse_bare_sms_submit():
    submit = _submit("15550101", "bare")
    parsed = tpdu.parse_sms_submit(submit)
    assert parsed.tp_user_data == b"bare"
    assert parsed.tp_mti == 1


def test_destination_from_tpdu():
    submit = _submit("15550102", "x")
    assert tpdu.destination_from_tpdu(submit) == "15550102"


def test_build_mt_deliver():
    addr = tpdu.Address("15550199")
    packed, septets = tpdu.pack_gsm7("delivered")
    deliver = tpdu.SmsDeliver(
        addr, packed, tp_dcs=0, scts="25010112000000", user_data_length=septets
    )
    mt = tpdu.RpDataNetworkToMs(deliver, rp_message_reference=0, rp_originator_address=addr)
    wire = mt.encode()
    assert isinstance(wire, bytes)
    assert wire[0] == 0x01  # RP-DATA n->ms
    assert wire.endswith(packed)


def test_build_sms_deliver_tpdu_helper():
    wire = tpdu.build_sms_deliver_tpdu("15550199", scts="25010112000000")
    assert isinstance(wire, bytes) and len(wire) > 0


def test_rp_ack():
    report = tpdu.SmsSubmitReport(scts="25010112000000")
    ack = tpdu.RpAckNetworkToMs(report, rp_message_reference=7)
    wire = ack.encode()
    assert wire[0] == 0x03  # RP-ACK n->ms
    assert wire[1] == 7  # echoes RP-MR


def test_builder_matches_kwargs_construction():
    """The fluent builders must encode byte-identically to the kwargs path."""
    oa = tpdu.Address.builder().ton(1).npi(1).address("15550199").build()
    built = (
        tpdu.RpDataNetworkToMs.builder(
            tpdu.SmsDeliver.builder(oa)
            .mms(True)
            .dcs(0)
            .scts("25010112000000")
            .gsm7_text("delivered")
            .build()
        )
        .originator_address(oa)
        .build()
        .encode()
    )

    packed, septets = tpdu.pack_gsm7("delivered")
    addr = tpdu.Address("15550199")
    deliver = tpdu.SmsDeliver(
        addr, packed, tp_dcs=0, scts="25010112000000", user_data_length=septets
    )
    kwargs = tpdu.RpDataNetworkToMs(
        deliver, rp_message_reference=0, rp_originator_address=addr
    ).encode()

    assert built == kwargs


def test_udh_builder_derives_length():
    udh = tpdu.UserDataHeader.builder().value(bytes([0x00, 0x03, 0x42, 0x02, 0x01])).build()
    assert udh.length == 5
    assert tpdu.UserDataHeader.builder().value(b"\xaa").length(9).build().length == 9


def test_rp_ack_builder():
    report = tpdu.SmsSubmitReport.builder().scts("25010112000000").build()
    wire = tpdu.RpAckNetworkToMs.builder(report).message_reference(7).build().encode()
    assert wire[0] == 0x03  # default RP-ACK n->ms
    assert wire[1] == 7  # echoed RP-MR


def test_builder_gsm7_error_surfaces_at_build():
    # A char outside the GSM 7-bit alphabet fails packing; the error is deferred
    # to build() so the setter chain stays fluent.
    oa = tpdu.Address.builder().address("15550100").build()
    with pytest.raises(ValueError):
        tpdu.SmsDeliver.builder(oa).gsm7_text("\U0001f600").build()


def test_invalid_input_raises():
    with pytest.raises(ValueError):
        tpdu.parse_rp_data(b"\x00")


def test_import_does_not_force_gil():
    """On a free-threaded build, importing tpdu must not re-enable the GIL
    (the module is declared `gil_used = false`)."""
    if not sysconfig.get_config_var("Py_GIL_DISABLED"):
        pytest.skip("not a free-threaded interpreter")
    assert sys._is_gil_enabled() is False, "importing tpdu re-enabled the GIL"

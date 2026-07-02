"""End-to-end demo of the `tpdu` Python bindings — the three things you'll
actually do: pack/unpack GSM 7-bit, decode an inbound MO SMS-SUBMIT, and build
an outbound MT SMS-DELIVER. All data is synthetic (fictional 555-01xx numbers).

Run with:  python python/examples/demo.py
(after `maturin develop --features extension-module`, or `pip install tpdu`)
"""

import tpdu

# 1) GSM 7-bit septet packing (TS 23.038).
packed, septets = tpdu.pack_gsm7("Hello from tpdu!")
print(f"GSM-7: {septets} septets -> {len(packed)} bytes: {packed.hex()}")
print(f"       unpacked: {tpdu.unpack_gsm7(packed, septets)!r}\n")


def synthetic_mo(dest: str, text: str) -> bytes:
    """Assemble a synthetic MO RP-DATA carrying an SMS-SUBMIT (in production this
    is the body of a SIP MESSAGE from the UE)."""
    ud, n = tpdu.pack_gsm7(text)
    digits = dest + ("F" if len(dest) % 2 else "")
    bcd = bytes(
        ((0xF if digits[i + 1] == "F" else int(digits[i + 1])) << 4) | int(digits[i])
        for i in range(0, len(digits), 2)
    )
    tpdu_bytes = bytes([0x01, 0x01, len(dest), 0x91]) + bcd + bytes([0, 0, n]) + ud
    return bytes([0x00, 0x01, 0x00, 0x00, len(tpdu_bytes)]) + tpdu_bytes


# 2) Decode an inbound MO RP-DATA carrying an SMS-SUBMIT.
rp = tpdu.parse_rp_data(synthetic_mo("15550100", "ping"))
submit = rp.sms_submit
print("Decoded MO SMS-SUBMIT:")
print(f"  destination = {submit.tp_destination_address.address}")
print(f"  message     = {submit.text()!r}")
print(f"  dcs=0x{submit.tp_dcs:02x}  mr={submit.tp_mr}\n")

# 3) Build an outbound MT SMS-DELIVER wrapped in RP-DATA (Network -> MS).
#    The fluent builders default the flags and derive TP-UDL (via gsm7_text);
#    you stay explicit about the data coding with .dcs(0) = GSM 7-bit.
oa = tpdu.Address.builder().ton(1).npi(1).address("15550199").build()
deliver = (
    tpdu.SmsDeliver.builder(oa)
    .dcs(0)
    .scts("25010112000000")
    .gsm7_text("Delivered by tpdu")
    .build()
)
mt = tpdu.RpDataNetworkToMs.builder(deliver).originator_address(oa).build()
wire = mt.encode()
print(f"Encoded MT RP-DATA ({len(wire)} bytes): {wire.hex()}")

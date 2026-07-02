"""Python-side memory-leak regression for the `tpdu` bindings.

The Rust `leak_check` example proves the codec itself doesn't leak native
memory; this guards the *binding* layer — a `PyBytes`/object that the bindings
forget to release would show up as Python-heap or live-object growth across many
calls. Uses `tracemalloc` (traces Python allocations, incl. the bytes the
bindings return) and the GC object count, both expected to stay flat.
"""

import gc
import tracemalloc

import tpdu


def _bcd(num: str) -> bytes:
    if len(num) % 2:
        num += "F"
    out = bytearray()
    for i in range(0, len(num), 2):
        lo = int(num[i], 16)
        hi = 0xF if num[i + 1] == "F" else int(num[i + 1], 16)
        out.append((hi << 4) | lo)
    return bytes(out)


def _mo(dest: str, text: str) -> bytes:
    ud, septets = tpdu.pack_gsm7(text)
    body = bytes([0x01, 0x01, len(dest), 0x91]) + _bcd(dest) + bytes([0, 0, septets]) + ud
    return bytes([0x00, 0x01, 0x00, 0x00, len(body)]) + body


_MO = _mo("15550100", "leak check message")


def _work() -> None:
    packed, septets = tpdu.pack_gsm7("hello tpdu leak check")
    _ = tpdu.unpack_gsm7(packed, septets)
    parsed = tpdu.parse_rp_data(_MO)
    _ = parsed.sms_submit.tp_user_data
    addr = tpdu.Address("15550199")
    deliver = tpdu.SmsDeliver(
        addr, packed, tp_dcs=0, scts="25010112000000", user_data_length=septets
    )
    _ = deliver.encode()


def test_bindings_do_not_leak():
    # Warm up so one-time allocations (interned strings, type objects) settle.
    for _ in range(2_000):
        _work()
    gc.collect()

    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    base_objects = len(gc.get_objects())

    for _ in range(40_000):
        _work()

    gc.collect()
    after = tracemalloc.take_snapshot()
    grown = sum(s.size_diff for s in after.compare_to(before, "filename"))
    tracemalloc.stop()
    object_growth = len(gc.get_objects()) - base_objects

    assert grown < 256 * 1024, f"python heap grew {grown} bytes across 40k cycles"
    assert object_growth < 1_000, f"live object count grew by {object_growth}"

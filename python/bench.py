"""Throughput benchmark for the `tpdu` Python bindings.

Reports ops/sec for the hot paths from Python (so it includes the PyO3 call
overhead, unlike the Rust criterion benches). All data is synthetic.

    python python/bench.py            # default 1,000,000 iters each
    ITERS=5000000 python python/bench.py
"""

import os
import time

import tpdu

ITERS = int(os.environ.get("ITERS", "1000000"))


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


def bench(name: str, fn, iters: int = ITERS) -> None:
    fn()  # warm up
    start = time.perf_counter()
    for _ in range(iters):
        fn()
    dt = time.perf_counter() - start
    print(f"{name:22} {iters / dt / 1e6:7.2f} M ops/s   ({iters:,} in {dt:.3f}s)")


def main() -> None:
    # Same inputs as the Rust criterion bench (benches/codec.rs) so the numbers
    # are comparable across languages.
    text = "Hello world! This is a GSM 7-bit packed message."
    packed, septets = tpdu.pack_gsm7(text)
    mo = _mo("15550100", "benchmark")
    print(f"tpdu python bench — {ITERS:,} iters each\n")
    bench("pack_gsm7", lambda: tpdu.pack_gsm7(text))
    bench("unpack_gsm7", lambda: tpdu.unpack_gsm7(packed, septets))
    bench("parse_rp_data", lambda: tpdu.parse_rp_data(mo))
    bench(
        "build_sms_deliver",
        lambda: tpdu.build_sms_deliver_tpdu(
            "15550199", short_message=packed, data_coding=0,
            user_data_length=septets, scts="25010112000000",
        ),
    )


if __name__ == "__main__":
    main()

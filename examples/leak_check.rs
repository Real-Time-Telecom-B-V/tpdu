//! Memory-leak regression check (counting global allocator).
//!
//! `tpdu` is a pure codec, so the only way it can leak is a buffer that escapes
//! per call. We install a counting allocator (live bytes = allocated − freed),
//! warm up, then run K cycles of the full decode+encode+GSM-7 workload, sampling
//! live bytes after each cycle. Live bytes must stay flat within a tight budget;
//! exit non-zero (and print FAIL) otherwise. Run via `scripts/mem_leak_test.sh`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use tpdu::{pack_gsm7, parse_rp_data, unpack_gsm7, RpDataNetworkToMs, SMSAddress, SmsDeliver};

/// Synthetic MO RP-DATA (fictional number, neutral text), built from the public
/// API — no captured data.
fn sample_mo() -> Vec<u8> {
    let dest = SMSAddress {
        ton: 1,
        npi: 1,
        address: "15550100".into(),
    };
    let (ud, septets) = pack_gsm7("leakcheck").unwrap();
    let mut tpdu = vec![0x01u8, 0x01];
    tpdu.extend(dest.encode(false).unwrap());
    tpdu.push(0);
    tpdu.push(0);
    tpdu.push(septets as u8);
    tpdu.extend(ud);
    let mut rp = vec![0x00u8, 0x01, 0x00, 0x00];
    rp.push(tpdu.len() as u8);
    rp.extend(tpdu);
    rp
}

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

const CYCLES: usize = 200;
const PER_CYCLE: usize = 2_000;
/// Budget for live-byte growth across all cycles. The codec allocates only
/// transient buffers, so steady-state growth should be ~0; allow slack for
/// allocator bookkeeping.
const BUDGET: isize = 256 * 1024;

fn workload(mo: &[u8], mt: &RpDataNetworkToMs) {
    let rp = parse_rp_data(mo).unwrap();
    std::hint::black_box(&rp);
    let bytes = mt.encode().unwrap();
    std::hint::black_box(&bytes);
    let (packed, septets) = pack_gsm7("Hello world! GSM-7 packing leak check.").unwrap();
    let text = unpack_gsm7(&packed, septets).unwrap();
    std::hint::black_box(text);
}

fn sample_mt() -> RpDataNetworkToMs {
    RpDataNetworkToMs {
        rp_message_type: 0x01,
        rp_message_reference: 0,
        rp_originator_address: Some(SMSAddress {
            ton: 1,
            npi: 1,
            address: "15555550100".into(),
        }),
        rp_destination_address: None,
        sms_deliver: SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_mti: 0,
            tp_originating_address: SMSAddress {
                ton: 1,
                npi: 1,
                address: "15555550100".into(),
            },
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
            tp_user_data_length: 4,
            tp_user_data: vec![0xd4, 0xf2, 0x9c, 0x0e],
        },
    }
}

fn main() {
    let mo = sample_mo();
    let mt = sample_mt();

    // Warm up so lazy one-time allocations don't count as growth.
    for _ in 0..PER_CYCLE {
        workload(&mo, &mt);
    }
    let baseline = LIVE.load(Ordering::Relaxed);
    println!("baseline live bytes: {baseline}");

    let mut max_delta = 0isize;
    for cycle in 0..CYCLES {
        for _ in 0..PER_CYCLE {
            workload(&mo, &mt);
        }
        let delta = LIVE.load(Ordering::Relaxed) - baseline;
        max_delta = max_delta.max(delta);
        if cycle % 50 == 0 || cycle == CYCLES - 1 {
            println!("cycle {cycle:>3}: live Δ = {delta} bytes");
        }
    }

    println!("max live Δ over {CYCLES} cycles: {max_delta} bytes (budget {BUDGET})");
    if max_delta > BUDGET {
        println!("FAIL: live bytes grew beyond budget — possible leak");
        std::process::exit(1);
    }
    println!("PASS: live bytes flat");
}

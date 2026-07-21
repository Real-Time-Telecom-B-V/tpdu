//! End-to-end demo of the `tpdu` codec — the three things you'll actually do:
//! pack/unpack GSM 7-bit, decode an inbound MO SMS-SUBMIT, and build an
//! outbound MT SMS-DELIVER. All data is synthetic (fictional 555-01xx numbers).
//!
//! Run with:  cargo run --example demo

use tpdu::{pack_gsm7, parse_rp_data, unpack_gsm7, RpDataNetworkToMs, SMSAddress, SmsDeliver};

fn main() {
    // 1) GSM 7-bit septet packing (TS 23.038).
    let (packed, septets) = pack_gsm7("Hello from tpdu!").unwrap();
    println!(
        "GSM-7: {septets} septets -> {} bytes: {packed:02x?}",
        packed.len()
    );
    println!(
        "       unpacked: {:?}\n",
        unpack_gsm7(&packed, septets).unwrap()
    );

    // 2) Decode an inbound MO RP-DATA carrying an SMS-SUBMIT (what arrives from a
    //    handset on the Gm interface). We synthesise one here for the demo.
    let mo = synthetic_mo("15550100", "ping");
    let rp = parse_rp_data(&mo).unwrap();
    let submit = &rp.sms_submit;
    println!("Decoded MO SMS-SUBMIT:");
    println!(
        "  destination = {}",
        submit
            .tp_destination_address
            .as_ref()
            .map(|a| a.address.as_str())
            .unwrap_or("?")
    );
    println!(
        "  message     = {:?}",
        String::from_utf8_lossy(&submit.tp_user_data)
    );
    println!("  dcs=0x{:02x}  mr={}\n", submit.tp_dcs, submit.tp_mr);

    // 3) Build an outbound MT SMS-DELIVER wrapped in RP-DATA (Network -> MS).
    //    The builders default the flags and TP-MTI and derive TP-User-Data-Length
    //    for you; you stay explicit about the data coding (`.dcs(0)` = GSM 7-bit).
    let oa = SMSAddress::builder()
        .ton(1)
        .npi(1)
        .address("15550199")
        .build();
    let deliver = SmsDeliver::builder(oa.clone())
        .mms(true)
        .dcs(0)
        .service_centre_timestamp("25010112000000")
        .gsm7_text("Delivered by tpdu")
        .build()
        .unwrap();
    let mt = RpDataNetworkToMs::builder(deliver)
        .originator_address(oa)
        .build();
    let wire = mt.encode().unwrap();
    println!("Encoded MT RP-DATA ({} bytes): {wire:02x?}", wire.len());
}

/// Assemble a synthetic MO RP-DATA carrying an SMS-SUBMIT. In production this is
/// the body of a SIP MESSAGE from the UE — here we build one so the demo is
/// self-contained.
fn synthetic_mo(dest: &str, text: &str) -> Vec<u8> {
    let addr = SMSAddress {
        ton: 1,
        npi: 1,
        address: dest.into(),
    };
    let (ud, septets) = pack_gsm7(text).unwrap();
    let mut tpdu = vec![0x01u8, 0x01]; // SMS-SUBMIT first byte (mti=1), TP-MR
    tpdu.extend(addr.encode(false).unwrap()); // TP-DA
    tpdu.push(0); // TP-PID
    tpdu.push(0); // TP-DCS (GSM 7-bit)
    tpdu.push(septets as u8); // TP-UDL
    tpdu.extend(ud);
    let mut rp = vec![0x00u8, 0x01, 0x00, 0x00]; // RP-DATA, RP-MR, no RP-OA/RP-DA
    rp.push(tpdu.len() as u8);
    rp.extend(tpdu);
    rp
}

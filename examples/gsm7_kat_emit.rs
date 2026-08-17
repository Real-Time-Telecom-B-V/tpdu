//! Re-derive the known-answer vectors in `tests/gsm7_kat.rs` against a
//! third-party dissector.
//!
//! The vectors in that test are literals on purpose: nothing in this crate gets
//! a say in whether they are right, so a change that moves the packer and the
//! unpacker together cannot pass them. This example is how they were obtained,
//! and how to re-obtain them if you want to check them against a different
//! dissector or a newer Wireshark.
//!
//! ```text
//! cargo run --example gsm7_kat_emit > kat.txt
//! text2pcap -u 5060,5060 -l 1 kat.txt kat.pcap
//! tshark -r kat.pcap -V | grep 'SMS text:'
//! ```
//!
//! Each packet is a SIP MESSAGE carrying `application/vnd.3gpp.sms`, which is
//! how SMS-over-IMS transports RP-DATA + a TPDU, and what Wireshark's `gsm_sms`
//! dissector descends into. Read back the `SMS text:` line per frame and compare
//! it with the `# frame N:` comment above the corresponding hex block. A field
//! shown as `[Malformed]` or `[Unknown]`, or a missing `SMS text:`, is a bug in
//! our encoder rather than a limitation of the dissector.

use tpdu::{pack_gsm7, RpDataNetworkToMs, SMSAddress, SmsDeliver};

/// The same texts as `tests/gsm7_kat.rs`: base alphabet, the national block, the
/// Greek block, the full escape table, and the 7-septet CR-pad boundary.
const TEXTS: &[&str] = &[
    "hellohello",
    "hello",
    "1234567",
    "@£$¥èéùì",
    "ΔΦΓΛΩΠΨΣΘΞ",
    "a^b{c}d[e]f~g|h€",
    "Ærøskøbing ÄÖÑÜ§¿",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::new();

    for (i, text) in TEXTS.iter().enumerate() {
        let (user_data, septets) = pack_gsm7(text)?;

        let deliver = SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: false,
            tp_mti: 0,
            tp_originating_address: SMSAddress {
                ton: 0x01,
                npi: 0x01,
                address: "15550101".to_string(),
            },
            tp_pid: 0,
            tp_dcs: 0, // GSM-7 default alphabet, so the dissector decodes the text
            tp_service_centre_timestamp: "26081712000000".to_string(),
            tp_user_data_length: u8::try_from(septets)?,
            tp_user_data: user_data.clone(),
        };

        // Built with our own RP-DATA encoder so the dissector checks that layer
        // too, not just the TPDU inside it.
        let body = RpDataNetworkToMs {
            rp_message_type: 0x01, // RP-DATA (network -> MS)
            rp_message_reference: u8::try_from(i)?,
            rp_originator_address: Some(SMSAddress {
                ton: 0x01,
                npi: 0x01,
                address: "15550199".to_string(),
            }),
            rp_destination_address: None,
            sms_deliver: deliver,
        }
        .encode()?;

        let sip = format!(
            "MESSAGE sip:+15550102@ims.invalid SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKkat{i:04}\r\n\
             From: <sip:+15550101@ims.invalid>;tag=kat{i}\r\n\
             To: <sip:+15550102@ims.invalid>\r\n\
             Call-ID: kat{i}@192.0.2.1\r\n\
             CSeq: 1 MESSAGE\r\n\
             Max-Forwards: 70\r\n\
             Content-Type: application/vnd.3gpp.sms\r\n\
             Content-Length: {len}\r\n\
             \r\n",
            len = body.len()
        );

        let mut packet = sip.into_bytes();
        packet.extend_from_slice(&body);

        // text2pcap hex-dump form: offset then space-separated octets.
        out.push_str(&format!(
            "# frame {}: {:?}  septets={} packed={}\n",
            i + 1,
            text,
            septets,
            hex::encode(&user_data)
        ));
        for (offset, chunk) in packet.chunks(16).enumerate() {
            let bytes: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!("{:06x}  {}\n", offset * 16, bytes.join(" ")));
        }
        out.push('\n');
    }

    print!("{out}");
    Ok(())
}

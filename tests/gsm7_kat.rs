//! GSM-7 known-answer vectors, validated by a third-party dissector.
//!
//! Every other test in this crate builds its expectation from our own public
//! API, which is a round trip: a single change that moves both the packer and
//! the unpacker — a rotated alphabet, a flipped bit order, a different pad
//! septet — passes all of them. The expected bytes below are *literals*, so
//! nothing in this crate participates in deciding whether they are right.
//!
//! Provenance of the literals. Each `packed` value was produced by
//! `pack_gsm7`, wrapped in RP-DATA inside a SIP MESSAGE with
//! `Content-Type: application/vnd.3gpp.sms` (how SMS-over-IMS carries it, per
//! TS 24.011 / TS 23.040), and dissected with `tshark` 4.6.4. Wireshark's
//! `gsm_sms` dissector read every one back as the intended text with no
//! `[Malformed]` or `[Unknown]` field, and also confirmed TP-DCS as the GSM-7
//! default alphabet and TP-UDL as the septet count recorded here. Wireshark
//! does not share our bugs, so agreeing with it is evidence in a way a round
//! trip is not. `hellohello -> e8329bfd4697d9ec37` is additionally the vector
//! most widely published for GSM-7 packing.
//!
//! To re-derive these against a new dissector, emit the bytes with `pack_gsm7`,
//! feed a `text2pcap` hex dump of the SIP MESSAGE to `tshark -r x.pcap -V`, and
//! read the `SMS text:` line.
//!
//! Coverage is chosen so that a regression cannot hide: the base alphabet, the
//! national block at 0x00-0x1F, the Greek block, the escape table (each of
//! `^{}[]~|€` costing two septets), and the septet boundary at exactly 7
//! characters, where TS 23.038 §6.1.2.3.1 requires the 7 spare bits to be
//! padded with CR (0x0D) rather than zeros.

use tpdu::{pack_gsm7, unpack_gsm7};

/// `(text, septets, packed_hex)` — `packed_hex` is a literal, never computed.
const VECTORS: &[(&str, usize, &str)] = &[
    // Plain ASCII, 10 septets over 9 octets. The canonical published vector.
    ("hellohello", 10, "e8329bfd4697d9ec37"),
    // 5 septets: 35 bits, so 5 octets with 5 spare bits zero-padded.
    ("hello", 5, "e8329bfd06"),
    // 7 septets: exactly 49 bits. One bit short of 7 octets, so the spare 7
    // bits carry CR (0x0D) per TS 23.038 §6.1.2.3.1, not zeros. A packer that
    // zero-pads here produces ...dd00 -> a trailing '@' on a strict decoder.
    ("1234567", 7, "31d98c56b3dd00"),
    // The 0x00-0x1F national block: @ £ $ ¥ è é ù ì are code points 0x00-0x07.
    ("@£$¥èéùì", 8, "8080604028180e"),
    // Greek capitals from 0x10-0x1A. Distinct from the Latin lookalikes.
    ("ΔΦΓΛΩΠΨΣΘΞ", 10, "10c98452b15c30190d"),
    // Every escape-table character, two septets each: 8 plain + 8*2 = 24.
    (
        "a^b{c}d[e]f~g|h€",
        24,
        "e10d45bc418d3729f28657def8cc9bde7903446fca",
    ),
    // Nordic and the upper-case national characters, plus § and ¿.
    ("Ærøskøbing ÄÖÑÜ§¿", 17, "1c3963be6688d3ee3368cbed7abfe0"),
];

#[test]
fn pack_gsm7_matches_the_wireshark_validated_vectors() {
    for (text, septets, expected_hex) in VECTORS {
        let (packed, got_septets) = pack_gsm7(text).expect("pack_gsm7");
        assert_eq!(
            hex::encode(&packed),
            *expected_hex,
            "packed bytes for {text:?} do not match the validated vector"
        );
        assert_eq!(
            got_septets, *septets,
            "septet count for {text:?} (this is TP-UDL on a 7-bit DCS message)"
        );
    }
}

#[test]
fn unpack_gsm7_reads_the_validated_vectors_back() {
    // The other direction against the same literals: this is not a round trip,
    // because the input bytes are fixed rather than produced by our packer.
    for (text, septets, expected_hex) in VECTORS {
        let bytes = hex::decode(expected_hex).expect("vector hex");
        let decoded = unpack_gsm7(&bytes, *septets).expect("unpack_gsm7");
        assert_eq!(
            decoded, *text,
            "decoding the validated vector {expected_hex} gave the wrong text"
        );
    }
}

#[test]
fn the_seven_septet_boundary_pads_with_cr_not_zero() {
    // Called out on its own because it is the single easiest thing to get wrong
    // and the hardest to notice: it only bites when the septet count mod 8 is 7.
    let (packed, septets) = pack_gsm7("1234567").expect("pack_gsm7");
    assert_eq!(septets, 7);
    assert_eq!(packed.len(), 7, "7 septets occupy 49 bits, so 7 octets");
    // The final octet holds the last septet's spare bit plus the CR pad.
    assert_eq!(
        packed[6], 0x00,
        "the top bit of septet 7 plus a CR pad shifted into place"
    );
    assert_eq!(hex::encode(&packed), "31d98c56b3dd00");
}

#[test]
fn an_eight_septet_message_needs_no_padding_at_all() {
    // 8 septets = 56 bits = exactly 7 octets, the one case with no spare bits,
    // so nothing is padded and the CR rule must not fire.
    let (packed, septets) = pack_gsm7("@£$¥èéùì").expect("pack_gsm7");
    assert_eq!(septets, 8);
    assert_eq!(packed.len(), 7);
    assert_eq!(hex::encode(&packed), "8080604028180e");
}

#[test]
fn escape_characters_cost_two_septets_each() {
    // TP-UDL counts septets, not characters. An encoder that counted characters
    // would under-report by one per escape character and truncate the message on
    // the receiving side.
    for (text, expected) in [
        ("^", 2usize),
        ("{}", 4),
        ("[]", 4),
        ("~", 2),
        ("|", 2),
        ("€", 2),
        ("\\", 2),
        ("a€b", 4),
    ] {
        let (_, septets) = pack_gsm7(text).expect("pack_gsm7");
        assert_eq!(septets, expected, "septet count for {text:?}");
    }
}

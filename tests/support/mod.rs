//! Wireshark as an independent decoder for the bytes this crate emits.
//!
//! A round trip through our own encoder and decoder proves nothing about the
//! wire: a mistake shared by both passes it. Wireshark's `gsm_a_rp` and
//! `gsm_sms` dissectors were written by other people from the same
//! specifications, so having them read a field back with the value we meant is
//! evidence a round trip cannot give.
//!
//! [`assert_dissects`] takes one relay-layer message (TS 24.011), hands it to
//! `tshark` and compares dissected field values. The framing is the smallest
//! one Wireshark will take: the RP message is the whole packet, written with
//! `text2pcap` under a user link type that is mapped to the `gsm_a_rp`
//! dissector, which descends into the TPDU by itself.
//!
//! To look at a message by hand:
//!
//! ```text
//! echo '0000 06 09' > rp.txt
//! text2pcap -l 147 rp.txt rp.pcap
//! tshark -r rp.pcap -V \
//!   -o 'uat:user_dlts:"User 0 (DLT=147)","gsm_a_rp","0","","0",""'
//! ```
//!
//! When `tshark` or `text2pcap` is not installed the check is skipped with a
//! note on stderr and the test passes on its other assertions. Set
//! `TPDU_REQUIRE_TSHARK=1` to turn a missing tool into a failure.

#![allow(dead_code)] // each test file uses its own subset

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Maps the user link type `text2pcap -l 147` writes to the RP dissector.
const USER_LINK_TYPE: &str = r#"uat:user_dlts:"User 0 (DLT=147)","gsm_a_rp","0","","0","""#;

/// Text Wireshark puts in a dissection it could not make sense of. None of it
/// may appear for bytes we emitted: a field shown this way is our bug.
const TROUBLE: &[&str] = &[
    "Malformed",
    "Extraneous Data",
    "Missing Mandatory element",
    "Unexpected Data Length",
    "Short Data",
    "not implemented",
    "Unknown",
];

/// "Unknown" is also the name of type-of-number 000 and numbering plan 0000
/// (TS 23.040 §9.1.2.5), where it is a value and not a complaint.
const UNKNOWN_AS_A_VALUE: &[&str] = &["Type of number: Unknown", "Numbering plan"];

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn installed(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn scratch_directory() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "tpdu-tshark-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("create scratch directory");
    directory
}

fn tshark(directory: &PathBuf, arguments: &[&str]) -> String {
    let output = Command::new("tshark")
        .args(["-n", "-r"])
        .arg(directory.join("message.pcap"))
        .args(["-o", USER_LINK_TYPE])
        .args(arguments)
        // Keep the run independent of whoever is running it: no personal
        // profile, and times rendered in UTC.
        .env("XDG_CONFIG_HOME", directory)
        .env("TZ", "UTC")
        .output()
        .expect("run tshark");
    assert!(
        output.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Dissect `rp_message` with tshark and return the value of each of `fields`,
/// or `None` when the tools are not installed.
///
/// A field that occurs more than once comes back with its values joined by
/// `;`, one that does not occur as an empty string. Panics if Wireshark flags
/// anything in the message as malformed, unknown or left over.
pub fn dissect(rp_message: &[u8], fields: &[&str]) -> Option<Vec<String>> {
    if !(installed("tshark") && installed("text2pcap")) {
        assert!(
            std::env::var_os("TPDU_REQUIRE_TSHARK").is_none(),
            "TPDU_REQUIRE_TSHARK is set but tshark / text2pcap are not installed"
        );
        eprintln!("skipping the Wireshark check: tshark / text2pcap are not installed");
        return None;
    }

    let directory = scratch_directory();
    let mut dump = String::from("000000");
    for octet in rp_message {
        write!(dump, " {octet:02x}").expect("write to a string");
    }
    dump.push('\n');
    std::fs::write(directory.join("message.txt"), dump).expect("write hex dump");

    let converted = Command::new("text2pcap")
        .args(["-q", "-l", "147"])
        .arg(directory.join("message.txt"))
        .arg(directory.join("message.pcap"))
        .output()
        .expect("run text2pcap");
    assert!(
        converted.status.success(),
        "text2pcap failed: {}",
        String::from_utf8_lossy(&converted.stderr)
    );

    let tree = tshark(&directory, &["-V"]);
    assert!(
        tree.contains("GSM A-I/F RP"),
        "tshark did not dissect {} as an RP message:\n{tree}",
        hex::encode(rp_message)
    );
    for line in tree.lines() {
        if UNKNOWN_AS_A_VALUE.iter().any(|value| line.contains(value)) {
            continue;
        }
        for trouble in TROUBLE {
            assert!(
                !line.contains(trouble),
                "tshark reports {trouble:?} for {}:\n{tree}",
                hex::encode(rp_message)
            );
        }
    }

    let mut arguments = vec!["-T", "fields", "-E", "occurrence=a", "-E", "aggregator=;"];
    for field in fields {
        arguments.extend(["-e", field]);
    }
    let line = tshark(&directory, &arguments);
    let values: Vec<String> = line
        .trim_end_matches(['\r', '\n'])
        .split('\t')
        .map(str::to_owned)
        .collect();
    assert_eq!(
        values.len(),
        fields.len(),
        "tshark returned {} values for {} fields:\n{tree}",
        values.len(),
        fields.len()
    );

    let _ = std::fs::remove_dir_all(&directory);
    Some(values)
}

/// Assert that tshark reads `rp_message` back with each field at the expected
/// value. Skipped, with a note on stderr, when tshark is not installed.
pub fn assert_dissects(rp_message: &[u8], expected: &[(&str, &str)]) {
    let fields: Vec<&str> = expected.iter().map(|(field, _)| *field).collect();
    let Some(values) = dissect(rp_message, &fields) else {
        return;
    };
    for ((field, want), got) in expected.iter().zip(&values) {
        assert_eq!(
            got,
            want,
            "tshark field {field} for {}",
            hex::encode(rp_message)
        );
    }
}

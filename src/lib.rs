//! SMS Transfer-layer PDU codec — 3GPP **TS 23.040** / **TS 23.038** / **TS 24.011**.
//!
//! Encodes and decodes the protocol data units that carry SMS between handsets,
//! IMS, and signalling cores:
//!
//! - **RP-DATA** (MS→Network and Network→MS), **RP-ACK**, **RP-ERROR** and
//!   **RP-SMMA** — the relay layer used on the Gm interface (SIP MESSAGE body)
//!   and in MAP/Diameter MO/MT-Forward-SM.
//! - **SMS-SUBMIT** / **SMS-DELIVER** / **SMS-STATUS-REPORT** TPDUs and the
//!   **SMS-SUBMIT-REPORT** / **SMS-DELIVER-REPORT** that acknowledge them.
//! - **GSM 7-bit** (default alphabet, septet packing per TS 23.038
//!   §6.1.2.1.1) and UCS-2 user data; **User-Data-Header** (concatenation,
//!   etc.), including the fill bits a header needs in front of 7-bit text.
//! - BCD and GSM-7 alphanumeric **SMS addresses** (TON/NPI).
//!
//! Pure Rust, no async, no I/O — just bytes in, bytes out. The same codec is
//! exposed to Python (`import tpdu`) when built with the `python` feature; the
//! Python API mirrors this one.

use byteorder::ReadBytesExt;
use gsm7::{Gsm7Reader, Gsm7Writer};
use std::fmt;
use std::io::{Cursor, Read};
use tracing::debug;

mod builder;
pub use builder::{
    RpAckBuilder, RpDataMsToNetworkBuilder, RpDataNetworkToMsBuilder,
    RpDataNetworkToMsStatusReportBuilder, RpErrorMsToNetworkBuilder, RpErrorNetworkToMsBuilder,
    RpSmmaBuilder, SMSAddressBuilder, SmsDeliverBuilder, SmsDeliverReportBuilder,
    SmsStatusReportBuilder, SmsSubmitBuilder, SmsSubmitReportBuilder, UserDataHeaderBuilder,
};

#[cfg(feature = "python")]
mod python;
#[cfg(feature = "python")]
pub use python::{populate, register};

/// A TPDU / RP-DATA codec error.
///
/// Opaque newtype around a human-readable, spec-referenced message (e.g.
/// "Unable to read TP-User-Data buffer …"). Implements [`std::error::Error`] so
/// it slots into `?` and `Box<dyn Error>` call sites; read [`Error::message`]
/// or the `Display` form for the detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    /// The underlying message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_string())
    }
}

// ── Low-level readers ────────────────────────────────────────────────────────

fn read_octet(cursor: &mut Cursor<&[u8]>, what: &str) -> Result<u8, Error> {
    cursor
        .read_u8()
        .map_err(|e| format!("Unable to read {what}: {e}").into())
}

fn read_octets(cursor: &mut Cursor<&[u8]>, length: usize, what: &str) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0; length];
    cursor
        .read_exact(&mut buffer)
        .map_err(|e| format!("Unable to read {what} ({length} octets): {e}"))?;
    Ok(buffer)
}

fn remaining(cursor: &Cursor<&[u8]>) -> usize {
    let position = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    cursor.get_ref().len().saturating_sub(position)
}

// ── TP-Data-Coding-Scheme (TS 23.038 §4) ─────────────────────────────────────

/// How the TP-User-Data of a message is coded, derived from TP-DCS per
/// TS 23.038 §4. It decides what TP-User-Data-Length counts (TS 23.040
/// §9.2.3.16): septets for [`Gsm7Bit`](UserDataCoding::Gsm7Bit), octets for
/// everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataCoding {
    /// Uncompressed GSM 7-bit default alphabet, packed in septets.
    Gsm7Bit,
    /// Uncompressed 8-bit data.
    EightBit,
    /// Uncompressed UCS-2.
    Ucs2,
    /// Compressed text (TS 23.042), whatever the character set underneath.
    Compressed,
}

/// Classify a TP-DCS octet per TS 23.038 §4.
///
/// The general and automatic-deletion groups (`00xx` / `01xx`) carry the
/// character set in bits 3-2 whether or not bit 4 flags a message class, so
/// `0x10`-`0x13` are 7-bit just like `0x00`. Group `1111` carries it in bit 2,
/// the message-waiting groups `1100` / `1101` are 7-bit and `1110` is UCS-2.
/// Reserved codings "shall be assumed to be the GSM 7 bit default alphabet".
pub fn user_data_coding(dcs: u8) -> UserDataCoding {
    match dcs >> 4 {
        0x0..=0x7 => {
            if dcs & 0x20 != 0 {
                UserDataCoding::Compressed
            } else {
                match (dcs >> 2) & 0x03 {
                    0x1 => UserDataCoding::EightBit,
                    0x2 => UserDataCoding::Ucs2,
                    _ => UserDataCoding::Gsm7Bit,
                }
            }
        }
        0xE => UserDataCoding::Ucs2,
        0xF => {
            if dcs & 0x04 != 0 {
                UserDataCoding::EightBit
            } else {
                UserDataCoding::Gsm7Bit
            }
        }
        _ => UserDataCoding::Gsm7Bit,
    }
}

/// Octets occupied by a TP-User-Data whose TP-User-Data-Length is `length`.
fn user_data_octets(coding: UserDataCoding, length: u8) -> usize {
    match coding {
        UserDataCoding::Gsm7Bit => (usize::from(length) * 7).div_ceil(8),
        _ => usize::from(length),
    }
}

/// The largest TP-User-Data any TPDU can carry (TS 23.040 §9.2.2.2).
const MAX_USER_DATA_OCTETS: usize = 140;

/// Refuse to emit a TP-User-Data whose octet count contradicts its TP-UDL: the
/// receiver would either cut the message short or read past the TPDU.
fn check_user_data(what: &str, dcs: u8, length: u8, user_data: &[u8]) -> Result<(), Error> {
    let coding = user_data_coding(dcs);
    let expected = user_data_octets(coding, length);
    if user_data.len() != expected {
        let unit = match coding {
            UserDataCoding::Gsm7Bit => "septets",
            _ => "octets",
        };
        return Err(format!(
            "{what}: TP-UDL {length} {unit} (TP-DCS 0x{dcs:02x}) needs {expected} octets of \
             TP-User-Data, got {}",
            user_data.len()
        )
        .into());
    }
    if user_data.len() > MAX_USER_DATA_OCTETS {
        return Err(format!(
            "{what}: TP-User-Data is {} octets, the maximum is {MAX_USER_DATA_OCTETS}",
            user_data.len()
        )
        .into());
    }
    Ok(())
}

// ── GSM 7-bit packing (TS 23.038 §6.1.2.1.1) ─────────────────────────────────

const GSM7_ESCAPE: u8 = 0x1B;

/// Septets one character costs: two for the extension table of TS 23.038
/// §6.2.1.1 (escape + code), one otherwise.
fn gsm7_septet_count(character: char) -> usize {
    match character {
        '\x0C' | '^' | '{' | '}' | '\\' | '[' | '~' | ']' | '|' | '€' => 2,
        _ => 1,
    }
}

/// Pack `text` as septets that start `fill_bits` bits into the first octet,
/// returning the octets and the number of septets the text occupies.
///
/// Spare bits, the fill bits in front included, are zero: TS 23.038
/// §6.1.2.1.1 packs SMS "by completing the octets with zeros on the left". (The
/// CR padding of §6.1.2.3.1 is a USSD rule and does not apply here.)
fn pack_septets(text: &str, fill_bits: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut writer = Gsm7Writer::new(Vec::new());
    let io_error = |e: std::io::Error| Error(format!("GSM 7-bit packing failed: {e}"));

    for _ in 0..fill_bits {
        writer.write_bit(false).map_err(io_error)?;
    }
    let mut septets = 0;
    for character in text.chars() {
        writer.write_char(character).map_err(|_| {
            format!("{character:?} is not in the GSM 7-bit default alphabet (TS 23.038 §6.2.1)")
        })?;
        septets += gsm7_septet_count(character);
    }
    // Zero-fill to the octet boundary ourselves so the writer has nothing left
    // to pad when it is finished.
    let used_bits = fill_bits + septets * 7;
    for _ in 0..(8 - used_bits % 8) % 8 {
        writer.write_bit(false).map_err(io_error)?;
    }
    let octets = writer.into_writer().map_err(io_error)?;
    Ok((octets, septets))
}

/// The septet at `index`, counting from `fill_bits` bits into `data`.
fn septet_at(data: &[u8], fill_bits: usize, index: usize) -> u8 {
    let bit = fill_bits + index * 7;
    let (octet, shift) = (bit / 8, bit % 8);
    let low = u16::from(data.get(octet).copied().unwrap_or(0));
    let high = u16::from(data.get(octet + 1).copied().unwrap_or(0));
    ((((high << 8) | low) >> shift) & 0x7F) as u8
}

/// The character a septet stands for in the default alphabet table of
/// TS 23.038 §6.2.1 (the escape code itself reads as a space, NOTE 1).
fn default_alphabet_character(septet: u8) -> char {
    if septet == GSM7_ESCAPE {
        return ' ';
    }
    Gsm7Reader::new(Cursor::new([septet]))
        .next()
        .and_then(Result::ok)
        .unwrap_or(' ')
}

/// Unpack exactly `septets` septets that start `fill_bits` bits into `data`.
///
/// The count comes from TP-UDL, so padding after the last septet is never read
/// as a character. An escape followed by a code the extension table does not
/// define falls back to the default alphabet character for that code, as
/// TS 23.038 §6.2.1.1 requires of a receiver; a lone escape reads as a space.
fn unpack_septets(data: &[u8], fill_bits: usize, septets: usize) -> Result<String, Error> {
    let needed_bits = fill_bits + septets * 7;
    if data.len() * 8 < needed_bits {
        return Err(format!(
            "{septets} septets need {} octets, only {} present",
            needed_bits.div_ceil(8),
            data.len()
        )
        .into());
    }

    let fill = u32::try_from(fill_bits).map_err(|_| "fill bits out of range")?;
    let mut reader = Gsm7Reader::new_with_bit_offset(Cursor::new(data), fill)
        .map_err(|e| format!("gsm7 decode: {e}"))?;

    let mut text = String::with_capacity(septets);
    let mut consumed = 0;
    while consumed < septets {
        match reader.next() {
            Some(Ok(character)) => {
                let width = gsm7_septet_count(character);
                if consumed + width > septets {
                    // The last septet TP-UDL counts is an escape; what follows
                    // it is padding, not part of the message.
                    text.push(' ');
                    break;
                }
                text.push(character);
                consumed += width;
            }
            // The reader fails only after an escape: either the code after it
            // is not in the extension table, or the data ended.
            Some(Err(_)) | None => {
                if consumed + 2 > septets {
                    text.push(' ');
                    break;
                }
                text.push(default_alphabet_character(septet_at(
                    data,
                    fill_bits,
                    consumed + 1,
                )));
                consumed += 2;
            }
        }
    }
    Ok(text)
}

/// Pack a Unicode string into GSM 7-bit septets per TS 23.038 §6.1.2.1.1.
/// Returns `(packed_bytes, septet_count)` where `septet_count` is the
/// value to use for TP-User-Data-Length on a 7-bit DCS message
/// (extension chars `^{}\[~]|€` and form-feed count as 2 septets each).
/// Spare bits in the last octet are zero.
pub fn pack_gsm7(input: &str) -> Result<(Vec<u8>, usize), Error> {
    pack_septets(input, 0)
}

/// Unpack exactly `septets` septets from a packed GSM 7-bit buffer per
/// TS 23.038 §6.1.2.1.1.
///
/// `septets` is the TP-User-Data-Length of the message. Whatever follows the
/// last septet in `data` is padding and is ignored, so a message of seven
/// septets never grows a spurious eighth character, and a genuine trailing `@`
/// is preserved. Fails if `data` is too short to hold `septets` septets.
pub fn unpack_gsm7(data: &[u8], septets: usize) -> Result<String, Error> {
    unpack_septets(data, 0, septets)
}

/// Septets a user-data header of `header_octets` octets occupies, fill bits
/// included (TS 23.040 §9.2.3.24).
fn header_septets(header_octets: usize) -> usize {
    (header_octets * 8).div_ceil(7)
}

/// Check that `header` is a whole user-data header: the UDHL octet followed by
/// exactly that many octets.
fn check_header(header: &[u8]) -> Result<(), Error> {
    match header.first() {
        Some(&length) if usize::from(length) + 1 == header.len() => Ok(()),
        Some(&length) => Err(format!(
            "user-data header is {} octets but its length octet says {length} follow",
            header.len()
        )
        .into()),
        None => Err("user-data header is empty, the length octet is missing".into()),
    }
}

/// Build the complete TP-User-Data of a GSM 7-bit message that carries a
/// user-data header, per TS 23.040 §9.2.3.24.
///
/// `header` is the whole header as it goes on the wire: the UDHL octet followed
/// by the information elements (what [`UserDataHeader::encode`] returns). The
/// header stays in octets, fill bits bring it to a septet boundary, and the
/// text is packed from there. Returns `(tp_user_data, tp_user_data_length)`
/// where the length counts septets: those of the header, fill bits included,
/// plus those of the text (§9.2.3.16).
///
/// Set TP-UDHI on the TPDU that carries the result.
pub fn pack_gsm7_with_header(header: &[u8], text: &str) -> Result<(Vec<u8>, usize), Error> {
    check_header(header)?;
    let in_header = header_septets(header.len());
    let fill_bits = in_header * 7 - header.len() * 8;
    let (packed, in_text) = pack_septets(text, fill_bits)?;

    let mut user_data = header.to_vec();
    user_data.extend_from_slice(&packed);
    Ok((user_data, in_header + in_text))
}

/// Split the TP-User-Data of a GSM 7-bit message that carries a user-data
/// header (TP-UDHI set) into `(header, text)`, per TS 23.040 §9.2.3.24.
///
/// `septets` is the TP-User-Data-Length of the message. The returned header is
/// the UDHL octet followed by the information elements.
pub fn unpack_gsm7_with_header(data: &[u8], septets: usize) -> Result<(Vec<u8>, String), Error> {
    let header_length = match data.first() {
        Some(&length) => usize::from(length) + 1,
        None => return Err("TP-User-Data is empty, the header length octet is missing".into()),
    };
    let header = data.get(..header_length).ok_or_else(|| {
        format!(
            "user-data header is {header_length} octets, only {} present",
            data.len()
        )
    })?;
    let in_header = header_septets(header_length);
    let in_text = septets.checked_sub(in_header).ok_or_else(|| {
        format!("user-data header takes {in_header} septets, TP-UDL is only {septets}")
    })?;
    let fill_bits = in_header * 7 - header_length * 8;
    let text = unpack_septets(&data[header_length..], fill_bits, in_text)?;
    Ok((header.to_vec(), text))
}

// ── User-Data-Header ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDataHeader {
    pub user_data_header_length: u8,
    pub user_data_header_value: Vec<u8>,
}

impl UserDataHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.user_data_header_length);
        data.extend_from_slice(&self.user_data_header_value);
        data
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let user_data_header_length = cursor
            .read_u8()
            .map_err(|e| format!("Unable to read User Data Header Length: {}", e))?;

        let mut user_data_header_value = vec![0; user_data_header_length as usize];
        cursor
            .read_exact(&mut user_data_header_value)
            .map_err(|e| format!("Unable to read User Data Header Value: {}", e))?;

        Ok(UserDataHeader {
            user_data_header_length,
            user_data_header_value,
        })
    }
}

/// Split a TP-User-Data as received into its header and the form the decoder
/// surfaces as `tp_user_data`: the header octets (when TP-UDHI is set) followed
/// by the short message, which is UTF-8 text for the GSM 7-bit alphabet and the
/// octets as received for every other coding.
fn split_user_data(
    dcs: u8,
    header_indicator: bool,
    length: u8,
    raw: &[u8],
) -> Result<(Option<UserDataHeader>, Vec<u8>), Error> {
    let seven_bit = user_data_coding(dcs) == UserDataCoding::Gsm7Bit;

    if !header_indicator {
        let user_data = if seven_bit {
            unpack_septets(raw, 0, usize::from(length))
                .map_err(|e| format!("Unable to decode 7-bit TP-User-Data: {e}"))?
                .into_bytes()
        } else {
            raw.to_vec()
        };
        return Ok((None, user_data));
    }

    let header = UserDataHeader::decode(&mut Cursor::new(raw))
        .map_err(|e| format!("Unable to decode User Data Header: {e}"))?;
    let user_data = if seven_bit {
        let (header_octets, text) = unpack_gsm7_with_header(raw, usize::from(length))
            .map_err(|e| format!("Unable to decode 7-bit TP-User-Data: {e}"))?;
        let mut user_data = header_octets;
        user_data.extend_from_slice(text.as_bytes());
        user_data
    } else {
        raw.to_vec()
    };
    Ok((Some(header), user_data))
}

// ── Time stamps (TS 23.040 §9.2.3.11) ────────────────────────────────────────

/// Encode a 7-octet semi-octet time (TP-SCTS, TP-DT, absolute TP-VP) from its
/// 14 digits.
fn encode_time(digits: &str, what: &str) -> Result<[u8; 7], Error> {
    if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{what} must be 14 semi-octet digits (yymmddHHMMSS and two for the time zone), \
             got {digits:?}"
        )
        .into());
    }
    // Semi-octet representation puts the first digit of each pair in bits 3-0,
    // so swap every pair before reading it as an octet.
    let mut swapped = String::with_capacity(14);
    for pair in digits.as_bytes().chunks_exact(2) {
        swapped.push(char::from(pair[1]));
        swapped.push(char::from(pair[0]));
    }
    let octets =
        hex::decode(&swapped).map_err(|e| format!("Unable to encode {what} {digits:?}: {e}"))?;
    <[u8; 7]>::try_from(octets.as_slice())
        .map_err(|_| format!("Unable to encode {what} {digits:?}").into())
}

/// Decode a 7-octet semi-octet time into its 14 digits, exactly as received.
fn decode_time(cursor: &mut Cursor<&[u8]>, what: &str) -> Result<String, Error> {
    let octets = read_octets(cursor, 7, what)?;
    let mut digits = String::with_capacity(14);
    for octet in octets {
        for nibble in [octet & 0x0F, octet >> 4] {
            digits.push(
                char::from_digit(u32::from(nibble), 16).map_or('0', |c| c.to_ascii_uppercase()),
            );
        }
    }
    Ok(digits)
}

/// Build the 14-digit string the time fields of this crate take (TP-SCTS,
/// TP-Discharge-Time, absolute TP-Validity-Period) from its parts, per
/// TS 23.040 §9.2.3.11.
///
/// `year` is the two-digit year and the rest is local time.
/// `time_zone_quarter_hours` is the offset of that local time from GMT in
/// quarters of an hour, negative west of Greenwich. The sign is carried in
/// bit 3 of the seventh octet, which is the top bit of the first of the two
/// time-zone digits, so a negative offset shows up as a first digit of `8` or
/// above (`-20` quarters is `"A0"`).
pub fn timestamp_digits(
    year: u8,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    time_zone_quarter_hours: i8,
) -> Result<String, Error> {
    let fields = [
        ("year", year, 0, 99),
        ("month", month, 1, 12),
        ("day", day, 1, 31),
        ("hour", hour, 0, 23),
        ("minute", minute, 0, 59),
        ("second", second, 0, 59),
    ];
    let mut digits = String::with_capacity(14);
    for (name, value, low, high) in fields {
        if value < low || value > high {
            return Err(format!("time stamp {name} {value} is outside {low}..={high}").into());
        }
        digits.push_str(&format!("{value:02}"));
    }
    let quarters = time_zone_quarter_hours.unsigned_abs();
    if quarters > 79 {
        return Err(format!(
            "time zone of {time_zone_quarter_hours} quarter hours does not fit the two \
             semi-octets of the field"
        )
        .into());
    }
    let sign = if time_zone_quarter_hours < 0 { 8 } else { 0 };
    digits.push_str(&format!("{:X}{}", quarters / 10 + sign, quarters % 10));
    Ok(digits)
}

// ── Addresses (TS 23.040 §9.1.2.5, TS 24.011 §8.2.5.1 / §8.2.5.2) ────────────

/// Type-of-number value for an alphanumeric address.
const TYPE_OF_NUMBER_ALPHANUMERIC: u8 = 0x05;
/// Address-Value octets a TP address can carry: 12 minus length and type.
const MAX_ADDRESS_VALUE_OCTETS: usize = 10;

/// An SMS address.
///
/// `address` holds the digits for a numeric address. Besides `0`-`9` the
/// semi-octet values above nine are written as TS 23.040 §9.1.2.3 has a mobile
/// display them: `*`, `#`, `a`, `b` and `c`. With type-of-number 5 it holds the
/// alphanumeric text instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMSAddress {
    pub ton: u8,
    pub npi: u8,
    pub address: String,
}

fn semi_octet_from_character(character: char) -> Option<u8> {
    match character {
        '0'..='9' => character.to_digit(10).and_then(|d| u8::try_from(d).ok()),
        '*' => Some(0xA),
        '#' => Some(0xB),
        'a' => Some(0xC),
        'b' => Some(0xD),
        'c' => Some(0xE),
        _ => None,
    }
}

fn character_from_semi_octet(semi_octet: u8) -> Option<char> {
    match semi_octet {
        0..=9 => Some(char::from(b'0' + semi_octet)),
        0xA => Some('*'),
        0xB => Some('#'),
        0xC => Some('a'),
        0xD => Some('b'),
        0xE => Some('c'),
        // 1111 is the fill for an odd number of digits, never a digit.
        _ => None,
    }
}

impl SMSAddress {
    /// Encode the address.
    ///
    /// With `length_as_bytes` false this is the transfer-layer form of
    /// TS 23.040 §9.1.2.5 (TP-DA, TP-OA, TP-RA): the length octet counts the
    /// useful semi-octets of the value, so the digits of a number and
    /// `ceil(septets * 7 / 4)` for an alphanumeric address. With
    /// `length_as_bytes` true it is the relay-layer form of TS 24.011 §8.2.5.1
    /// (RP-OA, RP-DA), where the length octet counts the octets that follow it
    /// and only numbers are allowed.
    pub fn encode(&self, length_as_bytes: bool) -> Result<Vec<u8>, Error> {
        if self.ton > 0x07 || self.npi > 0x0F {
            return Err(format!(
                "type-of-number {} / numbering-plan {} do not fit their 3 and 4 bit fields",
                self.ton, self.npi
            )
            .into());
        }
        let type_of_address = 0x80 | (self.ton << 4) | self.npi;

        let (length, value) = if self.ton == TYPE_OF_NUMBER_ALPHANUMERIC {
            if length_as_bytes {
                return Err(
                    "an RP address cannot be alphanumeric, TS 23.040 §9.1.2.5 allows that at the \
                     transfer layer only"
                        .into(),
                );
            }
            let (value, septets) = pack_septets(&self.address, 0)
                .map_err(|e| format!("Failed to encode address: {e}"))?;
            ((septets * 7).div_ceil(4), value)
        } else {
            let semi_octets = self
                .address
                .chars()
                .map(|c| {
                    semi_octet_from_character(c).ok_or_else(|| {
                        Error(format!(
                            "{c:?} in address {:?} is not a digit, '*', '#', 'a', 'b' or 'c'",
                            self.address
                        ))
                    })
                })
                .collect::<Result<Vec<u8>, Error>>()?;
            let value: Vec<u8> = semi_octets
                .chunks(2)
                .map(|pair| (pair.get(1).copied().unwrap_or(0x0F) << 4) | pair[0])
                .collect();
            let length = if length_as_bytes {
                value.len() + 1
            } else {
                semi_octets.len()
            };
            (length, value)
        };

        if value.len() > MAX_ADDRESS_VALUE_OCTETS {
            return Err(format!(
                "address {:?} needs {} octets, the maximum is {MAX_ADDRESS_VALUE_OCTETS}",
                self.address,
                value.len()
            )
            .into());
        }

        let mut data = Vec::with_capacity(value.len() + 2);
        data.push(u8::try_from(length).map_err(|_| "address length out of range")?);
        data.push(type_of_address);
        data.extend_from_slice(&value);
        Ok(data)
    }
}

/// Decode an address. `relay_layer` selects the RP form (the length octet
/// counts the octets after it, zero meaning the element is empty) over the TP
/// form (the length octet counts semi-octets and the type-of-address octet is
/// always there, even in front of no digits at all).
fn decode_sms_address(
    cursor: &mut Cursor<&[u8]>,
    relay_layer: bool,
) -> Result<Option<SMSAddress>, Error> {
    let length = usize::from(read_octet(cursor, "address length")?);

    if relay_layer && length == 0 {
        return Ok(None);
    }

    let type_of_address = read_octet(cursor, "TON/NPI")?;
    let ton = (type_of_address >> 4) & 0x07;
    let npi = type_of_address & 0x0F;

    debug!("Address Length: {}, TON/NPI: {}/{}", length, ton, npi);

    let value_octets = if relay_layer {
        length - 1
    } else {
        length.div_ceil(2)
    };
    let value = read_octets(cursor, value_octets, "address value")?;

    let address = if !relay_layer && ton == TYPE_OF_NUMBER_ALPHANUMERIC {
        unpack_septets(&value, 0, length * 4 / 7)
            .map_err(|e| format!("Unable to decode alphanumeric address: {e}"))?
    } else {
        let semi_octets = if relay_layer {
            value_octets * 2
        } else {
            length
        };
        value
            .iter()
            .flat_map(|octet| [octet & 0x0F, octet >> 4])
            .take(semi_octets)
            .filter_map(character_from_semi_octet)
            .collect()
    };

    Ok(Some(SMSAddress { ton, npi, address }))
}

fn decode_transfer_layer_address(
    cursor: &mut Cursor<&[u8]>,
    what: &str,
) -> Result<SMSAddress, Error> {
    decode_sms_address(cursor, false)
        .map_err(|e| format!("Could not decode {what}: {e}"))?
        .ok_or_else(|| format!("{what} is missing").into())
}

// ── TP-Validity-Period (TS 23.040 §9.2.3.12) ─────────────────────────────────

/// TP-VPF value for "TP-VP field not present" (TS 23.040 §9.2.3.3).
pub const VALIDITY_PERIOD_FORMAT_NONE: u8 = 0b00;
/// TP-VPF value for the enhanced format, bit 4 clear and bit 3 set.
pub const VALIDITY_PERIOD_FORMAT_ENHANCED: u8 = 0b01;
/// TP-VPF value for the relative format, bit 4 set and bit 3 clear.
pub const VALIDITY_PERIOD_FORMAT_RELATIVE: u8 = 0b10;
/// TP-VPF value for the absolute format, bits 4 and 3 set.
pub const VALIDITY_PERIOD_FORMAT_ABSOLUTE: u8 = 0b11;

/// TP-Validity-Period in one of the three formats TP-VPF selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidityPeriod {
    /// One octet, read with the table of TS 23.040 §9.2.3.12.1.
    Relative(u8),
    /// Seven octets coded like TP-SCTS (§9.2.3.12.2), held as the same
    /// 14-digit string the time-stamp fields use.
    Absolute(String),
    /// Seven octets, the first of which says how the rest is used
    /// (§9.2.3.12.3). Held exactly as on the wire.
    Enhanced([u8; 7]),
}

impl ValidityPeriod {
    /// The TP-VPF value that announces this format.
    pub fn format(&self) -> u8 {
        match self {
            ValidityPeriod::Relative(_) => VALIDITY_PERIOD_FORMAT_RELATIVE,
            ValidityPeriod::Absolute(_) => VALIDITY_PERIOD_FORMAT_ABSOLUTE,
            ValidityPeriod::Enhanced(_) => VALIDITY_PERIOD_FORMAT_ENHANCED,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            ValidityPeriod::Relative(value) => Ok(vec![*value]),
            ValidityPeriod::Absolute(digits) => {
                Ok(encode_time(digits, "TP-Validity-Period")?.to_vec())
            }
            ValidityPeriod::Enhanced(octets) => Ok(octets.to_vec()),
        }
    }

    fn decode(cursor: &mut Cursor<&[u8]>, format: u8) -> Result<Option<Self>, Error> {
        match format & 0x03 {
            VALIDITY_PERIOD_FORMAT_RELATIVE => Ok(Some(ValidityPeriod::Relative(read_octet(
                cursor,
                "TP-Validity-Period",
            )?))),
            VALIDITY_PERIOD_FORMAT_ABSOLUTE => Ok(Some(ValidityPeriod::Absolute(decode_time(
                cursor,
                "TP-Validity-Period",
            )?))),
            VALIDITY_PERIOD_FORMAT_ENHANCED => {
                let octets = read_octets(cursor, 7, "TP-Validity-Period")?;
                let octets = <[u8; 7]>::try_from(octets.as_slice())
                    .map_err(|_| "Unable to read TP-Validity-Period")?;
                Ok(Some(ValidityPeriod::Enhanced(octets)))
            }
            _ => Ok(None),
        }
    }
}

// ── Transfer-layer PDUs (TS 23.040 §9.2.2) ───────────────────────────────────

const MTI_DELIVER: u8 = 0b00;
const MTI_SUBMIT: u8 = 0b01;
const MTI_STATUS_REPORT: u8 = 0b10;

fn bit(octet: u8, number: u8) -> bool {
    (octet >> number) & 0x01 == 1
}

/// SMS-SUBMIT (TS 23.040 §9.2.2.2).
///
/// `tp_vpf` is the two-bit TP-Validity-Period-Format of §9.2.3.3 (see the
/// `VALIDITY_PERIOD_FORMAT_*` constants) and always agrees with
/// `tp_validity_period`.
///
/// The user data is held three ways. `tp_user_data_raw` is the TP-User-Data
/// exactly as on the wire and is what [`SmsSubmit::encode`] emits, with
/// `tp_user_data_length` as its TP-UDL. `tp_user_data_header` is the header
/// when TP-UDHI is set. `tp_user_data` is the readable form: the header octets
/// (when TP-UDHI is set) followed by the short message, which is UTF-8 text
/// when TP-DCS selects the GSM 7-bit default alphabet and the octets as
/// received for every other coding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsSubmit {
    pub tp_rp: bool,
    pub tp_udhi: bool,
    pub tp_srr: bool,
    pub tp_mti: u8,
    pub tp_rd: bool,
    pub tp_vpf: u8,
    pub tp_mr: u8,
    pub tp_destination_address: Option<SMSAddress>,
    pub tp_pid: u8,
    pub tp_dcs: u8,
    pub tp_validity_period: Option<ValidityPeriod>,
    pub tp_user_data_length: u8,
    pub tp_user_data_raw: Vec<u8>,
    pub tp_user_data_header: Option<UserDataHeader>,
    pub tp_user_data: Vec<u8>,
}

impl SmsSubmit {
    /// Encode to wire bytes per TS 23.040 §9.2.2.2.
    ///
    /// The TP-User-Data emitted is `tp_user_data_raw` under
    /// `tp_user_data_length`. Fails rather than emit a TPDU whose TP-VPF
    /// disagrees with its validity period, or whose TP-UDL disagrees with the
    /// user data.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.tp_mti != MTI_SUBMIT {
            return Err(format!("TP-MTI {} is not SMS-SUBMIT (1)", self.tp_mti).into());
        }
        let format = self
            .tp_validity_period
            .as_ref()
            .map_or(VALIDITY_PERIOD_FORMAT_NONE, ValidityPeriod::format);
        if self.tp_vpf != format {
            return Err(format!(
                "TP-VPF {} does not match the validity period, which needs TP-VPF {format}",
                self.tp_vpf
            )
            .into());
        }
        let destination = self
            .tp_destination_address
            .as_ref()
            .ok_or("SMS-SUBMIT needs a TP-Destination-Address")?;
        check_user_data(
            "SMS-SUBMIT",
            self.tp_dcs,
            self.tp_user_data_length,
            &self.tp_user_data_raw,
        )?;

        let mut data = vec![
            (self.tp_rp as u8) << 7
                | (self.tp_udhi as u8) << 6
                | (self.tp_srr as u8) << 5
                | self.tp_vpf << 3
                | (self.tp_rd as u8) << 2
                | MTI_SUBMIT,
            self.tp_mr,
        ];
        data.append(&mut destination.encode(false)?);
        data.push(self.tp_pid);
        data.push(self.tp_dcs);
        if let Some(validity_period) = &self.tp_validity_period {
            data.append(&mut validity_period.encode()?);
        }
        data.push(self.tp_user_data_length);
        data.extend_from_slice(&self.tp_user_data_raw);
        Ok(data)
    }
}

/// SMS-DELIVER (TS 23.040 §9.2.2.1).
///
/// `tp_user_data` is the TP-User-Data exactly as on the wire (packed septets
/// for a 7-bit TP-DCS, a header in front when TP-UDHI is set) and
/// `tp_user_data_length` its TP-UDL. `tp_service_centre_timestamp` is the 14
/// digits of §9.2.3.11, see [`timestamp_digits`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsDeliver {
    pub tp_rp: bool,
    pub tp_udhi: bool,
    pub tp_sri: bool,
    pub tp_lp: bool,
    pub tp_mms: bool,
    pub tp_mti: u8,
    pub tp_originating_address: SMSAddress,
    pub tp_pid: u8,
    pub tp_dcs: u8,
    pub tp_service_centre_timestamp: String,
    pub tp_user_data_length: u8,
    pub tp_user_data: Vec<u8>,
}

impl SmsDeliver {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.tp_mti != MTI_DELIVER {
            return Err(format!("TP-MTI {} is not SMS-DELIVER (0)", self.tp_mti).into());
        }
        check_user_data(
            "SMS-DELIVER",
            self.tp_dcs,
            self.tp_user_data_length,
            &self.tp_user_data,
        )?;

        let mut data = Vec::new();

        let first_byte = (self.tp_rp as u8) << 7
            | (self.tp_udhi as u8) << 6
            | (self.tp_sri as u8) << 5
            | (self.tp_lp as u8) << 3
            | (self.tp_mms as u8) << 2
            | MTI_DELIVER;
        data.push(first_byte);

        data.append(&mut self.tp_originating_address.encode(false)?);

        data.push(self.tp_pid);
        data.push(self.tp_dcs);
        data.extend_from_slice(&encode_time(
            &self.tp_service_centre_timestamp,
            "TP-Service-Centre-Time-Stamp",
        )?);
        data.push(self.tp_user_data_length);
        data.extend_from_slice(&self.tp_user_data);

        Ok(data)
    }

    /// Decode an SMS-DELIVER TPDU per TS 23.040 §9.2.2.1.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let first_byte = read_octet(&mut cursor, "first octet")?;
        let tp_mti = first_byte & 0x03;
        if tp_mti != MTI_DELIVER {
            return Err(format!("TP-MTI {tp_mti} is not SMS-DELIVER (0)").into());
        }
        let tp_originating_address =
            decode_transfer_layer_address(&mut cursor, "TP-Originating-Address")?;
        let tp_pid = read_octet(&mut cursor, "TP-PID")?;
        let tp_dcs = read_octet(&mut cursor, "TP-DCS")?;
        let tp_service_centre_timestamp = decode_time(&mut cursor, "TP-SCTS")?;
        let tp_user_data_length = read_octet(&mut cursor, "TP-User-Data-Length")?;
        let tp_user_data = read_octets(
            &mut cursor,
            user_data_octets(user_data_coding(tp_dcs), tp_user_data_length),
            "TP-User-Data",
        )?;

        Ok(SmsDeliver {
            tp_rp: bit(first_byte, 7),
            tp_udhi: bit(first_byte, 6),
            tp_sri: bit(first_byte, 5),
            tp_lp: bit(first_byte, 3),
            tp_mms: bit(first_byte, 2),
            tp_mti,
            tp_originating_address,
            tp_pid,
            tp_dcs,
            tp_service_centre_timestamp,
            tp_user_data_length,
            tp_user_data,
        })
    }
}

// ── Optional report parameters (TS 23.040 §9.2.3.27) ─────────────────────────

const PARAMETER_PROTOCOL_IDENTIFIER: u8 = 0x01;
const PARAMETER_DATA_CODING_SCHEME: u8 = 0x02;
const PARAMETER_USER_DATA_LENGTH: u8 = 0x04;
const PARAMETER_EXTENSION: u8 = 0x80;

/// The parameters a TP-Parameter-Indicator announces.
struct OptionalParameters {
    tp_pid: Option<u8>,
    tp_dcs: Option<u8>,
    tp_user_data_length: Option<u8>,
    tp_user_data: Vec<u8>,
}

/// Refuse a TP-Parameter-Indicator that disagrees with the parameters actually
/// supplied: the receiver reads the octets after it by its bits alone.
fn check_parameter_indicator(
    what: &str,
    tp_parameter_indicator: u8,
    tp_pid: Option<u8>,
    tp_dcs: Option<u8>,
    tp_user_data_length: Option<u8>,
) -> Result<(), Error> {
    let supplied = [
        (PARAMETER_PROTOCOL_IDENTIFIER, tp_pid.is_some(), "TP-PID"),
        (PARAMETER_DATA_CODING_SCHEME, tp_dcs.is_some(), "TP-DCS"),
        (
            PARAMETER_USER_DATA_LENGTH,
            tp_user_data_length.is_some(),
            "TP-UDL",
        ),
    ];
    for (flag, present, name) in supplied {
        if (tp_parameter_indicator & flag != 0) != present {
            return Err(format!(
                "{what}: TP-Parameter-Indicator 0x{tp_parameter_indicator:02x} and the presence \
                 of {name} disagree"
            )
            .into());
        }
    }
    if tp_parameter_indicator & PARAMETER_EXTENSION != 0 {
        return Err(format!(
            "{what}: TP-Parameter-Indicator 0x{tp_parameter_indicator:02x} announces a second \
             indicator octet, which is not supported"
        )
        .into());
    }
    Ok(())
}

/// Emit the parameters that follow TP-PI.
fn encode_parameters(
    what: &str,
    tp_pid: Option<u8>,
    tp_dcs: Option<u8>,
    tp_user_data_length: Option<u8>,
    tp_user_data: &[u8],
    data: &mut Vec<u8>,
) -> Result<(), Error> {
    data.extend(tp_pid);
    data.extend(tp_dcs);
    match tp_user_data_length {
        Some(length) => {
            // Without TP-DCS the receiver assumes the 7-bit default alphabet
            // (TS 23.040 §9.2.3.27).
            check_user_data(what, tp_dcs.unwrap_or(0), length, tp_user_data)?;
            data.push(length);
            data.extend_from_slice(tp_user_data);
        }
        None if !tp_user_data.is_empty() => {
            return Err(format!("{what}: TP-User-Data supplied without a TP-UDL").into());
        }
        None => {}
    }
    Ok(())
}

/// Read TP-PI, stepping over any extension octets.
fn decode_parameter_indicator(cursor: &mut Cursor<&[u8]>) -> Result<u8, Error> {
    let tp_parameter_indicator = read_octet(cursor, "TP-Parameter-Indicator")?;
    let mut extension = tp_parameter_indicator;
    while extension & PARAMETER_EXTENSION != 0 {
        extension = read_octet(cursor, "TP-Parameter-Indicator extension")?;
    }
    Ok(tp_parameter_indicator)
}

/// Read the parameters TP-PI announces. Whatever follows them is discarded, as
/// TS 23.040 §9.2.3.27 asks of a receiver.
fn decode_parameters(
    cursor: &mut Cursor<&[u8]>,
    tp_parameter_indicator: u8,
) -> Result<OptionalParameters, Error> {
    let mut read_if = |flag: u8, what: &str| -> Result<Option<u8>, Error> {
        if tp_parameter_indicator & flag != 0 {
            read_octet(cursor, what).map(Some)
        } else {
            Ok(None)
        }
    };
    let tp_pid = read_if(PARAMETER_PROTOCOL_IDENTIFIER, "TP-PID")?;
    let tp_dcs = read_if(PARAMETER_DATA_CODING_SCHEME, "TP-DCS")?;
    let tp_user_data_length = read_if(PARAMETER_USER_DATA_LENGTH, "TP-User-Data-Length")?;
    let tp_user_data = match tp_user_data_length {
        Some(length) => read_octets(
            cursor,
            user_data_octets(user_data_coding(tp_dcs.unwrap_or(0)), length),
            "TP-User-Data",
        )?,
        None => Vec::new(),
    };

    Ok(OptionalParameters {
        tp_pid,
        tp_dcs,
        tp_user_data_length,
        tp_user_data,
    })
}

/// Bits 7 and 5-2 of the first octet of a report, which are unused.
const REPORT_UNUSED_BITS: u8 = 0b1011_1100;
/// TP-FCS "Unspecified error cause" (TS 23.040 §9.2.3.22).
pub const FAILURE_CAUSE_UNSPECIFIED: u8 = 0xFF;

/// SMS-SUBMIT-REPORT (TS 23.040 §9.2.2.2a), the acknowledgement of an
/// SMS-SUBMIT.
///
/// It comes in two layouts. Inside an RP-ACK it has no failure cause
/// (`tp_failure_cause` is `None`). Inside an RP-ERROR the TP-Failure-Cause of
/// §9.2.3.22 follows the first octet (`tp_failure_cause` is `Some`). The
/// parameters after TP-SCTS are optional and each is announced by its bit in
/// `tp_parameter_indicator` (§9.2.3.27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsSubmitReport {
    pub tp_udhi: u8,
    pub tp_failure_cause: Option<u8>,
    pub tp_parameter_indicator: u8,
    pub tp_service_centre_timestamp: String,
    pub tp_pid: Option<u8>,
    pub tp_dcs: Option<u8>,
    pub tp_user_data_length: Option<u8>,
    pub tp_user_data: Vec<u8>,
}

impl SmsSubmitReport {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.tp_udhi > 1 {
            return Err(format!("TP-UDHI is one bit, got {}", self.tp_udhi).into());
        }
        let mut data = vec![(self.tp_udhi << 6) | MTI_SUBMIT];
        data.extend(self.tp_failure_cause);

        check_parameter_indicator(
            "SMS-SUBMIT-REPORT",
            self.tp_parameter_indicator,
            self.tp_pid,
            self.tp_dcs,
            self.tp_user_data_length,
        )?;
        data.push(self.tp_parameter_indicator);
        data.extend_from_slice(&encode_time(
            &self.tp_service_centre_timestamp,
            "TP-Service-Centre-Time-Stamp",
        )?);
        encode_parameters(
            "SMS-SUBMIT-REPORT",
            self.tp_pid,
            self.tp_dcs,
            self.tp_user_data_length,
            &self.tp_user_data,
            &mut data,
        )?;
        Ok(data)
    }

    /// Decode the layout carried in an RP-ACK (no TP-Failure-Cause).
    pub fn decode_for_rp_ack(data: &[u8]) -> Result<Self, Error> {
        Self::decode(data, false)
    }

    /// Decode the layout carried in an RP-ERROR (TP-Failure-Cause present).
    ///
    /// When any unused bit of the first octet is set the rest is not examined
    /// and the cause reads as "Unspecified error cause", as TS 23.040
    /// §9.2.2.2a requires of a receiver.
    pub fn decode_for_rp_error(data: &[u8]) -> Result<Self, Error> {
        Self::decode(data, true)
    }

    fn decode(data: &[u8], failure: bool) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let first_byte = read_octet(&mut cursor, "first octet")?;
        if first_byte & 0x03 != MTI_SUBMIT {
            return Err(
                format!("TP-MTI {} is not SMS-SUBMIT-REPORT (1)", first_byte & 0x03).into(),
            );
        }
        if failure && first_byte & REPORT_UNUSED_BITS != 0 {
            return Ok(SmsSubmitReport {
                tp_udhi: 0,
                tp_failure_cause: Some(FAILURE_CAUSE_UNSPECIFIED),
                tp_parameter_indicator: 0,
                tp_service_centre_timestamp: String::new(),
                tp_pid: None,
                tp_dcs: None,
                tp_user_data_length: None,
                tp_user_data: Vec::new(),
            });
        }
        let tp_failure_cause = if failure {
            Some(read_octet(&mut cursor, "TP-Failure-Cause")?)
        } else {
            None
        };
        let tp_parameter_indicator = decode_parameter_indicator(&mut cursor)?;
        let tp_service_centre_timestamp = decode_time(&mut cursor, "TP-SCTS")?;
        let parameters = decode_parameters(&mut cursor, tp_parameter_indicator)?;

        Ok(SmsSubmitReport {
            tp_udhi: (first_byte >> 6) & 0x01,
            tp_failure_cause,
            tp_parameter_indicator,
            tp_service_centre_timestamp,
            tp_pid: parameters.tp_pid,
            tp_dcs: parameters.tp_dcs,
            tp_user_data_length: parameters.tp_user_data_length,
            tp_user_data: parameters.tp_user_data,
        })
    }
}

/// SMS-DELIVER-REPORT (TS 23.040 §9.2.2.1a), the acknowledgement of an
/// SMS-DELIVER or SMS-STATUS-REPORT.
///
/// Like [`SmsSubmitReport`] it has two layouts: without a failure cause inside
/// an RP-ACK, with TP-Failure-Cause inside an RP-ERROR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsDeliverReport {
    pub tp_udhi: bool,
    pub tp_failure_cause: Option<u8>,
    pub tp_parameter_indicator: u8,
    pub tp_pid: Option<u8>,
    pub tp_dcs: Option<u8>,
    pub tp_user_data_length: Option<u8>,
    pub tp_user_data: Vec<u8>,
}

impl SmsDeliverReport {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = vec![((self.tp_udhi as u8) << 6) | MTI_DELIVER];
        data.extend(self.tp_failure_cause);
        check_parameter_indicator(
            "SMS-DELIVER-REPORT",
            self.tp_parameter_indicator,
            self.tp_pid,
            self.tp_dcs,
            self.tp_user_data_length,
        )?;
        data.push(self.tp_parameter_indicator);
        encode_parameters(
            "SMS-DELIVER-REPORT",
            self.tp_pid,
            self.tp_dcs,
            self.tp_user_data_length,
            &self.tp_user_data,
            &mut data,
        )?;
        Ok(data)
    }

    /// Decode the layout carried in an RP-ACK (no TP-Failure-Cause).
    pub fn decode_for_rp_ack(data: &[u8]) -> Result<Self, Error> {
        Self::decode(data, false)
    }

    /// Decode the layout carried in an RP-ERROR (TP-Failure-Cause present).
    ///
    /// When any unused bit of the first octet is set the rest is not examined
    /// and the cause reads as "Unspecified error cause", as TS 23.040
    /// §9.2.2.1a requires of a receiver.
    pub fn decode_for_rp_error(data: &[u8]) -> Result<Self, Error> {
        Self::decode(data, true)
    }

    fn decode(data: &[u8], failure: bool) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let first_byte = read_octet(&mut cursor, "first octet")?;
        if first_byte & 0x03 != MTI_DELIVER {
            return Err(
                format!("TP-MTI {} is not SMS-DELIVER-REPORT (0)", first_byte & 0x03).into(),
            );
        }
        if failure && first_byte & REPORT_UNUSED_BITS != 0 {
            return Ok(SmsDeliverReport {
                tp_udhi: false,
                tp_failure_cause: Some(FAILURE_CAUSE_UNSPECIFIED),
                tp_parameter_indicator: 0,
                tp_pid: None,
                tp_dcs: None,
                tp_user_data_length: None,
                tp_user_data: Vec::new(),
            });
        }
        let tp_failure_cause = if failure {
            Some(read_octet(&mut cursor, "TP-Failure-Cause")?)
        } else {
            None
        };
        let tp_parameter_indicator = decode_parameter_indicator(&mut cursor)?;
        let parameters = decode_parameters(&mut cursor, tp_parameter_indicator)?;

        Ok(SmsDeliverReport {
            tp_udhi: bit(first_byte, 6),
            tp_failure_cause,
            tp_parameter_indicator,
            tp_pid: parameters.tp_pid,
            tp_dcs: parameters.tp_dcs,
            tp_user_data_length: parameters.tp_user_data_length,
            tp_user_data: parameters.tp_user_data,
        })
    }
}

/// SMS-STATUS-REPORT (TS 23.040 §9.2.2.3), the service centre telling the
/// sender what became of an earlier SMS-SUBMIT or SMS-COMMAND.
///
/// `tp_mr` is the TP-Message-Reference of that earlier TPDU,
/// `tp_recipient_address` where it was headed, `tp_service_centre_timestamp`
/// when the service centre took it and `tp_discharge_time` when the outcome in
/// `tp_status` (§9.2.3.15) was reached. Both times are the 14 digits of
/// §9.2.3.11, see [`timestamp_digits`].
///
/// TP-Parameter-Indicator and what it announces are optional as a whole:
/// leave `tp_parameter_indicator` `None` and the report ends at TP-Status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsStatusReport {
    pub tp_udhi: bool,
    pub tp_srq: bool,
    pub tp_lp: bool,
    pub tp_mms: bool,
    pub tp_mr: u8,
    pub tp_recipient_address: SMSAddress,
    pub tp_service_centre_timestamp: String,
    pub tp_discharge_time: String,
    pub tp_status: u8,
    pub tp_parameter_indicator: Option<u8>,
    pub tp_pid: Option<u8>,
    pub tp_dcs: Option<u8>,
    pub tp_user_data_length: Option<u8>,
    pub tp_user_data: Vec<u8>,
}

impl SmsStatusReport {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = vec![
            (self.tp_udhi as u8) << 6
                | (self.tp_srq as u8) << 5
                | (self.tp_lp as u8) << 3
                | (self.tp_mms as u8) << 2
                | MTI_STATUS_REPORT,
            self.tp_mr,
        ];
        data.append(&mut self.tp_recipient_address.encode(false)?);
        data.extend_from_slice(&encode_time(
            &self.tp_service_centre_timestamp,
            "TP-Service-Centre-Time-Stamp",
        )?);
        data.extend_from_slice(&encode_time(&self.tp_discharge_time, "TP-Discharge-Time")?);
        data.push(self.tp_status);

        match self.tp_parameter_indicator {
            Some(indicator) => {
                check_parameter_indicator(
                    "SMS-STATUS-REPORT",
                    indicator,
                    self.tp_pid,
                    self.tp_dcs,
                    self.tp_user_data_length,
                )?;
                data.push(indicator);
                encode_parameters(
                    "SMS-STATUS-REPORT",
                    self.tp_pid,
                    self.tp_dcs,
                    self.tp_user_data_length,
                    &self.tp_user_data,
                    &mut data,
                )?;
            }
            None => {
                if self.tp_pid.is_some()
                    || self.tp_dcs.is_some()
                    || self.tp_user_data_length.is_some()
                    || !self.tp_user_data.is_empty()
                {
                    return Err(
                        "SMS-STATUS-REPORT: optional parameters need a TP-Parameter-Indicator"
                            .into(),
                    );
                }
            }
        }
        Ok(data)
    }

    /// Decode an SMS-STATUS-REPORT TPDU per TS 23.040 §9.2.2.3.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let first_byte = read_octet(&mut cursor, "first octet")?;
        if first_byte & 0x03 != MTI_STATUS_REPORT {
            return Err(
                format!("TP-MTI {} is not SMS-STATUS-REPORT (2)", first_byte & 0x03).into(),
            );
        }
        let tp_mr = read_octet(&mut cursor, "TP-MR")?;
        let tp_recipient_address =
            decode_transfer_layer_address(&mut cursor, "TP-Recipient-Address")?;
        let tp_service_centre_timestamp = decode_time(&mut cursor, "TP-SCTS")?;
        let tp_discharge_time = decode_time(&mut cursor, "TP-Discharge-Time")?;
        let tp_status = read_octet(&mut cursor, "TP-Status")?;

        // TP-PI is optional as a whole: a report may end at TP-Status.
        let tp_parameter_indicator = if remaining(&cursor) > 0 {
            Some(decode_parameter_indicator(&mut cursor)?)
        } else {
            None
        };
        let parameters = decode_parameters(&mut cursor, tp_parameter_indicator.unwrap_or(0))?;
        let OptionalParameters {
            tp_pid,
            tp_dcs,
            tp_user_data_length,
            tp_user_data,
        } = parameters;

        Ok(SmsStatusReport {
            tp_udhi: bit(first_byte, 6),
            tp_srq: bit(first_byte, 5),
            tp_lp: bit(first_byte, 3),
            tp_mms: bit(first_byte, 2),
            tp_mr,
            tp_recipient_address,
            tp_service_centre_timestamp,
            tp_discharge_time,
            tp_status,
            tp_parameter_indicator,
            tp_pid,
            tp_dcs,
            tp_user_data_length,
            tp_user_data,
        })
    }
}

// ── Relay-layer messages (TS 24.011 §7.3, §8.2) ──────────────────────────────

/// RP-DATA, mobile station to network (TS 24.011 table 8.3).
pub const RP_DATA_MS_TO_NETWORK: u8 = 0b000;
/// RP-DATA, network to mobile station.
pub const RP_DATA_NETWORK_TO_MS: u8 = 0b001;
/// RP-ACK, mobile station to network.
pub const RP_ACK_MS_TO_NETWORK: u8 = 0b010;
/// RP-ACK, network to mobile station.
pub const RP_ACK_NETWORK_TO_MS: u8 = 0b011;
/// RP-ERROR, mobile station to network.
pub const RP_ERROR_MS_TO_NETWORK: u8 = 0b100;
/// RP-ERROR, network to mobile station.
pub const RP_ERROR_NETWORK_TO_MS: u8 = 0b101;
/// RP-SMMA, mobile station to network.
pub const RP_SMMA_MS_TO_NETWORK: u8 = 0b110;

/// RP-User-Data information element identifier (TS 24.011 §8.2.5.3).
const RP_USER_DATA_ELEMENT_ID: u8 = 0x41;

fn check_message_type(actual: u8, expected: u8, name: &str) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("RP-Message-Type {actual} is not {name} ({expected})").into())
    }
}

/// Read RP-Message-Type and RP-Message-Reference, checking the type.
fn decode_relay_header(
    cursor: &mut Cursor<&[u8]>,
    expected: u8,
    name: &str,
) -> Result<(u8, u8), Error> {
    let rp_message_type = read_octet(cursor, "RP-Message-Type")? & 0x07;
    check_message_type(rp_message_type, expected, name)?;
    let rp_message_reference = read_octet(cursor, "RP-Message-Reference")?;
    Ok((rp_message_type, rp_message_reference))
}

fn encode_relay_address(address: Option<&SMSAddress>, data: &mut Vec<u8>) -> Result<(), Error> {
    match address {
        Some(address) => data.append(&mut address.encode(true)?),
        None => data.push(0),
    }
    Ok(())
}

/// Append a TPDU behind its one-octet length.
fn encode_length_value(what: &str, tpdu: &[u8], data: &mut Vec<u8>) -> Result<(), Error> {
    let length = u8::try_from(tpdu.len())
        .map_err(|_| format!("{what} of {} octets does not fit RP-User-Data", tpdu.len()))?;
    data.push(length);
    data.extend_from_slice(tpdu);
    Ok(())
}

/// Assemble an RP-DATA in either direction (TS 24.011 §7.3.1).
fn encode_relay_data(
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<&SMSAddress>,
    rp_destination_address: Option<&SMSAddress>,
    tpdu: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut data = vec![rp_message_type, rp_message_reference];
    encode_relay_address(rp_originator_address, &mut data)?;
    encode_relay_address(rp_destination_address, &mut data)?;
    encode_length_value("TPDU", tpdu, &mut data)?;
    Ok(data)
}

/// The parts of an RP-DATA in either direction, the TPDU still encoded.
struct RelayData {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<SMSAddress>,
    rp_destination_address: Option<SMSAddress>,
    tpdu: Vec<u8>,
}

fn decode_relay_data(data: &[u8], expected: u8, name: &str) -> Result<RelayData, Error> {
    let mut cursor = Cursor::new(data);
    let (rp_message_type, rp_message_reference) = decode_relay_header(&mut cursor, expected, name)?;
    debug!("RP-Message Type: {}", rp_message_type);
    debug!("RP-Message Reference: {}", rp_message_reference);

    let rp_originator_address = decode_sms_address(&mut cursor, true)
        .map_err(|e| format!("Could not decode RP-Originator Address: {}", e))?;
    debug!("RP-Originator Address: {:?}", rp_originator_address);

    let rp_destination_address = decode_sms_address(&mut cursor, true)
        .map_err(|e| format!("Could not decode RP-Destination Address: {}", e))?;
    debug!("RP-Destination Address: {:?}", rp_destination_address);

    let tpdu_length = read_octet(&mut cursor, "TPDU Length")?;
    debug!("TPDU Length: {}", tpdu_length);
    let tpdu = read_octets(&mut cursor, usize::from(tpdu_length), "TPDU")?;

    Ok(RelayData {
        rp_message_type,
        rp_message_reference,
        rp_originator_address,
        rp_destination_address,
        tpdu,
    })
}

/// RP-DATA, mobile station to network (TS 24.011 §7.3.1.2), carrying an
/// SMS-SUBMIT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDataMsToNetwork {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_originator_address: Option<SMSAddress>,
    pub rp_destination_address: Option<SMSAddress>,
    pub sms_submit: SmsSubmit,
}

impl RpDataMsToNetwork {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_DATA_MS_TO_NETWORK,
            "RP-DATA (MS to network)",
        )?;
        encode_relay_data(
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_originator_address.as_ref(),
            self.rp_destination_address.as_ref(),
            &self.sms_submit.encode()?,
        )
    }
}

/// RP-DATA, network to mobile station (TS 24.011 §7.3.1.1), carrying an
/// SMS-DELIVER. For the one carrying an SMS-STATUS-REPORT see
/// [`RpDataNetworkToMsStatusReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDataNetworkToMs {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_originator_address: Option<SMSAddress>,
    pub rp_destination_address: Option<SMSAddress>,
    pub sms_deliver: SmsDeliver,
}

impl RpDataNetworkToMs {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_DATA_NETWORK_TO_MS,
            "RP-DATA (network to MS)",
        )?;
        encode_relay_data(
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_originator_address.as_ref(),
            self.rp_destination_address.as_ref(),
            &self.sms_deliver.encode()?,
        )
    }
}

/// RP-DATA, network to mobile station (TS 24.011 §7.3.1.1), carrying an
/// SMS-STATUS-REPORT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDataNetworkToMsStatusReport {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_originator_address: Option<SMSAddress>,
    pub rp_destination_address: Option<SMSAddress>,
    pub sms_status_report: SmsStatusReport,
}

impl RpDataNetworkToMsStatusReport {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_DATA_NETWORK_TO_MS,
            "RP-DATA (network to MS)",
        )?;
        encode_relay_data(
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_originator_address.as_ref(),
            self.rp_destination_address.as_ref(),
            &self.sms_status_report.encode()?,
        )
    }
}

/// What [`parse_rp_data_network_to_ms`] found inside the RP-DATA: the TPDU the
/// network sends is told apart by its TP-MTI (TS 23.040 §9.2.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpDataNetworkToMsMessage {
    Deliver(RpDataNetworkToMs),
    StatusReport(RpDataNetworkToMsStatusReport),
}

/// Parse an RP-DATA sent by the network (TS 24.011 §7.3.1.1), which carries
/// either an SMS-DELIVER or an SMS-STATUS-REPORT.
pub fn parse_rp_data_network_to_ms(data: &[u8]) -> Result<RpDataNetworkToMsMessage, Error> {
    let relay = decode_relay_data(data, RP_DATA_NETWORK_TO_MS, "RP-DATA (network to MS)")?;
    let tp_mti = relay.tpdu.first().map(|octet| octet & 0x03);
    match tp_mti {
        Some(MTI_STATUS_REPORT) => Ok(RpDataNetworkToMsMessage::StatusReport(
            RpDataNetworkToMsStatusReport {
                rp_message_type: relay.rp_message_type,
                rp_message_reference: relay.rp_message_reference,
                rp_originator_address: relay.rp_originator_address,
                rp_destination_address: relay.rp_destination_address,
                sms_status_report: SmsStatusReport::decode(&relay.tpdu)
                    .map_err(|e| format!("Could not decode TPDU: {e}"))?,
            },
        )),
        // Everything else goes to the SMS-DELIVER decoder, which turns down a
        // TP-MTI other than 00.
        _ => Ok(RpDataNetworkToMsMessage::Deliver(RpDataNetworkToMs {
            rp_message_type: relay.rp_message_type,
            rp_message_reference: relay.rp_message_reference,
            rp_originator_address: relay.rp_originator_address,
            rp_destination_address: relay.rp_destination_address,
            sms_deliver: SmsDeliver::decode(&relay.tpdu)
                .map_err(|e| format!("Could not decode TPDU: {e}"))?,
        })),
    }
}

/// RP-ACK, network to mobile station (TS 24.011 §7.3.3), carrying the
/// SMS-SUBMIT-REPORT that acknowledges an SMS-SUBMIT.
///
/// `rp_user_data_element_id` is the RP-User-Data identifier, `0x41`, and
/// `rp_user_data_element_length` the length of the encoded report. Both are
/// checked by [`RpAck::encode`]; [`RpAck::builder`] fills them in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpAck {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_user_data_element_id: u8,
    pub rp_user_data_element_length: u8,
    pub sms_submit_report: SmsSubmitReport,
}

impl RpAck {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_ACK_NETWORK_TO_MS,
            "RP-ACK (network to MS)",
        )?;
        if self.rp_user_data_element_id != RP_USER_DATA_ELEMENT_ID {
            return Err(format!(
                "RP-User-Data element identifier is 0x{RP_USER_DATA_ELEMENT_ID:02x}, got \
                 0x{:02x}",
                self.rp_user_data_element_id
            )
            .into());
        }
        if self.sms_submit_report.tp_failure_cause.is_some() {
            return Err(
                "an SMS-SUBMIT-REPORT with a TP-Failure-Cause belongs in an RP-ERROR, not an \
                 RP-ACK"
                    .into(),
            );
        }
        let report = self.sms_submit_report.encode()?;
        if usize::from(self.rp_user_data_element_length) != report.len() {
            return Err(format!(
                "RP-User-Data length {} does not match the {} octets of the SMS-SUBMIT-REPORT",
                self.rp_user_data_element_length,
                report.len()
            )
            .into());
        }

        let mut data = vec![
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_user_data_element_id,
        ];
        encode_length_value("SMS-SUBMIT-REPORT", &report, &mut data)?;
        Ok(data)
    }
}

/// RP-Cause and what may follow it in an RP-ERROR (TS 24.011 §7.3.4).
struct RelayError {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_cause: u8,
    rp_diagnostic: Option<u8>,
    tpdu: Option<Vec<u8>>,
}

fn encode_relay_error(
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_cause: u8,
    rp_diagnostic: Option<u8>,
    tpdu: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    if rp_cause > 0x7F {
        return Err(format!("RP-Cause value {rp_cause} does not fit its 7 bits").into());
    }
    let mut data = vec![
        rp_message_type,
        rp_message_reference,
        // RP-Cause is LV: one octet of cause, optionally one of diagnostic.
        if rp_diagnostic.is_some() { 2 } else { 1 },
        rp_cause,
    ];
    data.extend(rp_diagnostic);
    if let Some(tpdu) = tpdu {
        data.push(RP_USER_DATA_ELEMENT_ID);
        encode_length_value("TPDU", &tpdu, &mut data)?;
    }
    Ok(data)
}

fn decode_relay_error(data: &[u8], expected: u8, name: &str) -> Result<RelayError, Error> {
    let mut cursor = Cursor::new(data);
    let (rp_message_type, rp_message_reference) = decode_relay_header(&mut cursor, expected, name)?;

    let cause_length = usize::from(read_octet(&mut cursor, "RP-Cause length")?);
    let cause = read_octets(&mut cursor, cause_length, "RP-Cause")?;
    let rp_cause = cause.first().ok_or("RP-Cause is empty")? & 0x7F;
    let rp_diagnostic = cause.get(1).copied();

    let tpdu = if remaining(&cursor) > 0 {
        let element_id = read_octet(&mut cursor, "information element identifier")?;
        if element_id == RP_USER_DATA_ELEMENT_ID {
            let length = read_octet(&mut cursor, "RP-User-Data length")?;
            Some(read_octets(
                &mut cursor,
                usize::from(length),
                "RP-User-Data",
            )?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(RelayError {
        rp_message_type,
        rp_message_reference,
        rp_cause,
        rp_diagnostic,
        tpdu,
    })
}

/// RP-ERROR, network to mobile station (TS 24.011 §7.3.4): the network turning
/// down an RP-DATA or RP-SMMA from the mobile station.
///
/// `rp_cause` is the 7-bit cause value of table 8.4, `rp_diagnostic` the
/// optional diagnostic octet behind it. The optional RP-User-Data carries the
/// SMS-SUBMIT-REPORT for RP-ERROR of TS 23.040 §9.2.2.2a, so the report must
/// have a `tp_failure_cause`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpErrorNetworkToMs {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_cause: u8,
    pub rp_diagnostic: Option<u8>,
    pub sms_submit_report: Option<SmsSubmitReport>,
}

impl RpErrorNetworkToMs {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_ERROR_NETWORK_TO_MS,
            "RP-ERROR (network to MS)",
        )?;
        let tpdu = match &self.sms_submit_report {
            Some(report) if report.tp_failure_cause.is_none() => {
                return Err("the SMS-SUBMIT-REPORT of an RP-ERROR needs a TP-Failure-Cause".into());
            }
            Some(report) => Some(report.encode()?),
            None => None,
        };
        encode_relay_error(
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_cause,
            self.rp_diagnostic,
            tpdu,
        )
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let relay = decode_relay_error(data, RP_ERROR_NETWORK_TO_MS, "RP-ERROR (network to MS)")?;
        let sms_submit_report = relay
            .tpdu
            .map(|tpdu| {
                SmsSubmitReport::decode_for_rp_error(&tpdu)
                    .map_err(|e| format!("Could not decode TPDU: {e}"))
            })
            .transpose()?;
        Ok(RpErrorNetworkToMs {
            rp_message_type: relay.rp_message_type,
            rp_message_reference: relay.rp_message_reference,
            rp_cause: relay.rp_cause,
            rp_diagnostic: relay.rp_diagnostic,
            sms_submit_report,
        })
    }
}

/// RP-ERROR, mobile station to network (TS 24.011 §7.3.4): the mobile station
/// turning down an RP-DATA from the network.
///
/// The optional RP-User-Data carries the SMS-DELIVER-REPORT for RP-ERROR of
/// TS 23.040 §9.2.2.1a, so the report must have a `tp_failure_cause`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpErrorMsToNetwork {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_cause: u8,
    pub rp_diagnostic: Option<u8>,
    pub sms_deliver_report: Option<SmsDeliverReport>,
}

impl RpErrorMsToNetwork {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(
            self.rp_message_type,
            RP_ERROR_MS_TO_NETWORK,
            "RP-ERROR (MS to network)",
        )?;
        let tpdu = match &self.sms_deliver_report {
            Some(report) if report.tp_failure_cause.is_none() => {
                return Err(
                    "the SMS-DELIVER-REPORT of an RP-ERROR needs a TP-Failure-Cause".into(),
                );
            }
            Some(report) => Some(report.encode()?),
            None => None,
        };
        encode_relay_error(
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_cause,
            self.rp_diagnostic,
            tpdu,
        )
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let relay = decode_relay_error(data, RP_ERROR_MS_TO_NETWORK, "RP-ERROR (MS to network)")?;
        let sms_deliver_report = relay
            .tpdu
            .map(|tpdu| {
                SmsDeliverReport::decode_for_rp_error(&tpdu)
                    .map_err(|e| format!("Could not decode TPDU: {e}"))
            })
            .transpose()?;
        Ok(RpErrorMsToNetwork {
            rp_message_type: relay.rp_message_type,
            rp_message_reference: relay.rp_message_reference,
            rp_cause: relay.rp_cause,
            rp_diagnostic: relay.rp_diagnostic,
            sms_deliver_report,
        })
    }
}

/// RP-SMMA (TS 24.011 §7.3.2): the mobile station telling the network it has
/// memory available again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpSmma {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
}

impl RpSmma {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_message_type(self.rp_message_type, RP_SMMA_MS_TO_NETWORK, "RP-SMMA")?;
        Ok(vec![self.rp_message_type, self.rp_message_reference])
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(data);
        let (rp_message_type, rp_message_reference) =
            decode_relay_header(&mut cursor, RP_SMMA_MS_TO_NETWORK, "RP-SMMA")?;
        Ok(RpSmma {
            rp_message_type,
            rp_message_reference,
        })
    }
}

/// Parse an RP-DATA sent by a mobile station (TS 24.011 §7.3.1.2), which
/// carries an SMS-SUBMIT.
pub fn parse_rp_data(data: &[u8]) -> Result<RpDataMsToNetwork, Error> {
    let relay = decode_relay_data(data, RP_DATA_MS_TO_NETWORK, "RP-DATA (MS to network)")?;
    let tpdu = decode_sms_submit_tpdu(&mut Cursor::new(relay.tpdu.as_slice()))
        .map_err(|e| format!("Could not decode TPDU: {}", e))?;

    Ok(RpDataMsToNetwork {
        rp_message_type: relay.rp_message_type,
        rp_message_reference: relay.rp_message_reference,
        rp_originator_address: relay.rp_originator_address,
        rp_destination_address: relay.rp_destination_address,
        sms_submit: tpdu,
    })
}

/// Decode an SMS-SUBMIT TPDU per TS 23.040 §9.2.2.2.
pub fn decode_sms_submit_tpdu(cursor: &mut Cursor<&[u8]>) -> Result<SmsSubmit, Error> {
    let first_byte = read_octet(cursor, "first octet")?;

    // First octet, TS 23.040 §9.2.3: TP-RP bit 7 (§9.2.3.17), TP-UDHI bit 6
    // (§9.2.3.23), TP-SRR bit 5 (§9.2.3.5), TP-VPF bits 4 and 3 (§9.2.3.3),
    // TP-RD bit 2 (§9.2.3.25), TP-MTI bits 1 and 0 (§9.2.3.1).
    let tp_rp = bit(first_byte, 7);
    let tp_udhi = bit(first_byte, 6);
    let tp_srr = bit(first_byte, 5);
    let tp_vpf = (first_byte >> 3) & 0x03;
    let tp_rd = bit(first_byte, 2);
    let tp_mti = first_byte & 0x03;

    debug!(
        "TP-RP: {}, TP-UDHI: {}, TP-SRR: {}, TP-MTI: {}, TP-RD: {:?}, TP-VPF: {:?}",
        tp_rp, tp_udhi, tp_srr, tp_mti, tp_rd, tp_vpf
    );
    if tp_mti != MTI_SUBMIT {
        return Err(format!("TP-MTI {tp_mti} is not SMS-SUBMIT (1)").into());
    }

    let tp_mr = read_octet(cursor, "TP-MR")?;
    debug!("TP-MR: {}", tp_mr);

    let tp_destination_address = decode_sms_address(cursor, false)?;
    debug!("TP-Destination Address: {:?}", tp_destination_address);

    let tp_pid = read_octet(cursor, "TP-PID")?;
    debug!("TP-PID: {}", tp_pid);

    let tp_dcs = read_octet(cursor, "TP-DCS")?;
    debug!("TP-DCS: {}", tp_dcs);

    let tp_validity_period = ValidityPeriod::decode(cursor, tp_vpf)?;
    debug!("TP-Validity-Period: {:?}", tp_validity_period);

    let tp_user_data_length = read_octet(cursor, "TP-User-Data-Length")?;
    debug!("TP-User-Data-Length: {}", tp_user_data_length);

    let raw_user_data = read_octets(
        cursor,
        user_data_octets(user_data_coding(tp_dcs), tp_user_data_length),
        "TP-User-Data buffer",
    )?;

    let (tp_user_data_header, tp_user_data) =
        split_user_data(tp_dcs, tp_udhi, tp_user_data_length, &raw_user_data)?;

    debug!("TP-User-Data: {}", String::from_utf8_lossy(&tp_user_data));

    Ok(SmsSubmit {
        tp_rp,
        tp_udhi,
        tp_srr,
        tp_mti,
        tp_rd,
        tp_vpf,
        tp_mr,
        tp_destination_address,
        tp_pid,
        tp_dcs,
        tp_validity_period,
        tp_user_data_length,
        tp_user_data_raw: raw_user_data,
        tp_user_data_header,
        tp_user_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Synthetic test data only ─────────────────────────────────────────
    // No real captures: fictional 555-01xx MSISDNs and neutral text. Every
    // vector is assembled from the public API so nothing real is embedded.

    /// Assemble an SMS-SUBMIT TPDU from parts (TS 23.040 §9.2.2.2).
    #[allow(clippy::too_many_arguments)]
    fn submit_tpdu(
        first_byte: u8,
        mr: u8,
        dest: &SMSAddress,
        pid: u8,
        dcs: u8,
        vp: Option<u8>,
        udl: u8,
        ud: &[u8],
    ) -> Vec<u8> {
        let mut t = vec![first_byte, mr];
        t.extend(dest.encode(false).unwrap());
        t.push(pid);
        t.push(dcs);
        if let Some(v) = vp {
            t.push(v);
        }
        t.push(udl);
        t.extend_from_slice(ud);
        t
    }

    /// Wrap an MO TPDU in RP-DATA MS→Network (TS 24.011 §7.3.1.1).
    fn rp_data_mo(rp_ref: u8, rp_da: Option<&SMSAddress>, tpdu: &[u8]) -> Vec<u8> {
        let mut d = vec![0x00, rp_ref, 0x00]; // RP-type=DATA, RP-MR, RP-OA absent
        match rp_da {
            Some(a) => d.extend(a.encode(true).unwrap()),
            None => d.push(0x00),
        }
        d.push(tpdu.len() as u8);
        d.extend_from_slice(tpdu);
        d
    }

    fn ucs2(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn error_is_std_error_and_displays() {
        let e: Error = "boom".into();
        assert_eq!(e.message(), "boom");
        assert_eq!(e.to_string(), "boom");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn gsm7_pack_septets_and_roundtrip() {
        let (bytes, septets) = pack_gsm7("hi").unwrap();
        assert_eq!(septets, 2);
        assert_eq!(unpack_gsm7(&bytes, septets).unwrap(), "hi");
    }

    #[test]
    fn gsm7_roundtrip_varied() {
        for input in [
            "",
            "a",
            "tpdu rocks",
            "Symbols @ {} [] | ~ ^ €",
            "voorbeeld",
        ] {
            let (b, s) = pack_gsm7(input).unwrap();
            assert_eq!(unpack_gsm7(&b, s).unwrap(), input, "roundtrip {input:?}");
        }
    }

    #[test]
    fn gsm7_extension_chars_are_two_septets() {
        let (_, s) = pack_gsm7("€[]").unwrap();
        assert_eq!(s, 6);
    }

    #[test]
    fn decode_submit_7bit_no_vp() {
        let dest = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550100".into(),
        };
        let (ud, septets) = pack_gsm7("ping").unwrap();
        let tpdu = submit_tpdu(0x01, 7, &dest, 0, 0, None, septets as u8, &ud);
        let rp = rp_data_mo(1, None, &tpdu);

        let p = parse_rp_data(&rp).unwrap();
        assert_eq!(p.rp_message_type, 0);
        assert_eq!(p.rp_message_reference, 1);
        assert_eq!(p.rp_originator_address, None);
        assert_eq!(p.rp_destination_address, None);
        assert_eq!(p.sms_submit.tp_mti, 1);
        assert!(!p.sms_submit.tp_udhi);
        assert!(!p.sms_submit.tp_rp);
        assert!(!p.sms_submit.tp_srr);
        assert_eq!(p.sms_submit.tp_mr, 7);
        assert_eq!(p.sms_submit.tp_vpf, 0);
        assert_eq!(p.sms_submit.tp_validity_period, None);
        assert_eq!(p.sms_submit.tp_destination_address, Some(dest));
        assert_eq!(p.sms_submit.tp_user_data, b"ping");
    }

    #[test]
    fn decode_submit_with_validity_and_sc_address() {
        let dest = SMSAddress {
            ton: 1,
            npi: 1,
            address: "155501234".into(),
        }; // odd length
        let sc = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550000".into(),
        };
        let (ud, septets) = pack_gsm7("hello from tpdu").unwrap();
        let tpdu = submit_tpdu(0x11, 0x2a, &dest, 0, 0, Some(0xff), septets as u8, &ud);
        let rp = rp_data_mo(2, Some(&sc), &tpdu);

        let p = parse_rp_data(&rp).unwrap();
        assert_eq!(p.rp_destination_address, Some(sc));
        // First octet 0x11: bit 4 set and bit 3 clear is the relative format
        // (TS 23.040 §9.2.3.3), so the two-bit field reads 0b10.
        assert_eq!(p.sms_submit.tp_vpf, VALIDITY_PERIOD_FORMAT_RELATIVE);
        assert_eq!(
            p.sms_submit.tp_validity_period,
            Some(ValidityPeriod::Relative(0xff))
        );
        assert_eq!(p.sms_submit.tp_destination_address, Some(dest));
        assert_eq!(p.sms_submit.tp_user_data, b"hello from tpdu");
    }

    #[test]
    fn decode_submit_ucs2() {
        let dest = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550102".into(),
        };
        let ud = ucs2("Hé€");
        let tpdu = submit_tpdu(0x01, 1, &dest, 0, 0x08, None, ud.len() as u8, &ud);
        let rp = rp_data_mo(3, None, &tpdu);

        let p = parse_rp_data(&rp).unwrap();
        assert_eq!(p.sms_submit.tp_dcs, 0x08);
        assert_eq!(p.sms_submit.tp_user_data, ud);
    }

    #[test]
    fn decode_submit_with_udh() {
        // Concatenation UDH (IEI 00, 3-byte ref/total/seq) on a UCS-2 body —
        // exercises UserDataHeader::decode without 7-bit septet alignment.
        let dest = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550103".into(),
        };
        let udh = [0x05u8, 0x00, 0x03, 0x42, 0x02, 0x01]; // UDHL=5
        let mut ud = udh.to_vec();
        ud.extend_from_slice(&ucs2("part1"));
        let tpdu = submit_tpdu(0x51, 9, &dest, 0, 0x08, Some(0xff), ud.len() as u8, &ud);
        let rp = rp_data_mo(4, None, &tpdu);

        let p = parse_rp_data(&rp).unwrap();
        assert!(p.sms_submit.tp_udhi);
        assert_eq!(
            p.sms_submit.tp_user_data_header,
            Some(UserDataHeader {
                user_data_header_length: 5,
                user_data_header_value: vec![0x00, 0x03, 0x42, 0x02, 0x01],
            })
        );
    }

    #[test]
    fn decode_truncated_user_data_errors() {
        let dest = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550100".into(),
        };
        // Claim UDL=10 septets but supply no user-data bytes → Err, not panic.
        let tpdu = submit_tpdu(0x01, 1, &dest, 0, 0, None, 10, &[]);
        let rp = rp_data_mo(1, None, &tpdu);
        assert!(parse_rp_data(&rp).is_err());
    }

    #[test]
    fn decode_short_input_errors_not_panics() {
        assert!(parse_rp_data(&[]).is_err());
        assert!(parse_rp_data(&[0x00]).is_err());
    }

    #[test]
    fn encode_mt_deliver_roundtrips_oa() {
        let oa = SMSAddress {
            ton: 1,
            npi: 1,
            address: "15550199".into(),
        };
        let (ud, septets) = pack_gsm7("delivered").unwrap();
        let deliver = SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_mti: 0,
            tp_originating_address: oa.clone(),
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
            tp_user_data_length: septets as u8,
            tp_user_data: ud.clone(),
        };
        let mt = RpDataNetworkToMs {
            rp_message_type: 0x01,
            rp_message_reference: 0,
            rp_originator_address: Some(oa),
            rp_destination_address: None,
            sms_deliver: deliver,
        };
        let encoded = mt.encode().unwrap();
        assert_eq!(encoded[0], 0x01); // RP-DATA n→ms
        assert!(encoded.ends_with(&ud));
        assert_eq!(encoded, mt.encode().unwrap()); // deterministic
    }

    #[test]
    fn encode_rp_ack() {
        let report = SmsSubmitReport {
            tp_udhi: 0,
            tp_failure_cause: None,
            tp_parameter_indicator: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
            tp_pid: None,
            tp_dcs: None,
            tp_user_data_length: None,
            tp_user_data: Vec::new(),
        };
        let ack = RpAck {
            rp_message_type: 0x03,
            rp_message_reference: 7,
            rp_user_data_element_id: 0x41,
            rp_user_data_element_length: 0x09,
            sms_submit_report: report,
        };
        let e = ack.encode().unwrap();
        assert_eq!(e[0], 0x03); // RP-ACK n→ms
        assert_eq!(e[1], 7); // echoes RP-MR
        assert_eq!(e[2], 0x41); // RP-User-Data IEI
    }

    #[test]
    fn alphanumeric_address_encodes() {
        // TON=5 (alphanumeric) sender ID in the transfer-layer form. The four
        // septets T=0x54 P=0x50 D=0x44 U=0x55 pack to 54 28 B1 0A, and the
        // length octet counts useful semi-octets: 28 bits make 7
        // (TS 23.040 §9.1.2.5).
        let a = SMSAddress {
            ton: 5,
            npi: 0,
            address: "TPDU".into(),
        };
        let enc = a.encode(false).unwrap();
        assert_eq!(enc, [0x07, 0xD0, 0x54, 0x28, 0xB1, 0x0A]);
        // An RP address is a BCD number, never alphanumeric.
        assert!(a.encode(true).is_err());
    }

    #[test]
    fn address_bcd_roundtrips_via_decoder() {
        for addr in ["15550100", "155501234"] {
            let a = SMSAddress {
                ton: 1,
                npi: 1,
                address: addr.into(),
            };
            let enc = a.encode(false).unwrap();
            let mut cur = Cursor::new(enc.as_slice());
            let dec = decode_sms_address(&mut cur, false).unwrap().unwrap();
            assert_eq!(dec, a);
        }
    }
}

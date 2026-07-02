//! SMS Transfer-layer PDU codec — 3GPP **TS 23.040** / **TS 23.038** / **TS 24.011**.
//!
//! Encodes and decodes the protocol data units that carry SMS between handsets,
//! IMS, and signalling cores:
//!
//! - **RP-DATA** (MS→Network and Network→MS) — the relay-layer wrapper used on
//!   the Gm interface (SIP MESSAGE body) and in MAP/Diameter MO/MT-Forward-SM.
//! - **SMS-SUBMIT** / **SMS-DELIVER** / **SMS-SUBMIT-REPORT** TPDUs.
//! - **GSM 7-bit** (default alphabet, septet packing per TS 23.038 §6.2.1) and
//!   UCS-2 user data; **User-Data-Header** (concatenation, etc.).
//! - BCD and GSM-7 alphanumeric **SMS addresses** (TON/NPI).
//!
//! Pure Rust, no async, no I/O — just bytes in, bytes out. The same codec is
//! exposed to Python (`import tpdu`) when built with the `python` feature; the
//! Python API mirrors this one.

use byteorder::ReadBytesExt;
use gsm7::{Gsm7Reader, Gsm7Writer};
use std::fmt;
use std::{
    io::{Cursor, Read},
    vec,
};
use tracing::debug;

mod builder;
pub use builder::{
    RpAckBuilder, RpDataMsToNetworkBuilder, RpDataNetworkToMsBuilder, SMSAddressBuilder,
    SmsDeliverBuilder, SmsSubmitBuilder, SmsSubmitReportBuilder, UserDataHeaderBuilder,
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct SMSAddress {
    pub ton: u8,
    pub npi: u8,
    pub address: String,
}

impl SMSAddress {
    pub fn encode(&self, length_as_bytes: bool) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        let address = self.address.clone();

        let address = if self.ton == 0x05 {
            let result = encode_string_to_7bit(&address)
                .map_err(|e| format!("Failed to encode address: {}", e))?;
            data.push(result.len() as u8 * 2);
            address.clone()
        } else if address.len() % 2 != 0 {
            if length_as_bytes {
                data.push((address.len() as u8 / 2) + 2);
            } else {
                data.push(address.len() as u8);
            }
            address.clone() + "F"
        } else {
            if length_as_bytes {
                data.push((address.len() as u8 / 2) + 1);
            } else {
                data.push(address.len() as u8);
            }
            address.clone()
        };

        data.push(1 << 7 | (self.ton << 4) | self.npi);

        if self.ton == 0x05 {
            let result = encode_string_to_7bit(&address)
                .map_err(|e| format!("Failed to encode address: {}", e))?;
            data.extend_from_slice(result.as_slice());
            return Ok(data);
        } else {
            let mut bcd_address = String::new();
            for i in (0..address.len()).step_by(2) {
                let byte = &address[i..i + 2];
                bcd_address.push_str(&byte.chars().rev().collect::<String>());
            }
            let result = hex::decode(bcd_address)
                .map_err(|e| format!("Failed to decode BCD address as hex: {}", e))?;
            data.extend_from_slice(&result);
        }
        Ok(data)
    }
}

#[derive(Debug, Clone)]
pub struct RpDataMsToNetwork {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_originator_address: Option<SMSAddress>,
    pub rp_destination_address: Option<SMSAddress>,
    pub sms_submit: SmsSubmit,
}

#[derive(Debug, Clone)]
pub struct RpDataNetworkToMs {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_originator_address: Option<SMSAddress>,
    pub rp_destination_address: Option<SMSAddress>,
    pub sms_deliver: SmsDeliver,
}

impl RpDataNetworkToMs {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();

        data.push(self.rp_message_type);
        data.push(self.rp_message_reference);

        if let Some(address) = &self.rp_originator_address {
            data.append(&mut address.encode(true)?);
        } else {
            data.push(0);
        }

        if let Some(address) = &self.rp_destination_address {
            data.append(&mut address.encode(true)?);
        } else {
            data.push(0);
        }

        let sms_deliver_encoded = self.sms_deliver.encode()?;
        let tpdu_length = sms_deliver_encoded.len() as u8;
        data.push(tpdu_length);

        data.extend_from_slice(&self.sms_deliver.encode()?);

        Ok(data)
    }
}

#[derive(Debug, Clone)]
pub struct RpAck {
    pub rp_message_type: u8,
    pub rp_message_reference: u8,
    pub rp_user_data_element_id: u8,
    pub rp_user_data_element_length: u8,
    pub sms_submit_report: SmsSubmitReport,
}

impl RpAck {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = vec![
            self.rp_message_type,
            self.rp_message_reference,
            self.rp_user_data_element_id,
            self.rp_user_data_element_length,
        ];
        data.extend_from_slice(&self.sms_submit_report.encode()?);

        Ok(data)
    }
}

#[derive(Debug, Clone)]
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
    pub tp_validity_period: Option<u8>,
    pub tp_user_data_length: u8,
    pub tp_user_data_raw: Vec<u8>,
    pub tp_user_data_header: Option<UserDataHeader>,
    pub tp_user_data: Vec<u8>,
}

#[derive(Debug, Clone)]
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
        let mut data = Vec::new();

        let first_byte = (self.tp_rp as u8) << 7
            | (self.tp_udhi as u8) << 6
            | (self.tp_sri as u8) << 5
            | (self.tp_lp as u8) << 3
            | (self.tp_mms as u8) << 2
            | (self.tp_mti);
        data.push(first_byte);

        data.append(&mut self.tp_originating_address.encode(false)?);

        data.push(self.tp_pid);
        data.push(self.tp_dcs);

        let mut bcd_address = String::new();
        for i in (0..self.tp_service_centre_timestamp.len()).step_by(2) {
            let byte = &self.tp_service_centre_timestamp[i..i + 2];
            bcd_address.push_str(&byte.chars().rev().collect::<String>());
        }

        let result = hex::decode(&bcd_address)
            .map_err(|e| format!("Failed to decode BCD address: {}", e))?;

        data.extend_from_slice(result.as_slice());
        data.push(self.tp_user_data_length);
        data.extend_from_slice(&self.tp_user_data);

        Ok(data)
    }
}

#[derive(Debug, Clone)]
pub struct SmsSubmitReport {
    pub tp_udhi: u8,
    pub tp_parameter_indicator: u8,
    pub tp_service_centre_timestamp: String,
}

impl SmsSubmitReport {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();

        let first_byte = self.tp_udhi << 6 | 0x1;
        data.push(first_byte);

        data.push(self.tp_parameter_indicator);

        let mut bcd_address = String::new();
        for i in (0..self.tp_service_centre_timestamp.len()).step_by(2) {
            let byte = &self.tp_service_centre_timestamp[i..i + 2];
            bcd_address.push_str(&byte.chars().rev().collect::<String>());
        }

        let decoded = hex::decode(&bcd_address)
            .map_err(|e| format!("Failed to decode BCD address: {}", e))?;

        data.extend_from_slice(&decoded);
        Ok(data)
    }
}

pub fn parse_rp_data(data: &[u8]) -> Result<RpDataMsToNetwork, Error> {
    let mut cursor = Cursor::new(data);

    let rp_message_type = cursor
        .read_u8()
        .map_err(|e| format!("Could not read RP-Message-Type {}", e))?;
    debug!("RP-Message Type: {}", rp_message_type);

    let rp_message_reference = cursor
        .read_u8()
        .map_err(|e| format!("Could not read RP-Message-Reference: {}", e))?;
    debug!("RP-Message Reference: {}", rp_message_reference);

    let rp_originator_address = decode_sms_address(&mut cursor, true)
        .map_err(|e| format!("Could not decode RP-Originator Address: {}", e))?;
    debug!("RP-Originator Address: {:?}", rp_originator_address);

    let rp_destination_address = decode_sms_address(&mut cursor, true)
        .map_err(|e| format!("Could not decode RP-Destination Address: {}", e))?;
    debug!("RP-Destination Address: {:?}", rp_destination_address);

    let _tpdu_length = cursor
        .read_u8()
        .map_err(|e| format!("Could not read TPDU Length: {}", e))?;
    debug!("TPDU Length: {}", _tpdu_length);

    let tpdu =
        decode_sms_submit_tpdu(&mut cursor).map_err(|e| format!("Could not decode TPDU: {}", e))?;

    Ok(RpDataMsToNetwork {
        rp_message_type,
        rp_message_reference,
        rp_originator_address,
        rp_destination_address,
        sms_submit: tpdu,
    })
}

pub fn decode_sms_submit_tpdu(cursor: &mut Cursor<&[u8]>) -> Result<SmsSubmit, Error> {
    let first_byte = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read first byte {}", e))?;

    let tp_rp = first_byte >> 7 == 1;
    let tp_udhi = (first_byte >> 6) & 0x01 == 1;
    let tp_srr = (first_byte >> 5) & 0x01 == 1;
    let tp_mti = first_byte << 6 >> 6;
    let tp_rd = first_byte >> 2 == 1;
    let tp_vpf = first_byte >> 4;

    debug!(
        "TP-RP: {}, TP-UDHI: {}, TP-SRR: {}, TP-MTI: {}, TP-RD: {:?}, TP-VPF: {:?}",
        tp_rp, tp_udhi, tp_srr, tp_mti, tp_rd, tp_vpf
    );

    let tp_mr = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read TP-MR {}", e))?;
    debug!("TP-MR: {}", tp_mr);

    let tp_destination_address = decode_sms_address(cursor, false)?;
    debug!("TP-Destination Address: {:?}", tp_destination_address);

    let tp_pid = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read TP-PID {}", e))?;
    debug!("TP-PID: {}", tp_pid);

    let tp_dcs = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read TP-DCS {}", e))?;
    debug!("TP-DCS: {}", tp_dcs);

    let tp_validity_period = if tp_vpf != 0 {
        let tp_validity_period = cursor
            .read_u8()
            .map_err(|e| format!("Unable to read TP-Validity-Period {}", e))?;
        debug!("TP-Validity-Period: {}", tp_validity_period);
        Some(tp_validity_period)
    } else {
        None
    };

    let tp_user_data_length = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read TP-User-Data-Length {}", e))?
        as u16;
    debug!("TP-User-Data-Length: {}", tp_user_data_length);

    let length_in_bytes = if tp_dcs == 0 {
        if (tp_user_data_length * 7) % 8 == 0 {
            tp_user_data_length * 7 / 8
        } else {
            ((tp_user_data_length * 7) / 8) + 1
        }
    } else {
        tp_user_data_length
    };

    let mut raw_user_data = vec![0; length_in_bytes as usize];
    cursor
        .read_exact(&mut raw_user_data)
        .map_err(|e| format!("Unable to read TP-User-Data buffer {}", e))?;

    let mut cursor = Cursor::new(raw_user_data.as_slice());

    let tp_user_data_header = if tp_udhi {
        let udh = Some(
            UserDataHeader::decode(&mut cursor)
                .map_err(|e| format!("Unable to decode User Data Header: {}", e))?,
        );
        cursor.set_position(0);
        udh
    } else {
        None
    };

    let mut tp_user_data = vec![];
    if tp_dcs == 0 {
        tp_user_data = decode_7bit_to_bytes(&mut cursor, tp_user_data_length as usize)
            .map_err(|e| format!("Unable to decode 7-bit TP-User-Data: {}", e))?;

        if tp_user_data_header.is_some() {
            let udhl = tp_user_data_header
                .as_ref()
                .map_or(0, |udh| udh.user_data_header_length as usize);
            tp_user_data = tp_user_data[udhl + 2..].to_vec();
        }
    } else {
        cursor
            .read_to_end(&mut tp_user_data)
            .map_err(|e| format!("Unable to read TP-User-Data as UTF-8: {}", e))?;
    }

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
        tp_user_data_length: tp_user_data_length as u8,
        tp_user_data_raw: raw_user_data.to_vec(),
        tp_user_data_header,
        tp_user_data,
    })
}

fn decode_7bit_to_bytes(
    cursor: &mut Cursor<&[u8]>,
    expected_length: usize,
) -> Result<Vec<u8>, Error> {
    let reader = Gsm7Reader::new(cursor);
    let mut decoded: Vec<u8> = Vec::new();

    for result in reader {
        match result {
            Ok(byte) => decoded.push(
                byte.try_into()
                    .map_err(|e| format!("Failed to convert GSM byte to u8: {}", e))?,
            ),
            Err(e) => return Err(format!("Failed to decode 7-bit GSM data: {}", e).into()),
        }
    }

    if decoded.len() != expected_length && decoded.ends_with(b"@") {
        return Ok(decoded[..decoded.len() - 1].to_vec());
    }

    Ok(decoded)
}

fn encode_string_to_7bit(input: &str) -> Result<Vec<u8>, Error> {
    let mut writer = Gsm7Writer::new(Vec::new());
    writer.write_str(input).map_err(|e| e.to_string())?;
    Ok(writer.into_writer().map_err(|e| e.to_string())?)
}

/// Pack a Unicode string into GSM 7-bit septets per TS 23.038 §6.2.1.
/// Returns `(packed_bytes, septet_count)` where `septet_count` is the
/// value to use for TP-User-Data-Length on a 7-bit DCS message
/// (extension chars `^{}\[~]|€` and form-feed count as 2 septets each).
pub fn pack_gsm7(input: &str) -> Result<(Vec<u8>, usize), Error> {
    let mut writer = Gsm7Writer::new(Vec::new());
    writer.write_str(input).map_err(|e| e.to_string())?;
    let bytes = writer.into_writer().map_err(|e| e.to_string())?;
    let septets = input
        .chars()
        .map(|c| match c {
            '\x0C' | '^' | '{' | '}' | '\\' | '[' | '~' | ']' | '|' | '€' => 2,
            _ => 1,
        })
        .sum();
    Ok((bytes, septets))
}

/// Unpack `septets` septets from a packed GSM 7-bit buffer per TS 23.038
/// §6.2.1.
///
/// When `septets * 7` isn't a byte boundary the buffer carries up to one
/// trailing 0-septet of carrier padding, which the GSM-7 reader surfaces as a
/// spurious trailing `@`. We compute how many septets the buffer actually holds
/// (`len * 8 / 7`) and drop exactly the excess over `septets` (each a trailing
/// `@`), so a genuine trailing `@` in the message is preserved and
/// extension-char-heavy strings — where the character count is *less* than the
/// septet count — round-trip correctly.
pub fn unpack_gsm7(data: &[u8], septets: usize) -> Result<String, Error> {
    let reader = Gsm7Reader::new(Cursor::new(data));
    let mut chars: Vec<char> = Vec::new();
    for r in reader {
        match r {
            Ok(c) => chars.push(c),
            Err(e) => return Err(format!("gsm7 decode: {}", e).into()),
        }
    }
    let mut padding = (data.len() * 8 / 7).saturating_sub(septets);
    while padding > 0 && chars.last() == Some(&'@') {
        chars.pop();
        padding -= 1;
    }
    Ok(chars.into_iter().collect())
}

fn decode_sms_address(
    cursor: &mut Cursor<&[u8]>,
    bytes: bool,
) -> Result<Option<SMSAddress>, Error> {
    let length = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read address length {}", e))? as usize;

    if length == 0 {
        return Ok(None);
    }

    let mut address = String::new();
    let ton_npi = cursor
        .read_u8()
        .map_err(|e| format!("Unable to read TON/NPI {}", e))?;

    let ton_npi = (ton_npi << 1) >> 1;
    let ton = ton_npi >> 4;
    let npi = (ton_npi << 4) >> 4;

    debug!("Address Length: {}, TON/NPI: {}/{}", length, ton, npi);

    let length = if !bytes && length % 2 != 0 {
        length + 1
    } else if bytes {
        (length * 2) - 2
    } else {
        length
    };

    debug!("Decoding address with {} bytes", (length / 2 + 1));

    for _ in 0..(length / 2) {
        let byte = cursor
            .read_u8()
            .map_err(|e| format!("Unable to read address byte {}", e))?;

        let digits = format!("{:02X}", byte);
        address.push_str(digits.chars().rev().collect::<String>().as_str());
    }

    let address = address.replace("F", "");

    Ok(Some(SMSAddress { ton, npi, address }))
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
        assert_eq!(p.sms_submit.tp_vpf, 1);
        assert_eq!(p.sms_submit.tp_validity_period, Some(0xff));
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
            tp_parameter_indicator: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
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
        // TON=5 (alphanumeric) sender ID — encode only (no BCD round-trip).
        let a = SMSAddress {
            ton: 5,
            npi: 0,
            address: "TPDU".into(),
        };
        let enc = a.encode(true).unwrap();
        assert!(!enc.is_empty());
        assert_eq!(enc[1], 0x80 | (5 << 4)); // TON/NPI byte
        assert_eq!(enc, a.encode(true).unwrap()); // deterministic
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

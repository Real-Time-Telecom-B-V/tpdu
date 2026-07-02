//! Fluent builders for the PDU and component types.
//!
//! An ergonomic layer over the public-field structs in the crate root — the
//! structs stay fully usable as literals; these builders are purely additive.
//! The shape mirrors the `smpp34` crate's `SubmitSmBuilder`:
//!
//! - **consuming** setters (`mut self -> Self`) so calls chain,
//! - a required, no-sensible-default field (an inner PDU, or an SMS-DELIVER's
//!   originating address) is passed to `builder(...)` rather than defaulted,
//! - a terminal `build()` that returns the struct. It returns `Result` only for
//!   the types whose [`SmsSubmitBuilder::gsm7_text`]-style helpers can fail to
//!   pack; everything else is infallible.
//!
//! **Nothing here is implicit about data coding.** The text helpers
//! ([`gsm7_text`](SmsDeliverBuilder::gsm7_text) /
//! [`ucs2_text`](SmsDeliverBuilder::ucs2_text)) set the user data *and* its
//! length, but never touch TP-DCS — set that yourself with `.dcs(..)`. Likewise
//! `.validity_period(..)` does not flip `.vpf(..)`. The builder computes the
//! mechanical lengths for you and nothing else.

use crate::{
    pack_gsm7, Error, RpAck, RpDataMsToNetwork, RpDataNetworkToMs, SMSAddress, SmsDeliver,
    SmsSubmit, SmsSubmitReport, UserDataHeader,
};

/// UTF-16BE encode a string into UCS-2 user-data bytes (TS 23.038 §6.2.3).
fn ucs2_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

// ── SMSAddress ───────────────────────────────────────────────────────────────

impl SMSAddress {
    /// Start building an [`SMSAddress`]. Defaults: TON/NPI `0`, empty address.
    pub fn builder() -> SMSAddressBuilder {
        SMSAddressBuilder::default()
    }
}

/// Builder for [`SMSAddress`]. See [`SMSAddress::builder`].
#[derive(Debug, Clone, Default)]
pub struct SMSAddressBuilder {
    ton: u8,
    npi: u8,
    address: String,
}

impl SMSAddressBuilder {
    /// Type-of-number (e.g. `1` international, `5` alphanumeric).
    pub fn ton(mut self, v: u8) -> Self {
        self.ton = v;
        self
    }
    /// Numbering-plan-identification.
    pub fn npi(mut self, v: u8) -> Self {
        self.npi = v;
        self
    }
    /// The digits (or, for TON 5, the alphanumeric label).
    pub fn address(mut self, v: impl Into<String>) -> Self {
        self.address = v.into();
        self
    }
    /// Finish and return the [`SMSAddress`].
    pub fn build(self) -> SMSAddress {
        SMSAddress {
            ton: self.ton,
            npi: self.npi,
            address: self.address,
        }
    }
}

// ── UserDataHeader ───────────────────────────────────────────────────────────

impl UserDataHeader {
    /// Start building a [`UserDataHeader`]. The header length defaults to the
    /// value's byte length — override with [`UserDataHeaderBuilder::length`].
    pub fn builder() -> UserDataHeaderBuilder {
        UserDataHeaderBuilder::default()
    }
}

/// Builder for [`UserDataHeader`]. See [`UserDataHeader::builder`].
#[derive(Debug, Clone, Default)]
pub struct UserDataHeaderBuilder {
    value: Vec<u8>,
    length: Option<u8>,
}

impl UserDataHeaderBuilder {
    /// The header IEIs. Unless [`length`](Self::length) is set, `build()`
    /// derives `user_data_header_length` from this slice.
    pub fn value(mut self, v: impl Into<Vec<u8>>) -> Self {
        self.value = v.into();
        self
    }
    /// Override the header length (defaults to the value's byte length).
    pub fn length(mut self, v: u8) -> Self {
        self.length = Some(v);
        self
    }
    /// Finish and return the [`UserDataHeader`].
    pub fn build(self) -> UserDataHeader {
        let user_data_header_length = self.length.unwrap_or(self.value.len() as u8);
        UserDataHeader {
            user_data_header_length,
            user_data_header_value: self.value,
        }
    }
}

// ── SmsSubmit ────────────────────────────────────────────────────────────────

impl SmsSubmit {
    /// Start building an [`SmsSubmit`] (MO). TP-MTI defaults to `1`
    /// (SMS-SUBMIT); every other field defaults to `0`/`false`/absent.
    pub fn builder() -> SmsSubmitBuilder {
        SmsSubmitBuilder::new()
    }
}

/// Builder for [`SmsSubmit`]. See [`SmsSubmit::builder`].
#[derive(Debug, Clone)]
pub struct SmsSubmitBuilder {
    tp_rp: bool,
    tp_udhi: bool,
    tp_srr: bool,
    tp_mti: u8,
    tp_rd: bool,
    tp_vpf: u8,
    tp_mr: u8,
    tp_destination_address: Option<SMSAddress>,
    tp_pid: u8,
    tp_dcs: u8,
    tp_validity_period: Option<u8>,
    tp_user_data_length: u8,
    tp_user_data_raw: Vec<u8>,
    tp_user_data_header: Option<UserDataHeader>,
    tp_user_data: Vec<u8>,
    err: Option<Error>,
}

impl SmsSubmitBuilder {
    fn new() -> Self {
        SmsSubmitBuilder {
            tp_rp: false,
            tp_udhi: false,
            tp_srr: false,
            tp_mti: 1, // SMS-SUBMIT
            tp_rd: false,
            tp_vpf: 0,
            tp_mr: 0,
            tp_destination_address: None,
            tp_pid: 0,
            tp_dcs: 0,
            tp_validity_period: None,
            tp_user_data_length: 0,
            tp_user_data_raw: Vec::new(),
            tp_user_data_header: None,
            tp_user_data: Vec::new(),
            err: None,
        }
    }

    /// TP-Reply-Path.
    pub fn rp(mut self, v: bool) -> Self {
        self.tp_rp = v;
        self
    }
    /// TP-User-Data-Header-Indicator.
    pub fn udhi(mut self, v: bool) -> Self {
        self.tp_udhi = v;
        self
    }
    /// TP-Status-Report-Request.
    pub fn srr(mut self, v: bool) -> Self {
        self.tp_srr = v;
        self
    }
    /// TP-Message-Type-Indicator (defaults to `1`, SMS-SUBMIT).
    pub fn mti(mut self, v: u8) -> Self {
        self.tp_mti = v;
        self
    }
    /// TP-Reject-Duplicates.
    pub fn rd(mut self, v: bool) -> Self {
        self.tp_rd = v;
        self
    }
    /// TP-Validity-Period-Format. Not implied by [`validity_period`](Self::validity_period).
    pub fn vpf(mut self, v: u8) -> Self {
        self.tp_vpf = v;
        self
    }
    /// TP-Message-Reference.
    pub fn mr(mut self, v: u8) -> Self {
        self.tp_mr = v;
        self
    }
    /// TP-Destination-Address.
    pub fn destination_address(mut self, v: SMSAddress) -> Self {
        self.tp_destination_address = Some(v);
        self
    }
    /// TP-Protocol-Identifier.
    pub fn pid(mut self, v: u8) -> Self {
        self.tp_pid = v;
        self
    }
    /// TP-Data-Coding-Scheme.
    pub fn dcs(mut self, v: u8) -> Self {
        self.tp_dcs = v;
        self
    }
    /// TP-Validity-Period. Set [`vpf`](Self::vpf) too — it is not implied.
    pub fn validity_period(mut self, v: u8) -> Self {
        self.tp_validity_period = Some(v);
        self
    }
    /// Raw user-data bytes. Does **not** set the length — use
    /// [`user_data_length`](Self::user_data_length), or a text helper which sets
    /// both.
    pub fn user_data(mut self, v: impl Into<Vec<u8>>) -> Self {
        self.tp_user_data = v.into();
        self
    }
    /// TP-User-Data-Length (septets for 7-bit DCS, otherwise bytes).
    pub fn user_data_length(mut self, v: u8) -> Self {
        self.tp_user_data_length = v;
        self
    }
    /// The raw on-wire user-data buffer (as surfaced by the decoder).
    pub fn user_data_raw(mut self, v: impl Into<Vec<u8>>) -> Self {
        self.tp_user_data_raw = v.into();
        self
    }
    /// TP-User-Data-Header. Remember to also set [`udhi`](Self::udhi).
    pub fn user_data_header(mut self, v: UserDataHeader) -> Self {
        self.tp_user_data_header = Some(v);
        self
    }
    /// Pack `text` as GSM 7-bit and set both the user data and its septet
    /// length. Does **not** set TP-DCS — pair with `.dcs(0)`. A packing failure
    /// is surfaced by [`build`](Self::build).
    pub fn gsm7_text(mut self, text: impl AsRef<str>) -> Self {
        match pack_gsm7(text.as_ref()) {
            Ok((bytes, septets)) => {
                self.tp_user_data = bytes;
                self.tp_user_data_length = septets as u8;
            }
            Err(e) => self.err = Some(e),
        }
        self
    }
    /// UTF-16BE encode `text` as UCS-2 and set both the user data and its byte
    /// length. Does **not** set TP-DCS — pair with `.dcs(0x08)`.
    pub fn ucs2_text(mut self, text: impl AsRef<str>) -> Self {
        let bytes = ucs2_bytes(text.as_ref());
        self.tp_user_data_length = bytes.len() as u8;
        self.tp_user_data = bytes;
        self
    }
    /// Finish and return the [`SmsSubmit`], or the error from a failed
    /// [`gsm7_text`](Self::gsm7_text).
    pub fn build(self) -> Result<SmsSubmit, Error> {
        if let Some(e) = self.err {
            return Err(e);
        }
        Ok(SmsSubmit {
            tp_rp: self.tp_rp,
            tp_udhi: self.tp_udhi,
            tp_srr: self.tp_srr,
            tp_mti: self.tp_mti,
            tp_rd: self.tp_rd,
            tp_vpf: self.tp_vpf,
            tp_mr: self.tp_mr,
            tp_destination_address: self.tp_destination_address,
            tp_pid: self.tp_pid,
            tp_dcs: self.tp_dcs,
            tp_validity_period: self.tp_validity_period,
            tp_user_data_length: self.tp_user_data_length,
            tp_user_data_raw: self.tp_user_data_raw,
            tp_user_data_header: self.tp_user_data_header,
            tp_user_data: self.tp_user_data,
        })
    }
}

// ── SmsDeliver ───────────────────────────────────────────────────────────────

impl SmsDeliver {
    /// Start building an [`SmsDeliver`] (MT) for the given originating address.
    /// TP-MTI defaults to `0` (SMS-DELIVER); other fields default to
    /// `0`/`false`/empty.
    pub fn builder(originating_address: SMSAddress) -> SmsDeliverBuilder {
        SmsDeliverBuilder::new(originating_address)
    }
}

/// Builder for [`SmsDeliver`]. See [`SmsDeliver::builder`].
#[derive(Debug, Clone)]
pub struct SmsDeliverBuilder {
    tp_rp: bool,
    tp_udhi: bool,
    tp_sri: bool,
    tp_lp: bool,
    tp_mms: bool,
    tp_mti: u8,
    tp_originating_address: SMSAddress,
    tp_pid: u8,
    tp_dcs: u8,
    tp_service_centre_timestamp: String,
    tp_user_data_length: u8,
    tp_user_data: Vec<u8>,
    err: Option<Error>,
}

impl SmsDeliverBuilder {
    fn new(oa: SMSAddress) -> Self {
        SmsDeliverBuilder {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: false,
            tp_mti: 0, // SMS-DELIVER
            tp_originating_address: oa,
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: String::new(),
            tp_user_data_length: 0,
            tp_user_data: Vec::new(),
            err: None,
        }
    }

    /// TP-Reply-Path.
    pub fn rp(mut self, v: bool) -> Self {
        self.tp_rp = v;
        self
    }
    /// TP-User-Data-Header-Indicator.
    pub fn udhi(mut self, v: bool) -> Self {
        self.tp_udhi = v;
        self
    }
    /// TP-Status-Report-Indication.
    pub fn sri(mut self, v: bool) -> Self {
        self.tp_sri = v;
        self
    }
    /// TP-Loop-Prevention.
    pub fn lp(mut self, v: bool) -> Self {
        self.tp_lp = v;
        self
    }
    /// TP-More-Messages-to-Send.
    pub fn mms(mut self, v: bool) -> Self {
        self.tp_mms = v;
        self
    }
    /// TP-Message-Type-Indicator (defaults to `0`, SMS-DELIVER).
    pub fn mti(mut self, v: u8) -> Self {
        self.tp_mti = v;
        self
    }
    /// TP-Originating-Address (also settable via [`SmsDeliver::builder`]).
    pub fn originating_address(mut self, v: SMSAddress) -> Self {
        self.tp_originating_address = v;
        self
    }
    /// TP-Protocol-Identifier.
    pub fn pid(mut self, v: u8) -> Self {
        self.tp_pid = v;
        self
    }
    /// TP-Data-Coding-Scheme.
    pub fn dcs(mut self, v: u8) -> Self {
        self.tp_dcs = v;
        self
    }
    /// TP-Service-Centre-Time-Stamp, as the semi-octet digit string the encoder
    /// swaps into BCD (e.g. `"25010112000000"`).
    pub fn service_centre_timestamp(mut self, v: impl Into<String>) -> Self {
        self.tp_service_centre_timestamp = v.into();
        self
    }
    /// Raw user-data bytes. Does **not** set the length — use
    /// [`user_data_length`](Self::user_data_length), or a text helper which sets
    /// both.
    pub fn user_data(mut self, v: impl Into<Vec<u8>>) -> Self {
        self.tp_user_data = v.into();
        self
    }
    /// TP-User-Data-Length (septets for 7-bit DCS, otherwise bytes).
    pub fn user_data_length(mut self, v: u8) -> Self {
        self.tp_user_data_length = v;
        self
    }
    /// Pack `text` as GSM 7-bit and set both the user data and its septet
    /// length. Does **not** set TP-DCS — pair with `.dcs(0)`. A packing failure
    /// is surfaced by [`build`](Self::build).
    pub fn gsm7_text(mut self, text: impl AsRef<str>) -> Self {
        match pack_gsm7(text.as_ref()) {
            Ok((bytes, septets)) => {
                self.tp_user_data = bytes;
                self.tp_user_data_length = septets as u8;
            }
            Err(e) => self.err = Some(e),
        }
        self
    }
    /// UTF-16BE encode `text` as UCS-2 and set both the user data and its byte
    /// length. Does **not** set TP-DCS — pair with `.dcs(0x08)`.
    pub fn ucs2_text(mut self, text: impl AsRef<str>) -> Self {
        let bytes = ucs2_bytes(text.as_ref());
        self.tp_user_data_length = bytes.len() as u8;
        self.tp_user_data = bytes;
        self
    }
    /// Finish and return the [`SmsDeliver`], or the error from a failed
    /// [`gsm7_text`](Self::gsm7_text).
    pub fn build(self) -> Result<SmsDeliver, Error> {
        if let Some(e) = self.err {
            return Err(e);
        }
        Ok(SmsDeliver {
            tp_rp: self.tp_rp,
            tp_udhi: self.tp_udhi,
            tp_sri: self.tp_sri,
            tp_lp: self.tp_lp,
            tp_mms: self.tp_mms,
            tp_mti: self.tp_mti,
            tp_originating_address: self.tp_originating_address,
            tp_pid: self.tp_pid,
            tp_dcs: self.tp_dcs,
            tp_service_centre_timestamp: self.tp_service_centre_timestamp,
            tp_user_data_length: self.tp_user_data_length,
            tp_user_data: self.tp_user_data,
        })
    }
}

// ── SmsSubmitReport ──────────────────────────────────────────────────────────

impl SmsSubmitReport {
    /// Start building an [`SmsSubmitReport`]. All fields default to `0`/empty.
    pub fn builder() -> SmsSubmitReportBuilder {
        SmsSubmitReportBuilder::default()
    }
}

/// Builder for [`SmsSubmitReport`]. See [`SmsSubmitReport::builder`].
#[derive(Debug, Clone, Default)]
pub struct SmsSubmitReportBuilder {
    tp_udhi: u8,
    tp_parameter_indicator: u8,
    tp_service_centre_timestamp: String,
}

impl SmsSubmitReportBuilder {
    /// TP-User-Data-Header-Indicator bit.
    pub fn udhi(mut self, v: u8) -> Self {
        self.tp_udhi = v;
        self
    }
    /// TP-Parameter-Indicator.
    pub fn parameter_indicator(mut self, v: u8) -> Self {
        self.tp_parameter_indicator = v;
        self
    }
    /// TP-Service-Centre-Time-Stamp digit string (see
    /// [`SmsDeliverBuilder::service_centre_timestamp`]).
    pub fn service_centre_timestamp(mut self, v: impl Into<String>) -> Self {
        self.tp_service_centre_timestamp = v.into();
        self
    }
    /// Finish and return the [`SmsSubmitReport`].
    pub fn build(self) -> SmsSubmitReport {
        SmsSubmitReport {
            tp_udhi: self.tp_udhi,
            tp_parameter_indicator: self.tp_parameter_indicator,
            tp_service_centre_timestamp: self.tp_service_centre_timestamp,
        }
    }
}

// ── RpDataMsToNetwork ────────────────────────────────────────────────────────

impl RpDataMsToNetwork {
    /// Start building an MO RP-DATA around an [`SmsSubmit`]. RP-Message-Type
    /// defaults to `0` (RP-DATA MS→Network); references/addresses default to
    /// `0`/absent.
    pub fn builder(sms_submit: SmsSubmit) -> RpDataMsToNetworkBuilder {
        RpDataMsToNetworkBuilder::new(sms_submit)
    }
}

/// Builder for [`RpDataMsToNetwork`]. See [`RpDataMsToNetwork::builder`].
#[derive(Debug, Clone)]
pub struct RpDataMsToNetworkBuilder {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<SMSAddress>,
    rp_destination_address: Option<SMSAddress>,
    sms_submit: SmsSubmit,
}

impl RpDataMsToNetworkBuilder {
    fn new(sms_submit: SmsSubmit) -> Self {
        RpDataMsToNetworkBuilder {
            rp_message_type: 0, // RP-DATA ms→n
            rp_message_reference: 0,
            rp_originator_address: None,
            rp_destination_address: None,
            sms_submit,
        }
    }
    /// RP-Message-Type (defaults to `0`, RP-DATA MS→Network).
    pub fn message_type(mut self, v: u8) -> Self {
        self.rp_message_type = v;
        self
    }
    /// RP-Message-Reference.
    pub fn message_reference(mut self, v: u8) -> Self {
        self.rp_message_reference = v;
        self
    }
    /// RP-Originator-Address.
    pub fn originator_address(mut self, v: SMSAddress) -> Self {
        self.rp_originator_address = Some(v);
        self
    }
    /// RP-Destination-Address (the SMSC, for an MO submit).
    pub fn destination_address(mut self, v: SMSAddress) -> Self {
        self.rp_destination_address = Some(v);
        self
    }
    /// Replace the wrapped [`SmsSubmit`].
    pub fn sms_submit(mut self, v: SmsSubmit) -> Self {
        self.sms_submit = v;
        self
    }
    /// Finish and return the [`RpDataMsToNetwork`].
    pub fn build(self) -> RpDataMsToNetwork {
        RpDataMsToNetwork {
            rp_message_type: self.rp_message_type,
            rp_message_reference: self.rp_message_reference,
            rp_originator_address: self.rp_originator_address,
            rp_destination_address: self.rp_destination_address,
            sms_submit: self.sms_submit,
        }
    }
}

// ── RpDataNetworkToMs ────────────────────────────────────────────────────────

impl RpDataNetworkToMs {
    /// Start building an MT RP-DATA around an [`SmsDeliver`]. RP-Message-Type
    /// defaults to `1` (RP-DATA Network→MS); references/addresses default to
    /// `0`/absent.
    pub fn builder(sms_deliver: SmsDeliver) -> RpDataNetworkToMsBuilder {
        RpDataNetworkToMsBuilder::new(sms_deliver)
    }
}

/// Builder for [`RpDataNetworkToMs`]. See [`RpDataNetworkToMs::builder`].
#[derive(Debug, Clone)]
pub struct RpDataNetworkToMsBuilder {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<SMSAddress>,
    rp_destination_address: Option<SMSAddress>,
    sms_deliver: SmsDeliver,
}

impl RpDataNetworkToMsBuilder {
    fn new(sms_deliver: SmsDeliver) -> Self {
        RpDataNetworkToMsBuilder {
            rp_message_type: 1, // RP-DATA n→ms
            rp_message_reference: 0,
            rp_originator_address: None,
            rp_destination_address: None,
            sms_deliver,
        }
    }
    /// RP-Message-Type (defaults to `1`, RP-DATA Network→MS).
    pub fn message_type(mut self, v: u8) -> Self {
        self.rp_message_type = v;
        self
    }
    /// RP-Message-Reference.
    pub fn message_reference(mut self, v: u8) -> Self {
        self.rp_message_reference = v;
        self
    }
    /// RP-Originator-Address (the SMSC, for an MT deliver).
    pub fn originator_address(mut self, v: SMSAddress) -> Self {
        self.rp_originator_address = Some(v);
        self
    }
    /// RP-Destination-Address.
    pub fn destination_address(mut self, v: SMSAddress) -> Self {
        self.rp_destination_address = Some(v);
        self
    }
    /// Replace the wrapped [`SmsDeliver`].
    pub fn sms_deliver(mut self, v: SmsDeliver) -> Self {
        self.sms_deliver = v;
        self
    }
    /// Finish and return the [`RpDataNetworkToMs`]. Encode it with
    /// [`RpDataNetworkToMs::encode`].
    pub fn build(self) -> RpDataNetworkToMs {
        RpDataNetworkToMs {
            rp_message_type: self.rp_message_type,
            rp_message_reference: self.rp_message_reference,
            rp_originator_address: self.rp_originator_address,
            rp_destination_address: self.rp_destination_address,
            sms_deliver: self.sms_deliver,
        }
    }
}

// ── RpAck ────────────────────────────────────────────────────────────────────

impl RpAck {
    /// Start building an RP-ACK around an [`SmsSubmitReport`]. RP-Message-Type
    /// defaults to `3` (RP-ACK Network→MS) and the RP-User-Data element IEI to
    /// `0x41`; other fields default to `0`.
    pub fn builder(sms_submit_report: SmsSubmitReport) -> RpAckBuilder {
        RpAckBuilder::new(sms_submit_report)
    }
}

/// Builder for [`RpAck`]. See [`RpAck::builder`].
#[derive(Debug, Clone)]
pub struct RpAckBuilder {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_user_data_element_id: u8,
    rp_user_data_element_length: u8,
    sms_submit_report: SmsSubmitReport,
}

impl RpAckBuilder {
    fn new(sms_submit_report: SmsSubmitReport) -> Self {
        RpAckBuilder {
            rp_message_type: 3, // RP-ACK n→ms
            rp_message_reference: 0,
            rp_user_data_element_id: 0x41,
            rp_user_data_element_length: 0,
            sms_submit_report,
        }
    }
    /// RP-Message-Type (defaults to `3`, RP-ACK Network→MS).
    pub fn message_type(mut self, v: u8) -> Self {
        self.rp_message_type = v;
        self
    }
    /// RP-Message-Reference (echoes the RP-DATA it acknowledges).
    pub fn message_reference(mut self, v: u8) -> Self {
        self.rp_message_reference = v;
        self
    }
    /// RP-User-Data element IEI (defaults to `0x41`).
    pub fn user_data_element_id(mut self, v: u8) -> Self {
        self.rp_user_data_element_id = v;
        self
    }
    /// RP-User-Data element length.
    pub fn user_data_element_length(mut self, v: u8) -> Self {
        self.rp_user_data_element_length = v;
        self
    }
    /// Replace the wrapped [`SmsSubmitReport`].
    pub fn sms_submit_report(mut self, v: SmsSubmitReport) -> Self {
        self.sms_submit_report = v;
        self
    }
    /// Finish and return the [`RpAck`]. Encode it with [`RpAck::encode`].
    pub fn build(self) -> RpAck {
        RpAck {
            rp_message_type: self.rp_message_type,
            rp_message_reference: self.rp_message_reference,
            rp_user_data_element_id: self.rp_user_data_element_id,
            rp_user_data_element_length: self.rp_user_data_element_length,
            sms_submit_report: self.sms_submit_report,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic data only: fictional 555-01xx MSISDNs, neutral text.

    #[test]
    fn sms_address_builder_matches_literal() {
        let built = SMSAddress::builder().ton(1).npi(1).address("15550100").build();
        assert_eq!(
            built,
            SMSAddress {
                ton: 1,
                npi: 1,
                address: "15550100".into(),
            }
        );
    }

    #[test]
    fn udh_builder_derives_length() {
        let built = UserDataHeader::builder()
            .value(vec![0x00, 0x03, 0x42, 0x02, 0x01])
            .build();
        assert_eq!(built.user_data_header_length, 5);
        assert_eq!(built.user_data_header_value, vec![0x00, 0x03, 0x42, 0x02, 0x01]);

        // Explicit override wins over the derived length.
        let overridden = UserDataHeader::builder().value(vec![0xaa]).length(9).build();
        assert_eq!(overridden.user_data_header_length, 9);
    }

    #[test]
    fn deliver_builder_gsm7_matches_hand_built_encode() {
        let oa = SMSAddress::builder().ton(1).npi(1).address("15550199").build();
        let (ud, septets) = pack_gsm7("delivered").unwrap();

        let built = SmsDeliver::builder(oa.clone())
            .mms(true)
            .dcs(0)
            .service_centre_timestamp("25010112000000")
            .gsm7_text("delivered")
            .build()
            .unwrap();

        let hand = SmsDeliver {
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_mti: 0,
            tp_originating_address: oa,
            tp_pid: 0,
            tp_dcs: 0,
            tp_service_centre_timestamp: "25010112000000".into(),
            tp_user_data_length: septets as u8,
            tp_user_data: ud,
        };

        assert_eq!(built.encode().unwrap(), hand.encode().unwrap());
    }

    #[test]
    fn deliver_builder_ucs2_sets_byte_length() {
        let oa = SMSAddress::builder().ton(1).npi(1).address("15550102").build();
        let built = SmsDeliver::builder(oa)
            .dcs(0x08)
            .service_centre_timestamp("25010112000000")
            .ucs2_text("Hé€")
            .build()
            .unwrap();
        // 3 UTF-16 code units → 6 bytes.
        assert_eq!(built.tp_user_data_length, 6);
        assert_eq!(built.tp_user_data.len(), 6);
    }

    #[test]
    fn submit_builder_roundtrips_through_parser() {
        let dest = SMSAddress::builder().ton(1).npi(1).address("15550100").build();
        let submit = SmsSubmit::builder()
            .mr(7)
            .destination_address(dest.clone())
            .dcs(0)
            .gsm7_text("ping")
            .build()
            .unwrap();

        let mo = RpDataMsToNetwork::builder(submit)
            .message_reference(1)
            .build();

        // Assemble the MO RP-DATA on the wire the same way the tests do, then
        // parse it back and confirm the builder produced the right fields.
        let tpdu = {
            let s = &mo.sms_submit;
            let mut t = vec![
                (s.tp_udhi as u8) << 6 | s.tp_mti,
                s.tp_mr,
            ];
            t.extend(s.tp_destination_address.as_ref().unwrap().encode(false).unwrap());
            t.push(s.tp_pid);
            t.push(s.tp_dcs);
            t.push(s.tp_user_data_length);
            t.extend_from_slice(&s.tp_user_data);
            t
        };
        let mut rp = vec![mo.rp_message_type, mo.rp_message_reference, 0x00, 0x00];
        rp.push(tpdu.len() as u8);
        rp.extend_from_slice(&tpdu);

        let parsed = crate::parse_rp_data(&rp).unwrap();
        assert_eq!(parsed.rp_message_reference, 1);
        assert_eq!(parsed.sms_submit.tp_mr, 7);
        assert_eq!(parsed.sms_submit.tp_destination_address, Some(dest));
        assert_eq!(parsed.sms_submit.tp_user_data, b"ping");
    }

    #[test]
    fn rp_ack_builder_defaults_and_encodes() {
        let report = SmsSubmitReport::builder()
            .service_centre_timestamp("25010112000000")
            .build();
        let ack = RpAck::builder(report).message_reference(7).build();
        let e = ack.encode().unwrap();
        assert_eq!(e[0], 0x03); // default RP-ACK n→ms
        assert_eq!(e[1], 7); // echoed RP-MR
        assert_eq!(e[2], 0x41); // default RP-User-Data IEI
    }

    #[test]
    fn gsm7_text_error_surfaces_at_build() {
        // A char outside the GSM 7-bit alphabet fails packing; the error is
        // deferred to build() so setters stay chainable.
        let oa = SMSAddress::builder().address("15550100").build();
        let r = SmsDeliver::builder(oa).gsm7_text("😀").build();
        assert!(r.is_err());
    }
}

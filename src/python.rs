//! PyO3 bindings for the `tpdu` codec — `import tpdu`.
//!
//! The Python API mirrors the Rust crate: parse RP-DATA / SMS-SUBMIT, build
//! SMS-DELIVER / RP-DATA Network→MS / RP-ACK, and pack/unpack GSM 7-bit. Use it
//! to:
//!
//! * parse RP-DATA carrying SMS-SUBMIT (UE-originated MO traffic arriving as the
//!   body of a SIP MESSAGE on the Gm interface);
//! * parse SMS-SUBMIT TPDU bytes directly (e.g. an SMPP `submit_sm`
//!   `short_message` with `esm_class & 0x40`, or an SS7 MO-Forward-SM);
//! * build SMS-DELIVER TPDU bytes for MT delivery via MAP / Diameter SGd
//!   MT-Forward-SM;
//! * build RP-DATA Network→MS bodies for MT delivery via SIP MESSAGE.
//!
//! Two entry points share one registration:
//! * `#[pymodule] fn tpdu` — the standalone extension module (`import tpdu`).
//! * [`register`] — grafts a `tpdu` submodule onto a parent module, so a host
//!   application that embeds CPython can expose the codec under its own
//!   namespace in-process.

use std::io::Cursor;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

/// Surface codec errors to Python as `ValueError`.
impl From<crate::Error> for PyErr {
    fn from(e: crate::Error) -> Self {
        PyValueError::new_err(e.to_string())
    }
}

/// Standalone extension module: `import tpdu`.
///
/// `gil_used = false` declares the module safe under free-threaded CPython
/// (PEP 703): the codec is pure and holds no shared mutable state, so importing
/// it does not force the GIL back on a no-GIL interpreter.
#[pymodule(gil_used = false)]
fn tpdu(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Bind a `tpdu` submodule onto `parent` — a module created by a host
/// application that embeds CPython. The host's package then re-exports it so
/// scripts can import the `tpdu` submodule and use it directly.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let tpdu = PyModule::new(py, "tpdu")?;
    add_contents(&tpdu)?;
    parent.setattr("tpdu", &tpdu)?;
    Ok(())
}

/// Populate `m` with every tpdu class and function. Use this from a host that
/// builds its own module — e.g. to expose the codec as its own top-level
/// namespace — instead of grafting a submodule with [`register`].
pub fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Register every class and function onto `m` — shared by the standalone
/// module, [`register`] and [`populate`] so the surfaces never drift.
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Address>()?;
    m.add_class::<UserDataHeader>()?;
    m.add_class::<SmsSubmit>()?;
    m.add_class::<SmsDeliver>()?;
    m.add_class::<RpData>()?;
    m.add_class::<RpDataNetworkToMs>()?;
    m.add_class::<SmsSubmitReport>()?;
    m.add_class::<RpAckNetworkToMs>()?;
    m.add_class::<AddressBuilder>()?;
    m.add_class::<UserDataHeaderBuilder>()?;
    m.add_class::<SmsDeliverBuilder>()?;
    m.add_class::<RpDataNetworkToMsBuilder>()?;
    m.add_class::<SmsSubmitReportBuilder>()?;
    m.add_class::<RpAckNetworkToMsBuilder>()?;
    m.add_function(wrap_pyfunction!(parse_rp_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_sms_submit, m)?)?;
    m.add_function(wrap_pyfunction!(destination_from_tpdu, m)?)?;
    m.add_function(wrap_pyfunction!(build_sms_deliver_tpdu, m)?)?;
    m.add_function(wrap_pyfunction!(pack_gsm7, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_gsm7, m)?)?;
    Ok(())
}

// ── Address ─────────────────────────────────────────────────────────────

/// SMS address (TP-DA / TP-OA / RP-OA / RP-DA shape).
#[pyclass(module = "tpdu", name = "Address", from_py_object)]
#[derive(Debug, Clone)]
pub struct Address {
    inner: crate::SMSAddress,
}

#[pymethods]
impl Address {
    #[new]
    #[pyo3(signature = (address, ton=1, npi=1))]
    fn new(address: String, ton: u8, npi: u8) -> Self {
        Self {
            inner: crate::SMSAddress { ton, npi, address },
        }
    }

    /// Start a fluent [`AddressBuilder`] (TON/NPI default to `1`).
    #[staticmethod]
    fn builder() -> AddressBuilder {
        AddressBuilder {
            ton: 1,
            npi: 1,
            address: String::new(),
        }
    }

    #[getter]
    fn ton(&self) -> u8 {
        self.inner.ton
    }

    #[getter]
    fn npi(&self) -> u8 {
        self.inner.npi
    }

    #[getter]
    fn address(&self) -> String {
        self.inner.address.clone()
    }

    /// E.164 form with leading `+` when the TON suggests international.
    fn to_e164(&self) -> String {
        match self.inner.ton {
            0x01 => format!("+{}", self.inner.address),
            _ => self.inner.address.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Address(ton={}, npi={}, address={:?})",
            self.inner.ton, self.inner.npi, self.inner.address
        )
    }
}

impl Address {
    pub(crate) fn from_inner(inner: crate::SMSAddress) -> Self {
        Self { inner }
    }
}

// ── UserDataHeader ──────────────────────────────────────────────────────

#[pyclass(module = "tpdu", name = "UserDataHeader", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct UserDataHeader {
    inner: crate::UserDataHeader,
}

#[pymethods]
impl UserDataHeader {
    #[new]
    fn new(value: Vec<u8>) -> Self {
        Self {
            inner: crate::UserDataHeader {
                user_data_header_length: value.len() as u8,
                user_data_header_value: value,
            },
        }
    }

    /// Start a fluent [`UserDataHeaderBuilder`]; the length is derived from the
    /// value unless overridden.
    #[staticmethod]
    fn builder() -> UserDataHeaderBuilder {
        UserDataHeaderBuilder {
            value: Vec::new(),
            length: None,
        }
    }

    #[getter]
    fn length(&self) -> u8 {
        self.inner.user_data_header_length
    }

    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.user_data_header_value)
    }

    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }
}

// ── SmsSubmit ───────────────────────────────────────────────────────────

#[pyclass(module = "tpdu", name = "SmsSubmit", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct SmsSubmit {
    inner: crate::SmsSubmit,
}

#[pymethods]
impl SmsSubmit {
    #[getter]
    fn tp_rp(&self) -> bool {
        self.inner.tp_rp
    }
    #[getter]
    fn tp_udhi(&self) -> bool {
        self.inner.tp_udhi
    }
    #[getter]
    fn tp_srr(&self) -> bool {
        self.inner.tp_srr
    }
    #[getter]
    fn tp_mti(&self) -> u8 {
        self.inner.tp_mti
    }
    #[getter]
    fn tp_rd(&self) -> bool {
        self.inner.tp_rd
    }
    #[getter]
    fn tp_vpf(&self) -> u8 {
        self.inner.tp_vpf
    }
    #[getter]
    fn tp_mr(&self) -> u8 {
        self.inner.tp_mr
    }
    #[getter]
    fn tp_pid(&self) -> u8 {
        self.inner.tp_pid
    }
    #[getter]
    fn tp_dcs(&self) -> u8 {
        self.inner.tp_dcs
    }

    #[getter]
    fn tp_destination_address(&self) -> Option<Address> {
        self.inner
            .tp_destination_address
            .clone()
            .map(Address::from_inner)
    }

    #[getter]
    fn tp_validity_period(&self) -> Option<u8> {
        self.inner.tp_validity_period
    }
    #[getter]
    fn tp_user_data_length(&self) -> u8 {
        self.inner.tp_user_data_length
    }

    #[getter]
    fn tp_user_data_raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.tp_user_data_raw)
    }

    #[getter]
    fn tp_user_data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.tp_user_data)
    }

    /// Decoded user data as a Python str when DCS=0 (GSM 7-bit) or
    /// DCS=8 (UCS-2). Returns None for binary / unknown encodings.
    fn text(&self) -> Option<String> {
        match self.inner.tp_dcs {
            0 => Some(String::from_utf8_lossy(&self.inner.tp_user_data).into_owned()),
            8 => {
                let bytes = &self.inner.tp_user_data;
                if bytes.len() % 2 != 0 {
                    return None;
                }
                let codepoints: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&codepoints))
            }
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SmsSubmit(tp_mti={}, tp_dcs=0x{:02x}, tp_pid=0x{:02x}, dest={:?}, udl={})",
            self.inner.tp_mti,
            self.inner.tp_dcs,
            self.inner.tp_pid,
            self.inner
                .tp_destination_address
                .as_ref()
                .map(|a| a.address.clone()),
            self.inner.tp_user_data_length,
        )
    }
}

// ── SmsDeliver ──────────────────────────────────────────────────────────

#[pyclass(module = "tpdu", name = "SmsDeliver", from_py_object)]
#[derive(Debug, Clone)]
pub struct SmsDeliver {
    inner: crate::SmsDeliver,
}

#[pymethods]
impl SmsDeliver {
    /// Construct an SMS-DELIVER TPDU. Fields default to common MT-shape
    /// values; override via kwargs.
    ///
    /// `user_data_length` (TP-UDL) defaults to `len(user_data)` — correct for
    /// 8-bit and UCS-2 DCS, where TP-UDL counts octets. For DCS=0 (GSM 7-bit
    /// packed) TP-UDL must count *septets*, which generally differs from the
    /// packed byte count: pass it explicitly (use `pack_gsm7` to get both).
    #[new]
    #[pyo3(signature = (
        originating_address,
        user_data,
        *,
        tp_rp = false,
        tp_udhi = false,
        tp_sri = false,
        tp_lp = false,
        tp_mms = true,
        tp_pid = 0,
        tp_dcs = 0,
        scts = None,
        user_data_length = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        originating_address: Address,
        user_data: Vec<u8>,
        tp_rp: bool,
        tp_udhi: bool,
        tp_sri: bool,
        tp_lp: bool,
        tp_mms: bool,
        tp_pid: u8,
        tp_dcs: u8,
        scts: Option<String>,
        user_data_length: Option<u8>,
    ) -> Self {
        let scts = scts.unwrap_or_else(now_scts);
        let tp_user_data_length = user_data_length.unwrap_or(user_data.len() as u8);
        Self {
            inner: crate::SmsDeliver {
                tp_rp,
                tp_udhi,
                tp_sri,
                tp_lp,
                tp_mms,
                tp_mti: 0, // SMS-DELIVER
                tp_originating_address: originating_address.inner,
                tp_pid,
                tp_dcs,
                tp_service_centre_timestamp: scts,
                tp_user_data_length,
                tp_user_data: user_data,
            },
        }
    }

    /// Start a fluent [`SmsDeliverBuilder`] for `originating_address`. Mirrors
    /// the kwargs constructor's defaults (`tp_mms=True`, SCTS = UTC-now) and adds
    /// `gsm7_text` / `ucs2_text` helpers that also set TP-UDL for you.
    #[staticmethod]
    fn builder(originating_address: Address) -> SmsDeliverBuilder {
        SmsDeliverBuilder {
            oa: originating_address.inner,
            tp_rp: false,
            tp_udhi: false,
            tp_sri: false,
            tp_lp: false,
            tp_mms: true,
            tp_pid: 0,
            tp_dcs: 0,
            scts: None,
            user_data: Vec::new(),
            user_data_length: None,
            err: None,
        }
    }

    /// Encode to wire bytes (TP-DELIVER, suitable for SMS-DELIVER inside an
    /// MT-Forward-SM or RP-DATA Network→MS).
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode()?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!(
            "SmsDeliver(oa={:?}, dcs=0x{:02x}, udl={})",
            self.inner.tp_originating_address.address,
            self.inner.tp_dcs,
            self.inner.tp_user_data_length,
        )
    }
}

// ── RpData (MS → Network, parsed from a SIP MESSAGE body) ───────────────

#[pyclass(module = "tpdu", name = "RpData", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct RpData {
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<Address>,
    rp_destination_address: Option<Address>,
    sms_submit: SmsSubmit,
}

#[pymethods]
impl RpData {
    #[getter]
    fn rp_message_type(&self) -> u8 {
        self.rp_message_type
    }
    #[getter]
    fn rp_message_reference(&self) -> u8 {
        self.rp_message_reference
    }

    #[getter]
    fn rp_originator_address(&self) -> Option<Address> {
        self.rp_originator_address.clone()
    }

    #[getter]
    fn rp_destination_address(&self) -> Option<Address> {
        self.rp_destination_address.clone()
    }

    #[getter]
    fn sms_submit(&self) -> SmsSubmit {
        self.sms_submit.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "RpData(type={}, mr={}, sms_submit={})",
            self.rp_message_type,
            self.rp_message_reference,
            self.sms_submit.__repr__(),
        )
    }
}

// ── RpDataNetworkToMs (MT delivery body for a SIP MESSAGE) ──────────────

#[pyclass(module = "tpdu", name = "RpDataNetworkToMs", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct RpDataNetworkToMs {
    inner: crate::RpDataNetworkToMs,
}

#[pymethods]
impl RpDataNetworkToMs {
    #[new]
    #[pyo3(signature = (
        sms_deliver,
        *,
        rp_message_type = 0x01,    // RP-DATA Network→MS
        rp_message_reference = 0,
        rp_originator_address = None,
        rp_destination_address = None,
    ))]
    fn new(
        sms_deliver: SmsDeliver,
        rp_message_type: u8,
        rp_message_reference: u8,
        rp_originator_address: Option<Address>,
        rp_destination_address: Option<Address>,
    ) -> Self {
        Self {
            inner: crate::RpDataNetworkToMs {
                rp_message_type,
                rp_message_reference,
                rp_originator_address: rp_originator_address.map(|a| a.inner),
                rp_destination_address: rp_destination_address.map(|a| a.inner),
                sms_deliver: sms_deliver.inner,
            },
        }
    }

    /// Start a fluent [`RpDataNetworkToMsBuilder`] around `sms_deliver`
    /// (RP-Message-Type defaults to `0x01`, RP-DATA Network→MS).
    #[staticmethod]
    fn builder(sms_deliver: SmsDeliver) -> RpDataNetworkToMsBuilder {
        RpDataNetworkToMsBuilder {
            sms_deliver: sms_deliver.inner,
            rp_message_type: 0x01,
            rp_message_reference: 0,
            rp_originator_address: None,
            rp_destination_address: None,
        }
    }

    /// Encode to wire bytes — drop into a SIP MESSAGE body with
    /// `Content-Type: application/vnd.3gpp.sms`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode()?;
        Ok(PyBytes::new(py, &bytes))
    }
}

// ── SmsSubmitReport (RP-ACK TPDU payload, n→ms) ─────────────────────────

/// SMS-SUBMIT-REPORT for RP-ACK (TS 23.040 §9.2.2.1a).
///
/// Carries TP-SCTS back to the UE inside an RP-ACK Network→MS; the SC
/// timestamp lets the UE confirm when the network accepted the MO.
#[pyclass(module = "tpdu", name = "SmsSubmitReport", from_py_object)]
#[derive(Debug, Clone)]
pub struct SmsSubmitReport {
    inner: crate::SmsSubmitReport,
}

#[pymethods]
impl SmsSubmitReport {
    /// `scts` defaults to UTC-now in TS 23.040 §9.2.3.11 form (14 hex digits,
    /// BCD-pair-swapped at encode time).
    #[new]
    #[pyo3(signature = (*, tp_udhi = false, tp_parameter_indicator = 0, scts = None))]
    fn new(tp_udhi: bool, tp_parameter_indicator: u8, scts: Option<String>) -> Self {
        Self {
            inner: crate::SmsSubmitReport {
                tp_udhi: tp_udhi as u8,
                tp_parameter_indicator,
                tp_service_centre_timestamp: scts.unwrap_or_else(now_scts),
            },
        }
    }

    /// Start a fluent [`SmsSubmitReportBuilder`] (SCTS defaults to UTC-now).
    #[staticmethod]
    fn builder() -> SmsSubmitReportBuilder {
        SmsSubmitReportBuilder {
            tp_udhi: false,
            tp_parameter_indicator: 0,
            scts: None,
        }
    }

    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode()?;
        Ok(PyBytes::new(py, &bytes))
    }
}

// ── RpAckNetworkToMs (RP-ACK n→ms over a SIP MESSAGE) ───────────────────

/// RP-ACK Network→MS (TS 24.011 §7.3.2.1).
///
/// Built by the IP-SM-GW immediately after accepting an MO RP-DATA from a UE;
/// `rp_message_reference` must echo the inbound RP-MR so the UE can correlate.
#[pyclass(module = "tpdu", name = "RpAckNetworkToMs", skip_from_py_object)]
#[derive(Debug, Clone)]
pub struct RpAckNetworkToMs {
    inner: crate::RpAck,
}

#[pymethods]
impl RpAckNetworkToMs {
    #[new]
    #[pyo3(signature = (sms_submit_report, *, rp_message_reference))]
    fn new(sms_submit_report: SmsSubmitReport, rp_message_reference: u8) -> PyResult<Self> {
        // Precompute the RP-User-Data IE length; a bad SCTS surfaces here
        // rather than at encode().
        let ie_len = sms_submit_report.inner.encode()?.len();
        Ok(Self {
            inner: crate::RpAck {
                rp_message_type: 0x03, // RP-ACK n→ms (TS 24.011 §8.2.2)
                rp_message_reference,
                rp_user_data_element_id: 0x41, // RP-User-Data IEI (§8.2.5.3)
                rp_user_data_element_length: ie_len as u8,
                sms_submit_report: sms_submit_report.inner,
            },
        })
    }

    /// Start a fluent [`RpAckNetworkToMsBuilder`] around `sms_submit_report`
    /// (RP-ACK Network→MS; RP-Message-Reference defaults to `0`).
    #[staticmethod]
    fn builder(sms_submit_report: SmsSubmitReport) -> RpAckNetworkToMsBuilder {
        RpAckNetworkToMsBuilder {
            sms_submit_report: sms_submit_report.inner,
            rp_message_reference: 0,
        }
    }

    /// Encode to wire bytes — drop into a SIP MESSAGE body with
    /// `Content-Type: application/vnd.3gpp.sms`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode()?;
        Ok(PyBytes::new(py, &bytes))
    }
}

// ── Fluent builders ─────────────────────────────────────────────────────
//
// PyO3 mirror of the Rust `*Builder` types. Setters mutate in place and return
// the receiver (`PyRefMut`) so calls chain the Pythonic way; `build()` clones
// out the finished object. Defaults follow the kwargs constructors above, not
// the Rust builders (e.g. Address TON/NPI = 1, SmsDeliver tp_mms = True), so the
// two Python construction styles agree. The `gsm7_text` / `ucs2_text` helpers
// set the user data *and* TP-UDL but never TP-DCS — set that with `.dcs(..)`.

/// Builder for [`Address`]. See [`Address::builder`].
#[pyclass(module = "tpdu", name = "AddressBuilder", skip_from_py_object)]
pub struct AddressBuilder {
    ton: u8,
    npi: u8,
    address: String,
}

#[pymethods]
impl AddressBuilder {
    fn ton(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.ton = v;
        slf
    }
    fn npi(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.npi = v;
        slf
    }
    fn address(mut slf: PyRefMut<'_, Self>, v: String) -> PyRefMut<'_, Self> {
        slf.address = v;
        slf
    }
    fn build(&self) -> Address {
        Address {
            inner: crate::SMSAddress {
                ton: self.ton,
                npi: self.npi,
                address: self.address.clone(),
            },
        }
    }
}

/// Builder for [`UserDataHeader`]. See [`UserDataHeader::builder`].
#[pyclass(module = "tpdu", name = "UserDataHeaderBuilder", skip_from_py_object)]
pub struct UserDataHeaderBuilder {
    value: Vec<u8>,
    length: Option<u8>,
}

#[pymethods]
impl UserDataHeaderBuilder {
    fn value(mut slf: PyRefMut<'_, Self>, v: Vec<u8>) -> PyRefMut<'_, Self> {
        slf.value = v;
        slf
    }
    fn length(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.length = Some(v);
        slf
    }
    fn build(&self) -> UserDataHeader {
        let length = self.length.unwrap_or(self.value.len() as u8);
        UserDataHeader {
            inner: crate::UserDataHeader {
                user_data_header_length: length,
                user_data_header_value: self.value.clone(),
            },
        }
    }
}

/// Builder for [`SmsDeliver`]. See [`SmsDeliver::builder`].
#[pyclass(module = "tpdu", name = "SmsDeliverBuilder", skip_from_py_object)]
pub struct SmsDeliverBuilder {
    oa: crate::SMSAddress,
    tp_rp: bool,
    tp_udhi: bool,
    tp_sri: bool,
    tp_lp: bool,
    tp_mms: bool,
    tp_pid: u8,
    tp_dcs: u8,
    scts: Option<String>,
    user_data: Vec<u8>,
    user_data_length: Option<u8>,
    err: Option<crate::Error>,
}

#[pymethods]
impl SmsDeliverBuilder {
    fn rp(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_rp = v;
        slf
    }
    fn udhi(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_udhi = v;
        slf
    }
    fn sri(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_sri = v;
        slf
    }
    fn lp(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_lp = v;
        slf
    }
    fn mms(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_mms = v;
        slf
    }
    fn pid(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.tp_pid = v;
        slf
    }
    fn dcs(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.tp_dcs = v;
        slf
    }
    fn scts(mut slf: PyRefMut<'_, Self>, v: String) -> PyRefMut<'_, Self> {
        slf.scts = Some(v);
        slf
    }
    fn originating_address(mut slf: PyRefMut<'_, Self>, v: Address) -> PyRefMut<'_, Self> {
        slf.oa = v.inner;
        slf
    }
    /// Set the raw user-data bytes without touching TP-UDL (use
    /// `user_data_length`, or a text helper which sets both).
    fn user_data(mut slf: PyRefMut<'_, Self>, v: Vec<u8>) -> PyRefMut<'_, Self> {
        slf.user_data = v;
        slf
    }
    fn user_data_length(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.user_data_length = Some(v);
        slf
    }
    /// Pack `text` as GSM 7-bit and set the user data + septet TP-UDL. Pair with
    /// `.dcs(0)`. A packing failure surfaces at `build()`.
    fn gsm7_text<'py>(mut slf: PyRefMut<'py, Self>, text: &str) -> PyRefMut<'py, Self> {
        match crate::pack_gsm7(text) {
            Ok((bytes, septets)) => {
                slf.user_data = bytes;
                slf.user_data_length = Some(septets as u8);
            }
            Err(e) => slf.err = Some(e),
        }
        slf
    }
    /// UTF-16BE encode `text` as UCS-2 and set the user data + byte TP-UDL. Pair
    /// with `.dcs(0x08)`.
    fn ucs2_text<'py>(mut slf: PyRefMut<'py, Self>, text: &str) -> PyRefMut<'py, Self> {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        slf.user_data_length = Some(bytes.len() as u8);
        slf.user_data = bytes;
        slf
    }
    fn build(&self) -> PyResult<SmsDeliver> {
        if let Some(e) = &self.err {
            return Err(e.clone().into());
        }
        let scts = self.scts.clone().unwrap_or_else(now_scts);
        let tp_user_data_length = self.user_data_length.unwrap_or(self.user_data.len() as u8);
        Ok(SmsDeliver {
            inner: crate::SmsDeliver {
                tp_rp: self.tp_rp,
                tp_udhi: self.tp_udhi,
                tp_sri: self.tp_sri,
                tp_lp: self.tp_lp,
                tp_mms: self.tp_mms,
                tp_mti: 0, // SMS-DELIVER
                tp_originating_address: self.oa.clone(),
                tp_pid: self.tp_pid,
                tp_dcs: self.tp_dcs,
                tp_service_centre_timestamp: scts,
                tp_user_data_length,
                tp_user_data: self.user_data.clone(),
            },
        })
    }
}

/// Builder for [`RpDataNetworkToMs`]. See [`RpDataNetworkToMs::builder`].
#[pyclass(
    module = "tpdu",
    name = "RpDataNetworkToMsBuilder",
    skip_from_py_object
)]
pub struct RpDataNetworkToMsBuilder {
    sms_deliver: crate::SmsDeliver,
    rp_message_type: u8,
    rp_message_reference: u8,
    rp_originator_address: Option<crate::SMSAddress>,
    rp_destination_address: Option<crate::SMSAddress>,
}

#[pymethods]
impl RpDataNetworkToMsBuilder {
    fn message_type(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.rp_message_type = v;
        slf
    }
    fn message_reference(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.rp_message_reference = v;
        slf
    }
    fn originator_address(mut slf: PyRefMut<'_, Self>, v: Address) -> PyRefMut<'_, Self> {
        slf.rp_originator_address = Some(v.inner);
        slf
    }
    fn destination_address(mut slf: PyRefMut<'_, Self>, v: Address) -> PyRefMut<'_, Self> {
        slf.rp_destination_address = Some(v.inner);
        slf
    }
    fn sms_deliver(mut slf: PyRefMut<'_, Self>, v: SmsDeliver) -> PyRefMut<'_, Self> {
        slf.sms_deliver = v.inner;
        slf
    }
    fn build(&self) -> RpDataNetworkToMs {
        RpDataNetworkToMs {
            inner: crate::RpDataNetworkToMs {
                rp_message_type: self.rp_message_type,
                rp_message_reference: self.rp_message_reference,
                rp_originator_address: self.rp_originator_address.clone(),
                rp_destination_address: self.rp_destination_address.clone(),
                sms_deliver: self.sms_deliver.clone(),
            },
        }
    }
}

/// Builder for [`SmsSubmitReport`]. See [`SmsSubmitReport::builder`].
#[pyclass(module = "tpdu", name = "SmsSubmitReportBuilder", skip_from_py_object)]
pub struct SmsSubmitReportBuilder {
    tp_udhi: bool,
    tp_parameter_indicator: u8,
    scts: Option<String>,
}

#[pymethods]
impl SmsSubmitReportBuilder {
    fn udhi(mut slf: PyRefMut<'_, Self>, v: bool) -> PyRefMut<'_, Self> {
        slf.tp_udhi = v;
        slf
    }
    fn parameter_indicator(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.tp_parameter_indicator = v;
        slf
    }
    fn scts(mut slf: PyRefMut<'_, Self>, v: String) -> PyRefMut<'_, Self> {
        slf.scts = Some(v);
        slf
    }
    fn build(&self) -> SmsSubmitReport {
        SmsSubmitReport {
            inner: crate::SmsSubmitReport {
                tp_udhi: self.tp_udhi as u8,
                tp_parameter_indicator: self.tp_parameter_indicator,
                tp_service_centre_timestamp: self.scts.clone().unwrap_or_else(now_scts),
            },
        }
    }
}

/// Builder for [`RpAckNetworkToMs`]. See [`RpAckNetworkToMs::builder`].
#[pyclass(module = "tpdu", name = "RpAckNetworkToMsBuilder", skip_from_py_object)]
pub struct RpAckNetworkToMsBuilder {
    sms_submit_report: crate::SmsSubmitReport,
    rp_message_reference: u8,
}

#[pymethods]
impl RpAckNetworkToMsBuilder {
    fn message_reference(mut slf: PyRefMut<'_, Self>, v: u8) -> PyRefMut<'_, Self> {
        slf.rp_message_reference = v;
        slf
    }
    fn sms_submit_report(mut slf: PyRefMut<'_, Self>, v: SmsSubmitReport) -> PyRefMut<'_, Self> {
        slf.sms_submit_report = v.inner;
        slf
    }
    fn build(&self) -> PyResult<RpAckNetworkToMs> {
        // A bad SCTS surfaces here (via the SMS-SUBMIT-REPORT encode) rather
        // than at the RP-ACK's own encode().
        let ie_len = self.sms_submit_report.encode()?.len();
        Ok(RpAckNetworkToMs {
            inner: crate::RpAck {
                rp_message_type: 0x03, // RP-ACK n→ms (TS 24.011 §8.2.2)
                rp_message_reference: self.rp_message_reference,
                rp_user_data_element_id: 0x41, // RP-User-Data IEI (§8.2.5.3)
                rp_user_data_element_length: ie_len as u8,
                sms_submit_report: self.sms_submit_report.clone(),
            },
        })
    }
}

// ── Module-level helpers ────────────────────────────────────────────────

/// Parse an MS→Network RP-DATA body — the body of a UE-originated SIP MESSAGE
/// on the Gm interface, or the equivalent RP-DATA inside an SS7 MO-Forward-SM.
#[pyfunction]
fn parse_rp_data(data: &[u8]) -> PyResult<RpData> {
    let parsed = crate::parse_rp_data(data)?;
    Ok(RpData {
        rp_message_type: parsed.rp_message_type,
        rp_message_reference: parsed.rp_message_reference,
        rp_originator_address: parsed.rp_originator_address.map(Address::from_inner),
        rp_destination_address: parsed.rp_destination_address.map(Address::from_inner),
        sms_submit: SmsSubmit {
            inner: parsed.sms_submit,
        },
    })
}

/// Parse a bare SMS-SUBMIT TPDU — useful when the TPDU arrives without the
/// RP-DATA wrapper (e.g. inside an SMPP `submit_sm` `short_message` with
/// `esm_class` set, or an SS7 MO-Forward-SM `sm-RP-UI`).
#[pyfunction]
fn parse_sms_submit(data: &[u8]) -> PyResult<SmsSubmit> {
    let mut cursor = Cursor::new(data);
    let inner = crate::decode_sms_submit_tpdu(&mut cursor)?;
    Ok(SmsSubmit { inner })
}

/// Pull the destination MSISDN (TP-DA) out of an SMS-SUBMIT TPDU. Returns the
/// bare digits (no leading `+`), or raises if the TPDU can't be parsed or has
/// no destination address.
#[pyfunction]
fn destination_from_tpdu(tpdu: &[u8]) -> PyResult<String> {
    let mut cursor = Cursor::new(tpdu);
    let parsed = crate::decode_sms_submit_tpdu(&mut cursor)?;
    parsed
        .tp_destination_address
        .map(|a| a.address)
        .ok_or_else(|| PyValueError::new_err("SMS-SUBMIT has no TP-DA"))
}

/// Build an SMS-DELIVER TPDU from SMPP `deliver_sm`-shaped fields — used by a
/// routing layer to wrap an inbound `deliver_sm` for MT-Forward-SM via MAP / SGd.
///
/// Defaults to UTC-now SCTS unless overridden. Pass `user_data_length` (TP-UDL)
/// explicitly when `data_coding=0` so it counts septets, not packed bytes.
#[pyfunction]
#[pyo3(signature = (
    source_addr, source_addr_ton = 1, source_addr_npi = 1,
    short_message = vec![],
    *,
    protocol_id = 0,
    data_coding = 0,
    udhi = false,
    scts = None,
    user_data_length = None,
))]
#[allow(clippy::too_many_arguments)]
fn build_sms_deliver_tpdu(
    source_addr: String,
    source_addr_ton: u8,
    source_addr_npi: u8,
    short_message: Vec<u8>,
    protocol_id: u8,
    data_coding: u8,
    udhi: bool,
    scts: Option<String>,
    user_data_length: Option<u8>,
) -> PyResult<Vec<u8>> {
    let tp_user_data_length = user_data_length.unwrap_or(short_message.len() as u8);
    let deliver = crate::SmsDeliver {
        tp_rp: false,
        tp_udhi: udhi,
        tp_sri: false,
        tp_lp: false,
        tp_mms: true,
        tp_mti: 0,
        tp_originating_address: crate::SMSAddress {
            ton: source_addr_ton,
            npi: source_addr_npi,
            address: source_addr,
        },
        tp_pid: protocol_id,
        tp_dcs: data_coding,
        tp_service_centre_timestamp: scts.unwrap_or_else(now_scts),
        tp_user_data_length,
        tp_user_data: short_message,
    };
    Ok(deliver.encode()?)
}

/// Pack a Unicode string into GSM 7-bit septets per TS 23.038 §6.2.1.
///
/// Returns `(packed_bytes, septet_count)` where `septet_count` is the value to
/// use for TP-UDL on a DCS=0 SMS-DELIVER (extension chars `^{}\[~]|€` and
/// form-feed count as 2 septets each).
#[pyfunction]
fn pack_gsm7<'py>(py: Python<'py>, text: &str) -> PyResult<(Bound<'py, PyBytes>, usize)> {
    let (bytes, septets) = crate::pack_gsm7(text)?;
    Ok((PyBytes::new(py, &bytes), septets))
}

/// Unpack `septets` septets from a packed GSM 7-bit buffer.
///
/// Drops the trailing `@` produced by carrier padding when the decoded char
/// count exceeds `septets` (TS 23.038 §6.2.1 disambiguates with TP-UDL).
#[pyfunction]
fn unpack_gsm7(data: &[u8], septets: usize) -> PyResult<String> {
    Ok(crate::unpack_gsm7(data, septets)?)
}

// ── Internals ───────────────────────────────────────────────────────────

/// 14-digit BCD-pair-swapped UTC timestamp (yymmddHHMMSS + tz placeholder).
/// `SmsDeliver::encode` reads the trailing pair as the timezone byte to match
/// TS 23.040 §9.2.3.11.
fn now_scts() -> String {
    use chrono::{Datelike, Timelike, Utc};
    let now = Utc::now();
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}00",
        now.year() % 100,
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

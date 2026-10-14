//! Virtual HID device: IOHIDUserDevice <-> ctaphid <-> ctap2 (Secure Enclave).
//!
//! All protocol state lives on one serial dispatch queue. Creating the
//! IOHIDUserDevice object requires the `com.apple.developer.hid.virtual.device`
//! entitlement. Activation (which publishes the kernel HID device) happens only
//! inside [`run`], which the binary gates behind `--run`.

use crate::block::{BlockLiteral, HeapBlock};
use crate::cf::{cf_data, cf_dict, cf_str, cf_u32, Cf};
use crate::ffi::*;
use crate::trace::{describe_report, describe_result, getinfo_summary, Dir};
use crate::{properties, DeviceIdentity, PropValue, DEFAULT_IDENTITY, REPORT_SIZE};
use backend_se::{storage_key, AccessPolicy, SeBackend, StorageMode, SystemEntropy};
use ctap2::{
    AttestationFormat, Authenticator, AuthenticatorConfig, Bytes, Presence, PresenceError,
    PresenceKind, PresenceRequest, UserPresence, UvPolicy,
};
use ctaphid::{keepalive_packet, Action, Command, Config, KeepaliveStatus, Packet, Server};
use se_fido_store::{default_dir, FileStore};
use std::cell::Cell;
use std::ffi::{c_void, CString};
use std::path::PathBuf;
use std::ptr::null;
use std::time::Instant;

const KEEPALIVE_MS: u64 = 100;

/// One log line to stderr (launchd sends it to target/se-run.log).
fn log(line: &str) {
    eprintln!("se-fido: {line}");
}

fn report_type_name(t: IOHIDReportType) -> &'static str {
    match t {
        0 => "input",
        1 => "output",
        2 => "feature",
        _ => "unknown",
    }
}

type Auth = Authenticator<SeBackend, FileStore<SystemEntropy>, DevicePresence>;

/// Runtime options for the virtual device (CLI flags / env).
#[derive(Debug, Clone)]
pub struct DeviceOptions {
    /// Default UV policy for new credentials.
    pub uv_policy: UvPolicy,
    /// Attestation format (affects whether MakeCredential will SE-prompt).
    pub attestation: AttestationFormat,
    /// DANGEROUS: skip LA/SE prompts and approve presence. Opt-in only.
    pub auto_approve: bool,
}

impl Default for DeviceOptions {
    fn default() -> Self {
        DeviceOptions {
            uv_policy: UvPolicy::Presence,
            attestation: AttestationFormat::PackedSelf,
            auto_approve: false,
        }
    }
}

/// Device-side presence: LocalAuthentication for UP when the SE will not
/// prompt; otherwise SE access control on the next sign enforces UV/UP.
struct DevicePresence {
    opts: DeviceOptions,
}

impl DevicePresence {
    fn reason(req: &PresenceRequest) -> String {
        let rp: String = req
            .rp_id
            .as_ref()
            .map(|t| t.as_str())
            .unwrap_or("this site")
            .chars()
            .filter(|ch| !ch.is_control() && !matches!(ch, '\u{2028}' | '\u{2029}'))
            .take(128)
            .collect();
        let rp = if rp.trim().is_empty() {
            "this site"
        } else {
            rp.as_str()
        };
        match req.kind {
            PresenceKind::MakeCredential => format!("Create a passkey for {rp}"),
            PresenceKind::GetAssertion => format!("Sign in to {rp}"),
            PresenceKind::Excluded => format!("Confirm a passkey already exists for {rp}"),
            PresenceKind::Reset => "Reset se-fido and delete all passkeys".into(),
            PresenceKind::Selection => format!("Select se-fido for {rp}"),
            PresenceKind::Probe => format!("Use se-fido with {rp}"),
        }
    }

    /// True when the next private-key use will trigger an SE ACL prompt.
    fn se_will_prompt(&self, req: &PresenceRequest) -> bool {
        match req.kind {
            PresenceKind::GetAssertion => {
                req.key_uv_policy.is_some_and(|policy| policy.supports_uv())
            }
            PresenceKind::MakeCredential => {
                self.opts.uv_policy.supports_uv()
                    && !matches!(self.opts.attestation, AttestationFormat::None)
            }
            _ => false,
        }
    }
}

impl UserPresence for DevicePresence {
    fn request(&mut self, req: &PresenceRequest) -> Result<Presence, PresenceError> {
        let policy = req.key_uv_policy.unwrap_or(self.opts.uv_policy);
        if self.opts.auto_approve {
            eprintln!(
                "se-fido: WARNING --auto-approve is ON; accepting {:?} without LA/Touch ID",
                req.kind
            );
            return Ok(Presence {
                user_verified: req.require_uv && policy.supports_uv(),
            });
        }
        if self.se_will_prompt(req) {
            // SE key ACL prompts on SecKeyCreateSignature; claim UV intent.
            // Cancel/deny from the SE maps to BackendError::Cancelled.
            return Ok(Presence {
                user_verified: policy.supports_uv(),
            });
        }
        // Explicit UP: LA with passcode allowed (UvPolicy::None non-biometric path).
        let biometry_only = (req.require_uv || matches!(policy, UvPolicy::Biometry))
            && matches!(
                req.kind,
                PresenceKind::MakeCredential | PresenceKind::GetAssertion
            );
        crate::la::evaluate(
            &Self::reason(req),
            biometry_only,
            std::time::Duration::from_secs(60),
        )
        .map(|p| Presence {
            // Credential policy is checked by CTAP before setting its UV bit.
            user_verified: p.user_verified,
        })
    }
}

struct Pending {
    cid: u32,
    cmd: Command,
    payload: Bytes,
}

struct Inner {
    server: Server,
    auth: Auth,
    device: IOHIDUserDeviceRef,
    queue: DispatchQueue,
    pending: Option<Pending>,
    assertion_cid: Option<u32>,
    timer: DispatchSource,
    started: Instant,
    /// Keepalives repeat every 100 ms while a request waits; log only the
    /// first one per request.
    keepalive_logged: Cell<bool>,
}

impl Inner {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn send_packets(&self, packets: &[Packet]) {
        for p in packets {
            self.log_out(p);
            let kr = unsafe {
                IOHIDUserDeviceHandleReportWithTimeStamp(
                    self.device,
                    mach_absolute_time(),
                    p.as_ptr(),
                    REPORT_SIZE as CFIndex,
                )
            };
            if kr != kIOReturnSuccess {
                eprintln!("se-fido: HandleReport failed: {kr:#x}");
            }
        }
    }

    fn log_out(&self, p: &Packet) {
        if p[4] & ctaphid::TYPE_INIT == 0 {
            return;
        }
        if p[4] & !ctaphid::TYPE_INIT == Command::Keepalive as u8 {
            if self.keepalive_logged.get() {
                return;
            }
            self.keepalive_logged.set(true);
        }
        log(&describe_report(Dir::Out, p));
    }

    fn send_keepalive(&self, cid: u32, status: KeepaliveStatus) {
        self.send_packets(&[keepalive_packet(cid, status)]);
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::None => {}
            Action::Send(p) | Action::Wink(p) => self.send_packets(&p),
            Action::Process { cid, cmd, payload } => {
                // Defer application work so Cancel and the keepalive timer can
                // run on this queue before we block on Secure Enclave ops.
                self.keepalive_logged.set(false);
                self.pending = Some(Pending {
                    cid,
                    cmd,
                    payload: Bytes::new(payload),
                });
                self.send_keepalive(cid, KeepaliveStatus::UpNeeded);
                unsafe {
                    dispatch_async_f(
                        self.queue,
                        self as *mut Inner as *mut c_void,
                        Some(run_pending_f),
                    );
                }
            }
            Action::Cancel { cid } => {
                log(&format!("cancel cid={cid:08x}"));
                if self.pending.as_ref().is_some_and(|p| p.cid == cid) {
                    self.pending = None;
                }
                if self.assertion_cid == Some(cid) {
                    self.assertion_cid = None;
                }
                self.server.abort(cid);
                if let Ok(p) = self.server.response(cid, Command::Cbor, &[0x2d]) {
                    self.send_packets(&p);
                }
            }
        }
    }

    fn run_pending(&mut self) {
        let Some(Pending { cid, cmd, payload }) = self.pending.take() else {
            return;
        };
        self.send_keepalive(cid, KeepaliveStatus::UpNeeded);
        let is_next =
            cmd == Command::Cbor && payload.first() == Some(&ctap2::command::GET_NEXT_ASSERTION);
        let resp = if is_next && self.assertion_cid != Some(cid) {
            vec![ctap2::Status::NotAllowed.code()]
        } else {
            if !is_next {
                self.assertion_cid = None;
            }
            let resp = match cmd {
                Command::Msg => ctap2::u2f::process(payload.as_slice()),
                _ => self.auth.process(&payload, self.now_ms()),
            };
            if cmd == Command::Cbor
                && payload.first() == Some(&ctap2::command::GET_ASSERTION)
                && resp.first() == Some(&ctap2::Status::Ok.code())
            {
                self.assertion_cid = Some(cid);
            } else if is_next && resp.first() != Some(&ctap2::Status::Ok.code()) {
                self.assertion_cid = None;
            }
            resp
        };
        log(&describe_result(cid, cmd, payload.as_slice(), &resp));
        if cmd == Command::Cbor && payload.first() == Some(&ctap2::command::GET_INFO) {
            log(&getinfo_summary(&resp));
        }
        match self.server.response(cid, cmd, &resp) {
            Ok(p) => self.send_packets(&p),
            Err(e) => eprintln!("se-fido: fragment response: {e}"),
        }
    }

    fn on_set_report(
        &mut self,
        report_type: IOHIDReportType,
        report_id: u32,
        report: &[u8],
    ) -> IOReturn {
        if report_type != kIOHIDReportTypeOutput {
            log(&format!(
                "set-report rejected: type={} id={report_id} len={}",
                report_type_name(report_type),
                report.len()
            ));
            return kIOReturnUnsupported;
        }
        if report.len() != REPORT_SIZE {
            log(&format!(
                "set-report rejected: type=output id={report_id} len={} (expected {REPORT_SIZE})",
                report.len()
            ));
            return kIOReturnBadArgument;
        }
        log(&format!(
            "set-report id={report_id} {}",
            describe_report(Dir::In, report)
        ));
        let mut packet = [0u8; REPORT_SIZE];
        packet.copy_from_slice(report);
        let now = self.now_ms();
        let timed = self.server.poll(now);
        self.send_packets(&timed);
        let action = self.server.handle_report(&packet, now);
        self.apply(action);
        kIOReturnSuccess
    }

    fn on_timer(&mut self) {
        let now = self.now_ms();
        let timed = self.server.poll(now);
        self.send_packets(&timed);
        if let Some(p) = &self.pending {
            self.send_keepalive(p.cid, KeepaliveStatus::UpNeeded);
        }
    }
}

unsafe extern "C" fn run_pending_f(ctx: *mut c_void) {
    (*(ctx as *mut Inner)).run_pending();
}

unsafe extern "C" fn timer_f(ctx: *mut c_void) {
    // Context set with dispatch_set_context on the timer source.
    if ctx.is_null() {
        return;
    }
    (*(ctx as *mut Inner)).on_timer();
}

/// SetReportBlock: IOReturn (^)(IOHIDReportType, uint32_t, const uint8_t *, CFIndex)
unsafe extern "C" fn set_report_invoke(
    block: *mut c_void,
    report_type: IOHIDReportType,
    report_id: u32,
    report: *const u8,
    report_length: CFIndex,
) -> IOReturn {
    if report.is_null() || report_length <= 0 {
        log(&format!(
            "set-report rejected: type={} id={report_id} len={report_length} (null or empty)",
            report_type_name(report_type)
        ));
        return kIOReturnBadArgument;
    }
    let literal = block as *mut BlockLiteral<*mut c_void>;
    let inner = (*literal).captured as *mut Inner;
    if inner.is_null() {
        return kIOReturnError;
    }
    let slice = std::slice::from_raw_parts(report, report_length as usize);
    (*inner).on_set_report(report_type, report_id, slice)
}

/// GetReportBlock: unused by CTAPHID interrupt OUT.
unsafe extern "C" fn get_report_invoke(
    _block: *mut c_void,
    report_type: IOHIDReportType,
    report_id: u32,
    _report: *mut u8,
    _report_length: *mut CFIndex,
) -> IOReturn {
    log(&format!(
        "get-report type={} id={report_id} (unsupported)",
        report_type_name(report_type)
    ));
    kIOReturnUnsupported
}

/// dispatch_block_t cancel handler.
unsafe extern "C" fn cancel_invoke(block: *mut c_void) {
    let literal = block as *mut BlockLiteral<*mut c_void>;
    let inner = (*literal).captured as *mut Inner;
    if inner.is_null() {
        return;
    }
    log("cancel handler fired (device cancelled by the system)");
    // Release the IOHIDUserDevice and free Inner after cancel completes.
    let inner = Box::from_raw(inner);
    if !inner.device.is_null() {
        CFRelease(inner.device as CFTypeRef);
    }
    if !inner.timer.is_null() {
        dispatch_source_cancel(inner.timer);
        dispatch_release(inner.timer as DispatchObject);
    }
    if !inner.queue.is_null() {
        dispatch_release(inner.queue as DispatchObject);
    }
    eprintln!("se-fido: device cancelled and released");
}

fn build_properties_dict(id: &DeviceIdentity) -> Cf {
    let mut owned: Vec<Cf> = Vec::new();
    let mut pairs: Vec<(CFTypeRef, CFTypeRef)> = Vec::new();
    for (k, v) in properties(id) {
        let key = cf_str(k);
        let val = match v {
            PropValue::Number(n) => cf_u32(n),
            PropValue::Text(t) => cf_str(t),
            PropValue::Data(d) => cf_data(d),
        };
        pairs.push((key.ptr(), val.ptr()));
        owned.push(key);
        owned.push(val);
    }
    let dict = cf_dict(&pairs);
    drop(owned);
    dict
}

fn open_authenticator(dir: PathBuf, opts: &DeviceOptions) -> Result<Auth, String> {
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = storage_key(&dir).map_err(|e| e.to_string())?;
    let store =
        FileStore::open(dir.join("store"), &key, SystemEntropy).map_err(|e| e.to_string())?;
    // Per-key ACL is chosen in create_key from UvPolicy; backend default unused.
    let backend = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
    let cfg = AuthenticatorConfig {
        default_uv_policy: opts.uv_policy,
        attestation: opts.attestation,
        ..AuthenticatorConfig::default()
    };
    Ok(Authenticator::new(
        backend,
        store,
        DevicePresence { opts: opts.clone() },
        cfg,
    ))
}

/// Data directory: `$SE_FIDO_DIR` or the store default.
pub fn data_dir() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("SE_FIDO_DIR") {
        return Ok(PathBuf::from(p));
    }
    default_dir().ok_or_else(|| "HOME unset and SE_FIDO_DIR not set".into())
}

/// Human-readable plan of what `--run` would do. Does not create a device.
pub fn dry_run_text(opts: &DeviceOptions) -> String {
    let id = &DEFAULT_IDENTITY;
    let dir = data_dir().unwrap_or_else(|e| PathBuf::from(format!("<error: {e}>")));
    let auto = if opts.auto_approve {
        "ON (DANGEROUS: no LA/Touch ID)"
    } else {
        "off (LA for UP when SE will not prompt; SE ACL on sign for presence/biometry)"
    };
    format!(
        "se-fido-device dry run (pass --run to create and activate the virtual HID device)\n\
         \n\
         identity:\n\
           Product={}\n\
           Manufacturer={}\n\
           SerialNumber={}\n\
           VendorID=0x{:04x} (placeholder, not a USB-IF assignment)\n\
           ProductID=0x{:04x} (placeholder)\n\
           Transport={}\n\
           PrimaryUsagePage=0x{:04x}\n\
           PrimaryUsage=0x{:04x}\n\
           ReportDescriptor={} bytes\n\
         \n\
         data dir: {}\n\
         entitlement: com.apple.developer.hid.virtual.device\n\
         options: IOHIDUserDeviceOptionsCreateOnActivate\n\
         uv_policy: {} (default for new credentials)\n\
         attestation: {:?}\n\
         auto_approve: {}\n\
         \n\
         See DEPLOY.md for signing and SIP/AMFI steps before --run.\n\
         After deploy, probe Touch ID SE keys with: target/debug/se-probe --touchid\n",
        id.product,
        id.manufacturer,
        id.serial,
        id.vendor_id,
        id.product_id,
        id.transport,
        crate::FIDO_USAGE_PAGE,
        crate::FIDO_USAGE_CTAPHID,
        crate::REPORT_DESCRIPTOR.len(),
        dir.display(),
        opts.uv_policy.as_str(),
        opts.attestation,
        auto,
    )
}

/// Create, activate and run the virtual HID device. Blocks in `dispatch_main`.
///
/// Requires the `com.apple.developer.hid.virtual.device` entitlement (or
/// SIP/AMFI relaxed so an ad-hoc signed binary carrying that entitlement is
/// accepted). See DEPLOY.md.
///
/// # Safety
/// Calls into IOKit and libdispatch. Only invoke from a process that holds the
/// entitlement and that the user has explicitly started with `--run`.
pub unsafe fn run(opts: &DeviceOptions) -> Result<(), String> {
    if opts.auto_approve {
        eprintln!("se-fido: WARNING starting with --auto-approve; presence is not verified");
    }
    let dir = data_dir()?;
    let mut auth = open_authenticator(dir, opts)?;
    let id = &DEFAULT_IDENTITY;
    log(&format!(
        "starting: VendorID=0x{:04x} ProductID=0x{:04x} Product=\"{}\" Transport={} \
         usage page 0x{:04x} uv_policy={} attestation={:?}",
        id.vendor_id,
        id.product_id,
        id.product,
        id.transport,
        crate::FIDO_USAGE_PAGE,
        opts.uv_policy.as_str(),
        opts.attestation,
    ));
    let info = auth.process(&Bytes::new(vec![ctap2::command::GET_INFO].into()), 0);
    log(&format!("advertised {}", getinfo_summary(&info)));
    let dict = build_properties_dict(&DEFAULT_IDENTITY);

    let label = CString::new("com.se-fido.device").unwrap();
    let queue = dispatch_queue_create(label.as_ptr(), null());
    if queue.is_null() {
        return Err("dispatch_queue_create failed".into());
    }

    let device = IOHIDUserDeviceCreateWithProperties(
        null(),
        dict.as_dict(),
        IOHIDUserDeviceOptionsCreateOnActivate,
    );
    if device.is_null() {
        dispatch_release(queue as DispatchObject);
        return Err("IOHIDUserDeviceCreateWithProperties returned null \
             (missing entitlement com.apple.developer.hid.virtual.device?)"
            .into());
    }

    let timer = dispatch_source_create(dispatch_source_type_timer(), 0, 0, queue);
    if timer.is_null() {
        CFRelease(device as CFTypeRef);
        dispatch_release(queue as DispatchObject);
        return Err("dispatch_source_create(timer) failed".into());
    }

    let inner = Box::new(Inner {
        server: Server::new(Config::default()),
        auth,
        device,
        queue,
        pending: None,
        assertion_cid: None,
        timer,
        started: Instant::now(),
        keepalive_logged: Cell::new(false),
    });
    let inner_ptr = Box::into_raw(inner);

    let set_block =
        HeapBlock::copy_with_context(set_report_invoke as *const _, inner_ptr as *mut c_void);
    let get_block =
        HeapBlock::copy_with_context(get_report_invoke as *const _, inner_ptr as *mut c_void);
    let cancel_block =
        HeapBlock::copy_with_context(cancel_invoke as *const _, inner_ptr as *mut c_void);

    IOHIDUserDeviceSetDispatchQueue(device, queue);
    IOHIDUserDeviceRegisterSetReportBlock(device, set_block.as_ptr());
    IOHIDUserDeviceRegisterGetReportBlock(device, get_block.as_ptr());
    IOHIDUserDeviceSetCancelHandler(device, cancel_block.as_ptr());

    // The device retains its own copies of the Blocks. Forget ours so Drop
    // does not release underneath the device; cancel_invoke frees Inner.
    std::mem::forget(set_block);
    std::mem::forget(get_block);
    std::mem::forget(cancel_block);

    dispatch_set_context(timer as DispatchObject, inner_ptr as *mut c_void);
    dispatch_source_set_event_handler_f(timer, Some(timer_f));
    let start = dispatch_time(DISPATCH_TIME_NOW, (KEEPALIVE_MS * NSEC_PER_MSEC) as i64);
    dispatch_source_set_timer(timer, start, KEEPALIVE_MS * NSEC_PER_MSEC, NSEC_PER_MSEC);
    dispatch_resume(timer as DispatchObject);

    IOHIDUserDeviceActivate(device);
    eprintln!(
        "se-fido: virtual HID device activated (usage page 0x{:04x}). \
         Kill the process to tear down; prefer a clean Cancel from the host.",
        crate::FIDO_USAGE_PAGE
    );

    dispatch_main()
}

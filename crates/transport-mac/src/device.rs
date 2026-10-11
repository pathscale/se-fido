//! Virtual HID device: IOHIDUserDevice <-> ctaphid <-> ctap2 (Secure Enclave).
//!
//! All protocol state lives on one serial dispatch queue. Creating the
//! IOHIDUserDevice object requires the `com.apple.developer.hid.virtual.device`
//! entitlement. Activation (which publishes the kernel HID device) happens only
//! inside [`run`], which the binary gates behind `--run`.

use crate::block::{BlockLiteral, HeapBlock};
use crate::cf::{cf_data, cf_dict, cf_str, cf_u32, Cf};
use crate::ffi::*;
use crate::{properties, DeviceIdentity, PropValue, DEFAULT_IDENTITY, REPORT_SIZE};
use backend_se::{storage_key, AccessPolicy, SeBackend, StorageMode, SystemEntropy};
use ctap2::{
    Authenticator, AuthenticatorConfig, Bytes, Presence, PresenceError, PresenceRequest,
    UserPresence,
};
use ctaphid::{keepalive_packet, Action, Command, Config, KeepaliveStatus, Packet, Server};
use se_fido_store::{default_dir, FileStore};
use std::ffi::{c_void, CString};
use std::path::PathBuf;
use std::ptr::null;
use std::time::Instant;

const KEEPALIVE_MS: u64 = 100;

type Auth = Authenticator<SeBackend, FileStore<SystemEntropy>, ImmediatePresence>;

/// Presence that approves immediately. Touch ID is M5. Keepalives are sent by
/// the device while a request is pending on the dispatch queue.
struct ImmediatePresence;

impl UserPresence for ImmediatePresence {
    fn request(&mut self, req: &PresenceRequest) -> Result<Presence, PresenceError> {
        Ok(Presence {
            user_verified: req.require_uv,
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
    timer: DispatchSource,
    started: Instant,
}

impl Inner {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn send_packets(&self, packets: &[Packet]) {
        for p in packets {
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
                if self.pending.as_ref().is_some_and(|p| p.cid == cid) {
                    self.pending = None;
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
        let resp = self.auth.process(&payload, self.now_ms());
        match self.server.response(cid, cmd, &resp) {
            Ok(p) => self.send_packets(&p),
            Err(e) => eprintln!("se-fido: fragment response: {e}"),
        }
    }

    fn on_set_report(&mut self, report_type: IOHIDReportType, report: &[u8]) -> IOReturn {
        if report_type != kIOHIDReportTypeOutput {
            return kIOReturnUnsupported;
        }
        if report.len() != REPORT_SIZE {
            return kIOReturnBadArgument;
        }
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
    _report_id: u32,
    report: *const u8,
    report_length: CFIndex,
) -> IOReturn {
    if report.is_null() || report_length <= 0 {
        return kIOReturnBadArgument;
    }
    let literal = block as *mut BlockLiteral<*mut c_void>;
    let inner = (*literal).captured as *mut Inner;
    if inner.is_null() {
        return kIOReturnError;
    }
    let slice = std::slice::from_raw_parts(report, report_length as usize);
    (*inner).on_set_report(report_type, slice)
}

/// GetReportBlock: unused by CTAPHID interrupt OUT.
unsafe extern "C" fn get_report_invoke(
    _block: *mut c_void,
    _report_type: IOHIDReportType,
    _report_id: u32,
    _report: *mut u8,
    _report_length: *mut CFIndex,
) -> IOReturn {
    kIOReturnUnsupported
}

/// dispatch_block_t cancel handler.
unsafe extern "C" fn cancel_invoke(block: *mut c_void) {
    let literal = block as *mut BlockLiteral<*mut c_void>;
    let inner = (*literal).captured as *mut Inner;
    if inner.is_null() {
        return;
    }
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

fn open_authenticator(dir: PathBuf) -> Result<Auth, String> {
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = storage_key(&dir).map_err(|e| e.to_string())?;
    let store =
        FileStore::open(dir.join("store"), &key, SystemEntropy).map_err(|e| e.to_string())?;
    let backend = SeBackend::new(StorageMode::Blob, AccessPolicy::None);
    let cfg = AuthenticatorConfig {
        builtin_uv: true,
        ..AuthenticatorConfig::default()
    };
    Ok(Authenticator::new(backend, store, ImmediatePresence, cfg))
}

/// Data directory: `$SE_FIDO_DIR` or the store default.
pub fn data_dir() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("SE_FIDO_DIR") {
        return Ok(PathBuf::from(p));
    }
    default_dir().ok_or_else(|| "HOME unset and SE_FIDO_DIR not set".into())
}

/// Human-readable plan of what `--run` would do. Does not create a device.
pub fn dry_run_text() -> String {
    let id = &DEFAULT_IDENTITY;
    let dir = data_dir().unwrap_or_else(|e| PathBuf::from(format!("<error: {e}>")));
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
         presence: auto-approve (Touch ID is M5)\n\
         \n\
         See DEPLOY.md for signing and SIP/AMFI steps before --run.\n",
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
pub unsafe fn run() -> Result<(), String> {
    let dir = data_dir()?;
    let auth = open_authenticator(dir)?;
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
        timer,
        started: Instant::now(),
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

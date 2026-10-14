//! LocalAuthentication via hand-written Objective-C runtime calls.
//!
//! No `-sys` / objc2 crates. Used for explicit user presence when the Secure
//! Enclave will not prompt (UvPolicy::None, Selection/Reset/Probe, or
//! MakeCredential with attestation "none").
//!
//! `evaluatePolicy:localizedReason:reply:` is asynchronous; we bridge with a
//! libdispatch semaphore so [`UserPresence::request`] can stay synchronous.
//! That wait is only for this OS API boundary, not for protocol shared state.

use crate::block::{BlockLiteral, HeapBlock};
use crate::ffi::BlockPtr;
use ctap2::{Presence, PresenceError};
use std::ffi::{c_char, c_void, CStr};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

type Id = *mut c_void;
type Sel = *const c_void;

/// LAPolicyDeviceOwnerAuthenticationWithBiometrics (LAContext.h).
const LA_POLICY_BIOMETRICS: isize = 1;
/// LAPolicyDeviceOwnerAuthentication: biometry or device password.
const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: isize = 2;

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
}

#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}

extern "C" {
    fn dispatch_semaphore_create(value: isize) -> *mut c_void;
    fn dispatch_semaphore_signal(dsema: *mut c_void) -> isize;
    fn dispatch_semaphore_wait(dsema: *mut c_void, timeout: u64) -> isize;
    fn dispatch_release(object: *mut c_void);
}

struct ReplyState {
    sema: *mut c_void,
    ok: AtomicBool,
    code: AtomicI64,
    completed: AtomicBool,
}

// The semaphore supports concurrent signal/wait calls. All reply data is atomic.
unsafe impl Send for ReplyState {}
unsafe impl Sync for ReplyState {}

impl Drop for ReplyState {
    fn drop(&mut self) {
        unsafe {
            crate::ffi::dispatch_release(self.sema);
        }
    }
}

fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

fn send0(obj: Id, s: Sel) -> Id {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel) -> Id = std::mem::transmute::<
            *const (),
            unsafe extern "C" fn(Id, Sel) -> Id,
        >(objc_msgSend as *const ());
        f(obj, s)
    }
}

fn send_i64(obj: Id, s: Sel) -> i64 {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel) -> i64 = std::mem::transmute::<
            *const (),
            unsafe extern "C" fn(Id, Sel) -> i64,
        >(objc_msgSend as *const ());
        f(obj, s)
    }
}

fn send_cstr(obj: Id, s: Sel, p: *const c_char) -> Id {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
            std::mem::transmute::<*const (), unsafe extern "C" fn(Id, Sel, *const c_char) -> Id>(
                objc_msgSend as *const (),
            );
        f(obj, s, p)
    }
}

fn send_policy_reply(obj: Id, s: Sel, policy: isize, reason: Id, reply: BlockPtr) {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel, isize, Id, BlockPtr) =
            std::mem::transmute::<*const (), unsafe extern "C" fn(Id, Sel, isize, Id, BlockPtr)>(
                objc_msgSend as *const (),
            );
        f(obj, s, policy, reason, reply);
    }
}

/// reply block: void (^)(BOOL success, NSError *error)
unsafe extern "C" fn reply_invoke(block: *mut c_void, success: bool, error: Id) {
    let lit = block as *mut BlockLiteral<*mut c_void>;
    let raw = (*lit).captured as *const ReplyState;
    if raw.is_null() {
        return;
    }
    // LA delivers one reply. Consume the reference reserved for that invocation.
    let state = Arc::from_raw(raw);
    let code = if !success && !error.is_null() {
        send_i64(error, sel(c"code"))
    } else {
        0
    };
    state.code.store(code, Ordering::Relaxed);
    state.ok.store(success, Ordering::Relaxed);
    state.completed.store(true, Ordering::Release);
    dispatch_semaphore_signal(state.sema);
}

fn msg_alloc_init(class: &CStr) -> Id {
    unsafe {
        let cls = objc_getClass(class.as_ptr());
        if cls.is_null() {
            return null_mut();
        }
        let obj = send0(cls, sel(c"alloc"));
        if obj.is_null() {
            return null_mut();
        }
        send0(obj, sel(c"init"))
    }
}

fn nsstring(s: &str) -> Id {
    let c = std::ffi::CString::new(s).unwrap_or_default();
    unsafe {
        let cls = objc_getClass(c"NSString".as_ptr());
        send_cstr(cls, sel(c"stringWithUTF8String:"), c.as_ptr())
    }
}

fn send_void(obj: Id, s: Sel) {
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel) = std::mem::transmute::<
            *const (),
            unsafe extern "C" fn(Id, Sel),
        >(objc_msgSend as *const ());
        f(obj, s);
    }
}

fn release(obj: Id) {
    if obj.is_null() {
        return;
    }
    unsafe {
        let f: unsafe extern "C" fn(Id, Sel) = std::mem::transmute::<
            *const (),
            unsafe extern "C" fn(Id, Sel),
        >(objc_msgSend as *const ());
        f(obj, sel(c"release"));
    }
}

/// Run LocalAuthentication and map the result to presence errors.
///
/// `biometry_only` selects LAPolicyDeviceOwnerAuthenticationWithBiometrics;
/// otherwise DeviceOwnerAuthentication (passcode allowed), which is the
/// non-biometric UP signal for [`ctap2::UvPolicy::None`].
pub fn evaluate(
    reason: &str,
    biometry_only: bool,
    timeout: Duration,
) -> Result<Presence, PresenceError> {
    unsafe {
        let ctx = msg_alloc_init(c"LAContext");
        if ctx.is_null() {
            return Err(PresenceError::UvFailed);
        }
        let policy = if biometry_only {
            LA_POLICY_BIOMETRICS
        } else {
            LA_POLICY_DEVICE_OWNER_AUTHENTICATION
        };
        let reason_ns = nsstring(reason);
        let sema = dispatch_semaphore_create(0);
        if sema.is_null() {
            release(ctx);
            return Err(PresenceError::UvFailed);
        }
        crate::ffi::dispatch_retain(sema);
        let state = Arc::new(ReplyState {
            sema,
            ok: AtomicBool::new(false),
            code: AtomicI64::new(0),
            completed: AtomicBool::new(false),
        });
        let reply_state = Arc::into_raw(Arc::clone(&state));
        let block =
            HeapBlock::copy_with_context(reply_invoke as *const _, reply_state as *mut c_void);

        send_policy_reply(
            ctx,
            sel(c"evaluatePolicy:localizedReason:reply:"),
            policy,
            reason_ns,
            block.as_ptr(),
        );

        let ns = timeout.as_nanos().min(i64::MAX as u128) as i64;
        let when = crate::ffi::dispatch_time(crate::ffi::DISPATCH_TIME_NOW, ns);
        let waited = dispatch_semaphore_wait(sema, when);
        if waited != 0 {
            send_void(ctx, sel(c"invalidate"));
        }
        drop(block);
        dispatch_release(sema);
        release(ctx);

        if waited != 0 {
            return Err(PresenceError::Timeout);
        }
        if !state.completed.load(Ordering::Acquire) {
            return Err(PresenceError::UvFailed);
        }
        if state.ok.load(Ordering::Relaxed) {
            return Ok(Presence {
                user_verified: biometry_only,
            });
        }
        let code = state.code.load(Ordering::Relaxed);
        // LAErrorUserCancel = -2, LAErrorAuthenticationFailed = -1, LAErrorUserFallback = -3
        Err(match code {
            -2 => PresenceError::Cancelled,
            -3 | -1 => PresenceError::Denied,
            _ => PresenceError::UvFailed,
        })
    }
}

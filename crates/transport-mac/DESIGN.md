# transport-mac design

Goal: browsers on this Mac see se-fido as a USB security key. They find
keys through IOHIDManager by HID usage page 0xF1D0, usage 0x01, so a virtual
HID device with the descriptor in `src/lib.rs` is enough; no USB stack is
involved.

Constraint: Rust only. No C, C++, Objective-C or Swift source anywhere. All
Apple APIs are reached through hand-written `extern "C"` declarations.

Status: design only. `src/ffi.rs` declares the API; nothing creates a device.

## Primary route: IOHIDUserDevice from a user-space process

API (IOKit/hid/IOHIDUserDevice.h, macOS 10.15+):

1. Build a CFDictionary from `properties()` (ReportDescriptor as CFData,
   numbers as CFNumber, strings as CFString). backend-se already has the
   CoreFoundation declarations needed.
2. `IOHIDUserDeviceCreateWithProperties(NULL, props, 0)`.
3. `IOHIDUserDeviceSetDispatchQueue(dev, q)` with one serial queue from
   `dispatch_queue_create`.
4. `IOHIDUserDeviceRegisterSetReportBlock(dev, block)`: output reports from
   the host arrive here, 64 bytes each.
5. `IOHIDUserDeviceActivate(dev)`.
6. Device to host: `IOHIDUserDeviceHandleReportWithTimeStamp(dev,
   mach_absolute_time(), report, 64)`.
7. Shutdown: `IOHIDUserDeviceCancel`, then release in the cancel handler.

Blocks: the report and cancel callbacks are Objective-C blocks. A block is
a C struct (`isa`, `flags`, `reserved`, `invoke`, `descriptor`). We define
it as a `#[repr(C)]` Rust struct with `isa = &_NSConcreteGlobalBlock`, a
static descriptor, and an `extern "C" fn invoke(block, type, id, ptr, len)`.
Global blocks capture nothing, so state reaches the callback through the
queue context (`dispatch_set_context` / `dispatch_get_context`) or a
pointer stored in an extended block struct. Block ABI flags and descriptor
layout to verify against the Block ABI spec (clang BlockLanguageSpec).

Event loop (house rules: Arc, reactive, no locks, no thread pools):

- All protocol state (ctaphid `Server`, ctap2 `Authenticator`) is owned by
  the single serial dispatch queue. The set-report block calls
  `Server::handle_report`; `Action::Process` runs `Authenticator::process`
  on the same queue; responses go out via HandleReport.
- User presence is the one long operation. M5 makes it asynchronous: the
  LocalAuthentication / Touch ID callback is posted back onto the queue,
  and a dispatch timer drives `Server::poll` plus KEEPALIVE packets every
  100 ms while waiting. CANCEL arrives as `Action::Cancel` on the same
  queue. No shared mutable state crosses threads.

Permissions:

- Creating a virtual HID device needs the restricted entitlement
  `com.apple.developer.hid.virtual.device`. Apple grants it on request
  only; ad-hoc signing cannot carry it while AMFI enforces entitlements.
- Without it, the user can run with SIP and AMFI relaxed (Recovery,
  `csrutil disable`, plus `amfi_get_out_of_my_way=1` boot-arg) so an
  ad-hoc signed binary with the entitlement is accepted. The user has said
  they will do this themselves when the driver part is ready. We never ask
  for it and never change system security settings.
- Unverified: whether macOS 26 still honours the entitlement for ad-hoc
  binaries under relaxed AMFI, and whether Chrome, Firefox and Safari all
  accept a device with Transport "Virtual". Safari routes WebAuthn through
  the system (AuthenticationServices); its handling of virtual HID keys is
  the biggest unknown.

## Fallback route: DriverKit HID driver written in Rust

Only if the user-space route is blocked. Fragile and unsupported: Apple
supports DriverKit drivers built from C++ with iig; a Rust dext depends on
private ABI details that can change with any OS update.

Shape: a dext whose `IOUserHIDDevice` subclass is implemented in Rust by
hand-matching the DriverKit C++ ABI:

- Itanium C++ name mangling for every DriverKit symbol we call or
  override (`_ZN15IOUserHIDDevice...`).
- vtable layouts for OSObject, IOService, IOHIDDevice, IOUserHIDDevice,
  including offset-to-top and RTTI slots, built as Rust statics.
- Object layouts (`OSObject` refcount and `ivars` pointers) as
  `#[repr(C)]` structs.
- OSMetaClass registration so the kernel can instantiate our class by
  name from the IOKitPersonalities.

Open questions:

- iig: `.iig` files generate the dispatch glue (`_Dispatch` methods,
  message IDs, `OSAction` subclasses, `IMPL` / `SUPERDISPATCH` macros) for
  remote calls between the kernel and the dext. We would need to
  reproduce what iig generates for each method we override
  (`Start`, `Stop`, `newDeviceDescription`, `newReportDescriptor`,
  `setReport`, `handleReport`), byte for byte, without running iig on our
  own code. Feasible only by reading the public DriverKit headers and
  generated headers from the SDK.
- Packaging: a `.dext` bundle (Info.plist with IOKitPersonalities,
  `OSBundleUsageDescription`, CFBundlePackageType DEXT) inside a host
  `.app`, activated by `OSSystemExtensionRequest` (Objective-C API; would
  be reached through hand-declared `objc_msgSend`).
- Signing: entitlements `com.apple.developer.driverkit`,
  `com.apple.developer.driverkit.family.hid.device`,
  `com.apple.developer.driverkit.transport.hid`; development needs
  `systemextensionsctl developer on` and SIP off for unsigned or
  ad-hoc dexts.
- Linking a Rust staticlib into a DriverKit target (the DriverKit SDK
  runtime, no std, which Rust target triple, panic=abort, allocator).

No implementation of either route in this run.

# transport-mac design

Goal: browsers on this Mac see se-fido as a USB security key. They find
keys through IOHIDManager by HID usage page 0xF1D0, usage 0x01, so a virtual
HID device with the descriptor in `src/lib.rs` is enough; no USB stack is
involved.

Constraint: Rust only. No C, C++, Objective-C or Swift source. All Apple
APIs are reached through hand-written `extern "C"` declarations.

## Headers checked (macOS 26.2 SDK)

SDK path from `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcrun --sdk macosx --show-sdk-path`:

`.../MacOSX26.2.sdk`

| Symbol | Header | Lines |
| --- | --- | --- |
| `IOHIDUserDeviceRef` | `IOKit.framework/Headers/hidsystem/IOHIDUserDevice.h` | 37 |
| `IOHIDUserDeviceSetReportBlock` | same | 57-60 |
| `IOHIDUserDeviceGetReportBlock` | same | 82-85 |
| `IOHIDUserDeviceOptionsCreateOnActivate` | same | 99-101 |
| `IOHIDUserDeviceGetTypeID` | same | 109-110 |
| `IOHIDUserDeviceCreateWithProperties` | same | 138-143 |
| `IOHIDUserDeviceRegisterGetReportBlock` | same | 162-165 |
| `IOHIDUserDeviceRegisterSetReportBlock` | same | 184-187 |
| `IOHIDUserDeviceSetDispatchQueue` | same | 210-213 |
| `IOHIDUserDeviceSetCancelHandler` | same | 244-247 |
| `IOHIDUserDeviceActivate` | same | 272-274 |
| `IOHIDUserDeviceCancel` | same | 307-309 |
| `IOHIDUserDeviceHandleReportWithTimeStamp` | same | 370-375 |
| Entitlement note in CreateWithProperties docs | same | 119-121 |
| `kIOHIDReportTypeInput/Output/Feature` | `hid/IOHIDDeviceTypes.h` | 45-48 |
| `kIOHIDReportDescriptorKey` etc. | `hid/IOHIDDeviceKeys.h` | 34,42,50,66,74,82,134,142,152,162,210 |
| `kIOHIDTransportVirtualValue` `"Virtual"` | `hid/IOHIDKeys.h` | 104 |
| `kIOReturnSuccess/Unsupported/...` | `IOKit.framework/Headers/IOReturn.h` | 95-109 |
| `_Block_copy`, `_Block_release`, `_NSConcrete*Block` | `usr/include/Block.h` | 31,34,43,44 |
| `dispatch_queue_create`, `dispatch_main`, `dispatch_async_f` | `usr/include/dispatch/queue.h` | 1091,1249,270 |
| `DISPATCH_QUEUE_SERIAL` (`NULL`) | same | 721 |
| `dispatch_source_create`, `DISPATCH_SOURCE_TYPE_TIMER` | `usr/include/dispatch/source.h` | 400,187 |
| `dispatch_time`, `NSEC_PER_MSEC`, `DISPATCH_TIME_NOW` | `usr/include/dispatch/time.h` | 110,56,79 |
| `dispatch_block_t` | `usr/include/dispatch/object.h` | 238 |

Block object layout (not in the public SDK header; from Apple libclosure /
llvm `Block_private.h`, which matches the public Block Language Spec):

```text
struct Block_descriptor { unsigned long reserved; unsigned long size; };
struct Block_layout {
  void *isa;
  int flags;
  int reserved;
  void (*invoke)(void *, ...);
  struct Block_descriptor *descriptor;
  /* captures follow */
};
```

Flags: `BLOCK_NEEDS_FREE (1<<24)`, `BLOCK_HAS_COPY_DISPOSE (1<<25)`,
`BLOCK_IS_GLOBAL (1<<28)`.

Note: `IOHIDUserDevice.h` lives under `Headers/hidsystem/`, not
`Headers/hid/`. The Command Line Tools SDK symlink tree may omit it; use the
full Xcode SDK.

## Primary route (implemented)

1. Build a CFDictionary from `properties()` (ReportDescriptor as CFData,
   numbers as CFNumber, strings as CFString).
2. `IOHIDUserDeviceCreateWithProperties(NULL, props,
   IOHIDUserDeviceOptionsCreateOnActivate)`.
3. Serial queue from `dispatch_queue_create("com.se-fido.device", NULL)`.
4. `IOHIDUserDeviceSetDispatchQueue`, register set/get report Blocks and a
   cancel handler Block (built in Rust via `_NSConcreteStackBlock` +
   `_Block_copy`; invoke functions are `extern "C"`).
5. 100 ms timer (`DISPATCH_SOURCE_TYPE_TIMER`) on the same queue for
   CTAPHID continuation timeouts and KEEPALIVE while a request is pending.
6. `IOHIDUserDeviceActivate`.
7. Host output reports -> `Server::handle_report`. `Action::Process` is
   deferred with `dispatch_async_f` so Cancel and keepalives can run first;
   then `Authenticator::process` (SE backend) runs and replies via
   `IOHIDUserDeviceHandleReportWithTimeStamp`.
8. Shutdown: `IOHIDUserDeviceCancel`; cancel handler releases the device.

VendorID `0x1209` / ProductID `0x51d0` are our placeholders (pid.codes open
vendor domain + se-fido mnemonic), not USB-IF assignments. Transport is
`"Virtual"`. Browsers match on usage page 0xF1D0.

Presence: default UV policy is `presence` (SE `kSecAccessControlUserPresence`).
`none` and `biometry` are selectable per device (`--uv-policy`). UP when the
SE will not prompt uses LocalAuthentication via `objc_msgSend` (passcode
allowed for `none`). `--auto-approve` is opt-in only and logged loudly.
Keepalive UPNEEDED while a request is pending on the queue.

## Permissions

- Creating a virtual HID device needs
  `com.apple.developer.hid.virtual.device` (cited in IOHIDUserDevice.h:119-121).
- Without an Apple grant, the user can relax SIP/AMFI so an ad-hoc signed
  binary carrying that entitlement is accepted. Steps and uncertainty are
  in DEPLOY.md. We never change system security settings ourselves.

## Binary

`se-fido-device` prints a dry-run plan by default. `--run` calls
`device::run` (create + activate). Do not pass `--run` until DEPLOY.md
steps are done.

## Fallback route: DriverKit HID driver written in Rust

Only if the user-space route is blocked. Fragile and unsupported: Apple
supports DriverKit drivers built from C++ with iig; a Rust dext depends on
private ABI details that can change with any OS update.

Shape: a dext whose `IOUserHIDDevice` subclass is implemented in Rust by
hand-matching the DriverKit C++ ABI (Itanium mangling, vtables,
OSObject/IOService layouts, OSMetaClass registration).

Open questions: reproducing iig-generated dispatch, dext bundle packaging,
signing entitlements, linking a Rust staticlib into a DriverKit target.
No implementation of this route.

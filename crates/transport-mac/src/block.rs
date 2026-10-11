//! Apple Block ABI in Rust (clang Block Language Spec + Block_private layout).
//!
//! Layout (llvm Block_private.h / Apple libclosure):
//! ```text
//! struct Block_descriptor { ulong reserved; ulong size; /* optional copy, dispose */ };
//! struct Block_layout {
//!   void *isa; int flags; int reserved;
//!   void (*invoke)(void *, ...);
//!   Block_descriptor *descriptor;
//!   /* captures... */
//! };
//! ```
//!
//! A stack Block with one raw-pointer capture is promoted with `_Block_copy`
//! (memcpy of `descriptor.size` bytes). No copy/dispose helpers are needed for
//! a plain pointer. See DESIGN.md for flag values and header citations.

use crate::ffi::{_Block_copy, _Block_release, _NSConcreteStackBlock, BlockPtr};
use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem;
use core::ptr;

/// `BLOCK_IS_GLOBAL` (1 << 28) from Block_private.h.
pub const BLOCK_IS_GLOBAL: i32 = 1 << 28;
/// `BLOCK_HAS_COPY_DISPOSE` (1 << 25).
pub const BLOCK_HAS_COPY_DISPOSE: i32 = 1 << 25;
/// `BLOCK_NEEDS_FREE` (1 << 24); set by the runtime on heap copies.
pub const BLOCK_NEEDS_FREE: i32 = 1 << 24;

#[repr(C)]
pub struct BlockDescriptor {
    pub reserved: usize,
    pub size: usize,
}

#[repr(C)]
pub struct BlockLiteral<T> {
    pub isa: *mut c_void,
    pub flags: i32,
    pub reserved: i32,
    pub invoke: *const c_void,
    pub descriptor: *const BlockDescriptor,
    pub captured: T,
}

/// Layout constants for fixtures (pointer-width dependent).
pub const LITERAL_SIZE_NO_CAPTURE: usize = mem::size_of::<BlockLiteral<()>>();
pub const LITERAL_SIZE_PTR_CAPTURE: usize = mem::size_of::<BlockLiteral<*mut c_void>>();
pub const OFFSET_ISA: usize = 0;
pub const OFFSET_FLAGS: usize = mem::offset_of!(BlockLiteral<()>, flags);
pub const OFFSET_RESERVED: usize = mem::offset_of!(BlockLiteral<()>, reserved);
pub const OFFSET_INVOKE: usize = mem::offset_of!(BlockLiteral<()>, invoke);
pub const OFFSET_DESCRIPTOR: usize = mem::offset_of!(BlockLiteral<()>, descriptor);
pub const OFFSET_CAPTURED: usize = mem::offset_of!(BlockLiteral<*mut c_void>, captured);
pub const DESCRIPTOR_SIZE: usize = mem::size_of::<BlockDescriptor>();

static PTR_CAPTURE_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: mem::size_of::<BlockLiteral<*mut c_void>>(),
};

/// Heap Block created with `_Block_copy`. Released on drop.
pub struct HeapBlock {
    ptr: *mut c_void,
    _marker: PhantomData<*mut c_void>,
}

impl HeapBlock {
    /// Stack literal capturing `ctx`, then `_Block_copy` to the heap.
    ///
    /// # Safety
    /// `invoke` must match the Block call signature expected by the API that
    /// receives this Block. `ctx` must stay valid for every invocation.
    pub unsafe fn copy_with_context(invoke: *const c_void, ctx: *mut c_void) -> Self {
        let mut literal = BlockLiteral {
            isa: unsafe { &_NSConcreteStackBlock as *const _ as *mut c_void },
            flags: 0,
            reserved: 0,
            invoke,
            descriptor: &PTR_CAPTURE_DESCRIPTOR,
            captured: ctx,
        };
        let ptr = unsafe { _Block_copy(&mut literal as *mut _ as *const c_void) };
        if ptr.is_null() {
            panic!("_Block_copy returned null");
        }
        HeapBlock {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn as_ptr(&self) -> BlockPtr {
        self.ptr as BlockPtr
    }
}

impl Drop for HeapBlock {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { _Block_release(self.ptr) };
            self.ptr = ptr::null_mut();
        }
    }
}

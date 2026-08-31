//! T-215: confirm a freed key handle's own backing memory is actually zeroed, not just that the
//! standalone `dstu_memzero` helper (already covered by `ffi_tests.rs`'s `memzero_wipes_buffer`)
//! works on a buffer nobody claims is linked to key lifecycle at all.
//!
//! Reading memory *after* `dstu_*_key_free` returns is undefined behavior - the allocator is free
//! to reuse, unmap, or poison the page, and this would not survive Miri. The well-defined
//! alternative used here: a `#[global_allocator]` installed only in this test binary that captures
//! the bytes at a *matching* pointer inside its own `dealloc` call, i.e. after the wrapped key
//! type's `Drop`/zeroize has already run (Rust drops the pointee in place before the `Box`
//! deallocates its backing memory) but *before* the real allocator reclaims the page - the memory
//! is still logically the allocator's own view at that point, so this is legal, not UB. Capture is
//! filtered by exact pointer address (set immediately before the one `free` call under test, cleared
//! immediately after) rather than by allocation size alone, so an unrelated same-sized allocation
//! freed concurrently by another test in this binary cannot produce a false positive.
//!
//! This crate's key types don't implement the `zeroize` crate's `ZeroizeOnDrop` marker trait
//! specifically - they hand-roll `impl Drop { fn drop(&mut self) { self.0.zeroize() } }` instead
//! (e.g. `dstu_core::crypto_auth::Key`), so a compile-time `T: ZeroizeOnDrop` trait-bound assertion
//! (the advisor-suggested second signal) doesn't type-check against this codebase's actual pattern
//! - this runtime capture is the one instrument used here, not paired with a trait assertion.
//!
//! **Excluded under Miri on Windows only** (`#![cfg(not(all(miri, windows)))]` below). First
//! discovered on this project's own Windows dev machine: registering ANY custom
//! `#[global_allocator]` (confirmed with a minimal 15-line repro containing none of this crate's
//! own logic - a bare passthrough to `System`) makes libtest's own internal teardown
//! (`Box<Counter<Channel<CompletedTest>>>`'s drop, deallocating the harness's own result-reporting
//! channel) fail a Stacked Borrows check inside `std::sys::alloc::windows::dealloc`'s hidden
//! size-header lookup (`(ptr as *mut Header).sub(1)`) there. That's a Windows-target-specific code
//! path with no Linux equivalent - confirmed by actually running this file's real, un-excluded
//! form under `cargo +nightly miri test` on the project's Raspberry Pi (real `aarch64-unknown-
//! linux-gnu`): all 6 tests pass clean, including the negative control. CI's own Miri job
//! (`.github/workflows/rust.yml`, `ubuntu-latest`, `dstu-core-capi` in its matrix) is the same OS
//! family as that confirmation, so this file runs there for real - the Windows-only exclusion below
//! is scoped as narrowly as the actual finding, not a blanket Miri skip. The crash happens in the
//! test *harness's own* teardown regardless of which individual tests run, so on Windows a per-test
//! `#[cfg_attr(miri, ignore = "...")]` (this project's usual pattern, e.g. `crates/uacrypt/tests/
//! support/mod.rs`'s subprocess-spawning tests) can't avoid it - only excluding the whole file (and
//! therefore the `#[global_allocator]` registration itself) can, hence the file-level cfg rather
//! than a per-test one.
#![cfg(not(all(miri, windows)))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use dstu_core_capi::auth::{dstu_auth_key_free, dstu_auth_key_generate, DstuAuthKey};
use dstu_core_capi::error::DstuStatus;
use dstu_core_capi::secretbox::{
    dstu_secretbox_key_free, dstu_secretbox_key_generate, DstuSecretboxKey,
};
use dstu_core_capi::secretstream::{
    dstu_secretstream_key_free, dstu_secretstream_key_generate, DstuSecretstreamKey,
};
use dstu_core_capi::sign::{dstu_sign_key_free, dstu_sign_key_generate, DstuSigningKey};
use dstu_core_capi::stream::{dstu_stream_key_free, dstu_stream_key_generate, DstuStreamKey};

struct CapturingAllocator;

/// 0 means "not currently watching any pointer" - never a valid allocation address.
static TARGET_PTR: AtomicUsize = AtomicUsize::new(0);
static CAPTURE_FIRED: AtomicBool = AtomicBool::new(false);
static CAPTURED_ALL_ZERO: AtomicBool = AtomicBool::new(false);
static CAPTURED_LEN: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CapturingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TARGET_PTR.load(Ordering::SeqCst) == ptr as usize {
            // Raw-pointer byte reads, deliberately not `slice::from_raw_parts` - constructing a
            // `&[u8]` here and iterating it performs an implicit reborrow/retag under Stacked
            // Borrows that Miri treats as invalidating the allocation-wide provenance the
            // Windows target's own `System::deallocate` needs afterward for its hidden
            // size-header lookup (`(ptr as *mut Header).sub(1)`) - confirmed the hard way, this
            // exact function failed under `cargo +nightly miri test` with a
            // "tag does not exist in the borrow stack" error until switched to this form. A raw
            // `.read()` through the original pointer's own provenance, with no new reference
            // created, doesn't have that effect.
            let all_zero = (0..layout.size()).all(|i| unsafe { ptr.add(i).read() } == 0);
            CAPTURED_ALL_ZERO.store(all_zero, Ordering::SeqCst);
            CAPTURED_LEN.store(layout.size(), Ordering::SeqCst);
            CAPTURE_FIRED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static ALLOC: CapturingAllocator = CapturingAllocator;

/// Serializes the whole "arm capture -> free -> read capture" window across tests in this binary -
/// cargo runs `#[test]` fns in parallel threads by default, and two tests both watching a pointer
/// at once would race on the shared statics above.
static CAPTURE_WINDOW: Mutex<()> = Mutex::new(());

/// Arms capture for `ptr`, calls `free_fn(ptr)`, disarms, and asserts the freed handle's backing
/// memory was observed and was all-zero.
fn assert_free_zeroizes<T>(label: &str, ptr: *mut T, free_fn: unsafe extern "C" fn(*mut T)) {
    let _guard = CAPTURE_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    CAPTURE_FIRED.store(false, Ordering::SeqCst);
    CAPTURED_ALL_ZERO.store(false, Ordering::SeqCst);
    TARGET_PTR.store(ptr as usize, Ordering::SeqCst);

    unsafe { free_fn(ptr) };

    TARGET_PTR.store(0, Ordering::SeqCst);
    assert!(
        CAPTURE_FIRED.load(Ordering::SeqCst),
        "{label}: never observed a dealloc of the freed handle's own pointer - the allocator hook \
         didn't fire, this test proves nothing"
    );
    assert!(
        CAPTURED_LEN.load(Ordering::SeqCst) > 0,
        "{label}: captured a zero-length allocation, suspicious"
    );
    assert!(
        CAPTURED_ALL_ZERO.load(Ordering::SeqCst),
        "{label}: freed key handle's backing memory was NOT all-zero"
    );
}

#[test]
fn auth_key_free_zeroizes_backing_memory() {
    let mut ptr: *mut DstuAuthKey = std::ptr::null_mut();
    assert_eq!(
        unsafe { dstu_auth_key_generate(&mut ptr) },
        DstuStatus::DSTU_OK
    );
    assert_free_zeroizes("auth_key", ptr, dstu_auth_key_free);
}

#[test]
fn secretbox_key_free_zeroizes_backing_memory() {
    let mut ptr: *mut DstuSecretboxKey = std::ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretbox_key_generate(&mut ptr) },
        DstuStatus::DSTU_OK
    );
    assert_free_zeroizes("secretbox_key", ptr, dstu_secretbox_key_free);
}

#[test]
fn sign_key_free_zeroizes_backing_memory() {
    let mut ptr: *mut DstuSigningKey = std::ptr::null_mut();
    assert_eq!(
        unsafe { dstu_sign_key_generate(&mut ptr) },
        DstuStatus::DSTU_OK
    );
    assert_free_zeroizes("sign_key", ptr, dstu_sign_key_free);
}

#[test]
fn stream_key_free_zeroizes_backing_memory() {
    let mut ptr: *mut DstuStreamKey = std::ptr::null_mut();
    assert_eq!(
        unsafe { dstu_stream_key_generate(&mut ptr) },
        DstuStatus::DSTU_OK
    );
    assert_free_zeroizes("stream_key", ptr, dstu_stream_key_free);
}

#[test]
fn secretstream_key_free_zeroizes_backing_memory() {
    let mut ptr: *mut DstuSecretstreamKey = std::ptr::null_mut();
    assert_eq!(
        unsafe { dstu_secretstream_key_generate(&mut ptr) },
        DstuStatus::DSTU_OK
    );
    assert_free_zeroizes("secretstream_key", ptr, dstu_secretstream_key_free);
}

/// Negative control (proves this harness can actually detect a non-zeroized free, not just that
/// it never fails): a plain `Box<[u8; 64]>` filled with a non-zero pattern has no zeroize-on-drop
/// behavior at all, so its freed backing memory must NOT read back as all-zero.
#[test]
fn negative_control_plain_box_free_is_not_zeroized() {
    let _guard = CAPTURE_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    let boxed: Box<[u8; 64]> = Box::new([0xAB; 64]);
    let ptr = Box::into_raw(boxed);

    CAPTURE_FIRED.store(false, Ordering::SeqCst);
    CAPTURED_ALL_ZERO.store(false, Ordering::SeqCst);
    TARGET_PTR.store(ptr as usize, Ordering::SeqCst);
    drop(unsafe { Box::from_raw(ptr) });
    TARGET_PTR.store(0, Ordering::SeqCst);

    assert!(
        CAPTURE_FIRED.load(Ordering::SeqCst),
        "harness didn't observe the dealloc at all"
    );
    assert!(
        !CAPTURED_ALL_ZERO.load(Ordering::SeqCst),
        "harness reported all-zero for a value with no zeroize-on-drop behavior - the harness \
         itself is broken, not proving anything about real key types"
    );
}

//! Shared JNI plumbing: panic safety at the FFI boundary, byte-array-length checks, and the
//! misuse/crypto-failure exception split.
//!
//! **Every `Java_...` entry point in this crate goes through [`guard`].** Unwinding across an FFI
//! boundary into a foreign (JVM) stack frame is undefined behavior per the Rust reference, not
//! just a style preference - `dstu-core-capi` (T-158) wraps every export in `catch_unwind` for
//! the identical reason (D-150's own doc comment), and the `jni` crate gives no automatic panic
//! guard the way `napi`/`PyO3`/`magnus` do for the other direct-Rust bindings.

use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// A failure to report to the Java caller, split three ways - a finer split than
/// Python's plain `ValueError`/`DstuError`, matching C#'s own three-way
/// `ArgumentException`/`InvalidOperationException`/`DstuException` split instead (T-52/D-152),
/// since Java (like C#) has a distinct exception for "wrong argument value" versus "wrong call
/// sequence for the current state": `Misuse` throws `IllegalArgumentException` (e.g. a
/// wrong-length key), `State` throws `IllegalStateException` (e.g. a hasher already finalized,
/// or any handle used after `close()`), `Crypto` throws the dedicated
/// `ua.dstucrypto.dstucore.DstuException`.
pub enum Failure {
    Misuse(String),
    State(String),
    Crypto(String),
}

/// Converts any `dstu_core` `Result<T, E>` into `Result<T, Failure::Crypto>` - every wrapped
/// error type's `Display` impl already carries the specific cause, so the message is reused
/// as-is rather than re-derived per call site.
pub trait IntoCrypto<T> {
    fn crypto(self) -> Result<T, Failure>;
}

impl<T, E: std::fmt::Display> IntoCrypto<T> for Result<T, E> {
    fn crypto(self) -> Result<T, Failure> {
        self.map_err(|e| Failure::Crypto(e.to_string()))
    }
}

/// Converts a caller-supplied byte slice to a fixed-size array, or a [`Failure::Misuse`] naming
/// the expected length - the JNI-side equivalent of every other binding's own `to_array` helper.
pub fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], Failure> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        Failure::Misuse(format!(
            "{what} must be exactly {N} bytes, got {}",
            bytes.len()
        ))
    })
}

fn throw(env: &mut JNIEnv, failure: Failure) {
    let (class, message) = match failure {
        Failure::Misuse(message) => ("java/lang/IllegalArgumentException", message),
        Failure::State(message) => ("java/lang/IllegalStateException", message),
        Failure::Crypto(message) => ("ua/dstucrypto/dstucore/DstuException", message),
    };
    // A `throw_new` failure here means the JVM itself is already in an unrecoverable state (e.g.
    // OOM constructing the exception object) - nothing further native code can do about it.
    let _ = env.throw_new(class, message);
}

/// Runs `f`, catching both a returned [`Failure`] and a caught Rust panic and converting either
/// into a pending Java exception, then returns `default`. Every native method in this crate calls
/// its real logic through this wrapper and nothing else - once `default` is returned, the pending
/// exception (set via `throw_new`/`throw` above) fires in Java the moment control returns there;
/// the native method's own return value is discarded by the JVM in that case, but must still be a
/// well-typed value of the right shape (`null`/`0`/`false`), which `default` supplies.
pub fn guard<'local, F, R>(env: &mut JNIEnv<'local>, default: R, f: F) -> R
where
    F: FnOnce(&mut JNIEnv<'local>) -> Result<R, Failure> + std::panic::UnwindSafe,
{
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(value)) => value,
        Ok(Err(failure)) => {
            throw(env, failure);
            default
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                "internal panic in dstu_core_java (this is a bug - please report it)",
            );
            default
        }
    }
}

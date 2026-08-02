//! Shared PHP exception class for this extension - `docs/cross-language-style-guide.md`'s "errors
//! are an explicit, typed result" principle, PHP form. One exception class across every `crypto_*`
//! wrapper (`DstuCoreException`, flat name, no namespace), not one per module - every failure
//! raised here already carries a specific message from the wrapped `dstu_core` error type's own
//! `Display` impl, so a caller who needs to distinguish cases matches on that message, the same
//! shape PHP's own bundled `SodiumException` has for `ext-sodium` (`docs/DECISIONS.md` D-142's
//! naming-convention entry has the full precedent). A caller-input mistake (wrong-length key,
//! negative subkey id) raises PHP's own built-in `\ValueError` instead (`crate::util::to_array`),
//! not this class - matches Ruby's `ArgumentError`/Python's `ValueError` split, this project's
//! standing two-different-failure-classes convention.

use ext_php_rs::{
    exception::PhpException,
    php_class,
    zend::{ce, ClassEntry},
};

/// Raised for any `dstu_core` crypto operation failure (authentication/tamper rejection, OS CSPRNG
/// failure, malformed input, etc.) - see the raised message for the specific cause.
#[php_class]
#[php(name = "DstuCoreException")]
#[php(extends(ce = ce::exception, stub = "\\Exception"))]
#[derive(Default)]
pub struct DstuCoreException;

/// Bridges any `dstu_core` error (all of which implement `Display`) onto a thrown
/// `DstuCoreException`.
pub trait IntoDstuException<T> {
    fn dstu(self) -> Result<T, PhpException>;
}

impl<T, E: core::fmt::Display> IntoDstuException<T> for Result<T, E> {
    fn dstu(self) -> Result<T, PhpException> {
        self.map_err(|e| PhpException::from_class::<DstuCoreException>(e.to_string()))
    }
}

/// PHP's own built-in `\ValueError` class entry (PHP 8+) - used for a caller-input mistake a
/// fixed-size Rust array forecloses (wrong-length key/context/nonce/etc.), never for a crypto
/// operation failure.
pub fn value_error() -> &'static ClassEntry {
    ce::value_error()
}

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
    builders::ModuleBuilder,
    exception::PhpException,
    php_class, php_function, wrap_function,
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

/// Throws a `DstuCoreException` carrying `message`. `DstuCoreException` has no `#[php_impl]`
/// constructor (deliberately - it only ever needs to be constructed on the Rust side via
/// `PhpException::from_class`), so `new DstuCoreException(...)` fails from pure PHP with "You
/// cannot instantiate this class from PHP." (confirmed by a real error, not assumed). This
/// function is the escape hatch the pure-PHP `DstuCoreSecretStreamWriter`/`Reader` wrapper
/// (`lib/DstuCoreSecretStream.php`, step 3) calls instead of `throw new DstuCoreException(...)`
/// for its own protocol-level failures (truncation, oversized chunk length, trailing data) -
/// always throws, so a plain call like `dstu_core_throw_error("...")` behaves exactly like a
/// `throw` statement at the call site.
#[php_function]
pub fn dstu_core_throw_error(message: String) -> Result<(), PhpException> {
    Err(PhpException::from_class::<DstuCoreException>(message))
}

/// Registers this module's function - see `secretbox::register`'s doc comment (`secretbox.rs`)
/// for why each module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module.function(wrap_function!(dstu_core_throw_error))
}

//! `crypto_generichash` wrapper - see [`dstu_core::crypto_generichash`] (Kupyna-256/512). One-shot
//! functions for a whole in-memory message, plus incremental `*Hasher` classes for a large or
//! streamed one - both produce the same digest for the same bytes. Class names are prefixed
//! `DstuCore*` (not namespaced - `docs/DECISIONS.md` D-142) to avoid colliding with an unrelated
//! extension's own global class table entry, matching the flat `dstu_core_*` function-naming
//! convention.

use std::cell::RefCell;

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_class, php_function,
    php_impl, wrap_function,
};

use crate::error::DstuCoreException;
use dstu_core::crypto_generichash as core;

/// Computes the 32-byte Kupyna-256 digest of `message`.
///
/// `#[php(name = ...)]` pinned explicitly - `#[php_function]`'s default snake_case rename rule
/// splits a letter-to-digit boundary (`kupyna256` -> `kupyna_256`), confirmed by a real smoke
/// test calling the unprefixed name and getting "Call to undefined function", not assumed.
#[php_function]
#[php(name = "dstu_core_generichash_kupyna256")]
pub fn dstu_core_generichash_kupyna256(message: Binary<u8>) -> Binary<u8> {
    Binary::from(core::Kupyna256::digest(&message).to_vec())
}

/// Computes the 64-byte Kupyna-512 digest of `message`. See
/// [`dstu_core_generichash_kupyna256`]'s doc comment for why `#[php(name = ...)]` is pinned.
#[php_function]
#[php(name = "dstu_core_generichash_kupyna512")]
pub fn dstu_core_generichash_kupyna512(message: Binary<u8>) -> Binary<u8> {
    Binary::from(core::Kupyna512::digest(&message).to_vec())
}

fn already_finalized() -> PhpException {
    PhpException::from_class::<DstuCoreException>("hasher already finalized".to_string())
}

/// Incremental Kupyna-256 hasher - call `update` any number of times, then `finalize` once.
#[php_class]
#[php(name = "DstuCoreKupyna256Hasher")]
pub struct Kupyna256Hasher(RefCell<Option<core::Kupyna256Hasher>>);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl Kupyna256Hasher {
    pub fn __construct() -> Self {
        Self(RefCell::new(Some(core::Kupyna256Hasher::new())))
    }

    pub fn update(&self, data: Binary<u8>) -> Result<(), PhpException> {
        match self.0.borrow_mut().as_mut() {
            Some(hasher) => {
                hasher.update(&data);
                Ok(())
            }
            None => Err(already_finalized()),
        }
    }

    /// Consumes the accumulated state and returns the 32-byte digest. Throws `DstuCoreException`
    /// if called more than once.
    pub fn finalize(&self) -> Result<Binary<u8>, PhpException> {
        match self.0.borrow_mut().take() {
            Some(hasher) => Ok(Binary::from(hasher.finalize().to_vec())),
            None => Err(already_finalized()),
        }
    }
}

/// Incremental Kupyna-512 hasher - call `update` any number of times, then `finalize` once.
#[php_class]
#[php(name = "DstuCoreKupyna512Hasher")]
pub struct Kupyna512Hasher(RefCell<Option<core::Kupyna512Hasher>>);

#[php_impl]
#[php(change_method_case = "snake_case")]
impl Kupyna512Hasher {
    pub fn __construct() -> Self {
        Self(RefCell::new(Some(core::Kupyna512Hasher::new())))
    }

    pub fn update(&self, data: Binary<u8>) -> Result<(), PhpException> {
        match self.0.borrow_mut().as_mut() {
            Some(hasher) => {
                hasher.update(&data);
                Ok(())
            }
            None => Err(already_finalized()),
        }
    }

    /// Consumes the accumulated state and returns the 64-byte digest. Throws `DstuCoreException`
    /// if called more than once.
    pub fn finalize(&self) -> Result<Binary<u8>, PhpException> {
        match self.0.borrow_mut().take() {
            Some(hasher) => Ok(Binary::from(hasher.finalize().to_vec())),
            None => Err(already_finalized()),
        }
    }
}

/// Registers this module's functions and classes - see `secretbox::register`'s doc comment for
/// why each module registers its own functions.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(dstu_core_generichash_kupyna256))
        .function(wrap_function!(dstu_core_generichash_kupyna512))
        .class::<Kupyna256Hasher>()
        .class::<Kupyna512Hasher>()
}

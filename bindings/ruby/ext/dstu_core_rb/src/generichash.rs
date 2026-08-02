//! `crypto_generichash` wrapper - see [`dstu_core::crypto_generichash`] (Kupyna-256/512). One-shot
//! functions for a whole in-memory message, plus incremental `*Hasher` classes for a large or
//! streamed one - both produce the same digest for the same bytes.

use std::cell::RefCell;

use dstu_core::crypto_generichash as core;
use magnus::{wrap, Error, RString, Ruby};

/// Computes the 32-byte Kupyna-256 digest of `message`.
pub fn kupyna256(ruby: &Ruby, message: RString) -> RString {
    ruby.str_from_slice(&core::Kupyna256::digest(&message.to_bytes()))
}

/// Computes the 64-byte Kupyna-512 digest of `message`.
pub fn kupyna512(ruby: &Ruby, message: RString) -> RString {
    ruby.str_from_slice(&core::Kupyna512::digest(&message.to_bytes()))
}

fn already_finalized() -> Error {
    Error::new(
        Ruby::get()
            .expect("must run on a Ruby thread")
            .exception_arg_error(),
        "hasher already finalized",
    )
}

/// Incremental Kupyna-256 hasher - call `update` any number of times, then `finalize` once.
#[wrap(class = "DstuCore::Kupyna256Hasher")]
pub struct Kupyna256Hasher(RefCell<Option<core::Kupyna256Hasher>>);

impl Kupyna256Hasher {
    fn new() -> Self {
        Self(RefCell::new(Some(core::Kupyna256Hasher::new())))
    }

    fn update(&self, data: RString) -> Result<(), Error> {
        match self.0.borrow_mut().as_mut() {
            Some(hasher) => {
                hasher.update(&data.to_bytes());
                Ok(())
            }
            None => Err(already_finalized()),
        }
    }

    /// Consumes the accumulated state and returns the 32-byte digest. Raises `ArgumentError` if
    /// called more than once.
    fn finalize(&self) -> Result<RString, Error> {
        match self.0.borrow_mut().take() {
            Some(hasher) => Ok(Ruby::get()
                .expect("must run on a Ruby thread")
                .str_from_slice(&hasher.finalize())),
            None => Err(already_finalized()),
        }
    }
}

/// Incremental Kupyna-512 hasher - call `update` any number of times, then `finalize` once.
#[wrap(class = "DstuCore::Kupyna512Hasher")]
pub struct Kupyna512Hasher(RefCell<Option<core::Kupyna512Hasher>>);

impl Kupyna512Hasher {
    fn new() -> Self {
        Self(RefCell::new(Some(core::Kupyna512Hasher::new())))
    }

    fn update(&self, data: RString) -> Result<(), Error> {
        match self.0.borrow_mut().as_mut() {
            Some(hasher) => {
                hasher.update(&data.to_bytes());
                Ok(())
            }
            None => Err(already_finalized()),
        }
    }

    /// Consumes the accumulated state and returns the 64-byte digest. Raises `ArgumentError` if
    /// called more than once.
    fn finalize(&self) -> Result<RString, Error> {
        match self.0.borrow_mut().take() {
            Some(hasher) => Ok(Ruby::get()
                .expect("must run on a Ruby thread")
                .str_from_slice(&hasher.finalize())),
            None => Err(already_finalized()),
        }
    }
}

pub fn init(ruby: &Ruby, module: magnus::RModule) -> Result<(), Error> {
    use magnus::{function, method, prelude::*};

    module.define_singleton_method("kupyna256", function!(kupyna256, 1))?;
    module.define_singleton_method("kupyna512", function!(kupyna512, 1))?;

    let hasher256 = module.define_class("Kupyna256Hasher", ruby.class_object())?;
    hasher256.define_singleton_method("new", function!(Kupyna256Hasher::new, 0))?;
    hasher256.define_method("update", method!(Kupyna256Hasher::update, 1))?;
    hasher256.define_method("finalize", method!(Kupyna256Hasher::finalize, 0))?;

    let hasher512 = module.define_class("Kupyna512Hasher", ruby.class_object())?;
    hasher512.define_singleton_method("new", function!(Kupyna512Hasher::new, 0))?;
    hasher512.define_method("update", method!(Kupyna512Hasher::update, 1))?;
    hasher512.define_method("finalize", method!(Kupyna512Hasher::finalize, 0))?;

    Ok(())
}

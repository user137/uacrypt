//! `randombytes` wrapper - see [`dstu_core::randombytes`] (OS CSPRNG via `getrandom`).

use ext_php_rs::{
    binary::Binary, builders::ModuleBuilder, exception::PhpException, php_function, wrap_function,
};

use crate::error::IntoDstuException;

/// Returns `size` cryptographically secure random bytes from the OS CSPRNG.
#[php_function]
pub fn dstu_core_randombytes_buf(size: usize) -> Result<Binary<u8>, PhpException> {
    let mut buf = vec![0u8; size];
    dstu_core::randombytes::randombytes_buf(&mut buf).dstu()?;
    Ok(Binary::from(buf))
}

/// Registers this module's functions - see `secretbox::register`'s doc comment for why each
/// module registers its own.
pub fn register(module: ModuleBuilder) -> ModuleBuilder {
    module.function(wrap_function!(dstu_core_randombytes_buf))
}

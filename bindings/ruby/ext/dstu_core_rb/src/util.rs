//! Small helpers shared by every `crypto_*` wrapper module - fixed-length conversion from a
//! caller-supplied Ruby `String` (arbitrary length) to the fixed-size array `dstu_core`'s own API
//! expects, and a one-line `Result<T, E: Display> -> Result<T, magnus::Error>` bridge onto
//! [`crate::error::dstu_error`] so every wrapper function doesn't hand-write the same `.map_err`.

use magnus::{Error, Ruby};

/// Converts a Ruby `String`'s bytes to a fixed-size array, raising `ArgumentError` (not
/// `DstuCore::Error` - this is a caller-input mistake, not a crypto operation failure) if the
/// length is wrong.
pub fn to_array<const N: usize>(ruby: &Ruby, bytes: &[u8], name: &str) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        Error::new(
            ruby.exception_arg_error(),
            format!("{name} must be exactly {N} bytes, got {}", bytes.len()),
        )
    })
}

/// Bridges any `dstu_core` error (all of which implement `Display`) onto
/// [`crate::error::dstu_error`].
pub trait IntoDstuError<T> {
    fn dstu(self, ruby: &Ruby) -> Result<T, Error>;
}

impl<T, E: core::fmt::Display> IntoDstuError<T> for Result<T, E> {
    fn dstu(self, ruby: &Ruby) -> Result<T, Error> {
        self.map_err(|e| Error::new(crate::error::dstu_error(ruby), e.to_string()))
    }
}

//! Small helper shared by every `crypto_*` wrapper module - fixed-length conversion from a
//! caller-supplied PHP binary string (arbitrary length) to the fixed-size array `dstu_core`'s own
//! API expects.

use ext_php_rs::exception::PhpException;

use crate::error::value_error;

/// Converts a byte slice to a fixed-size array, raising `\ValueError` (not `DstuCoreException` -
/// this is a caller-input mistake, not a crypto operation failure) if the length is wrong.
pub fn to_array<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], PhpException> {
    <[u8; N]>::try_from(bytes).map_err(|_| {
        PhpException::new(
            format!("{name} must be exactly {N} bytes, got {}", bytes.len()),
            0,
            value_error(),
        )
    })
}

//! `randombytes` wrapper - see [`dstu_core::randombytes`] (OS CSPRNG via `getrandom`).

use crate::util::IntoDstuError;
use magnus::{Error, RString, Ruby};

/// Returns `size` cryptographically secure random bytes from the OS CSPRNG.
pub fn randombytes_buf(ruby: &Ruby, size: usize) -> Result<RString, Error> {
    let mut buf = vec![0u8; size];
    dstu_core::randombytes::randombytes_buf(&mut buf).dstu(ruby)?;
    Ok(ruby.str_from_slice(&buf))
}

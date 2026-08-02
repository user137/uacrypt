//! `randombytes` wrapper - see `dstu_core::randombytes` (OS CSPRNG via `getrandom`).

use crate::util::IntoDstuError;
use napi::bindgen_prelude::Buffer;
use napi::Result;
use napi_derive::napi;

/// Returns `size` cryptographically secure random bytes from the OS CSPRNG.
#[napi(js_name = "randombytesBuf")]
pub fn randombytes_buf(size: u32) -> Result<Buffer> {
    let mut buf = vec![0u8; size as usize];
    dstu_core::randombytes::randombytes_buf(&mut buf).dstu()?;
    Ok(Buffer::from(buf))
}

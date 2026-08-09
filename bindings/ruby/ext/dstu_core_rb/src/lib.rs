//! `dstu_core_rb` - Ruby bindings for `dstu-core` via `magnus`/`rb_sys`. Flat function-per-module
//! naming (`DstuCore.secretbox_seal`, etc.), one Rust module per `dstu_core::crypto_*` module plus
//! [`self_test`] (step 1). Keys/ciphertexts/tags cross the boundary as plain `String` (binary);
//! failures raise `DstuCore::Error` (or Ruby's own `ArgumentError` for a caller-input mistake like
//! a wrong-length key, not a crypto failure). Ruby's own `snake_case` convention needs no
//! per-function casing override, unlike Node's `js_name` requirement (D-126) - method names pass
//! through as written. A more idiomatic Ruby surface (an `IO`-like `crypto_secretstream` wrapper)
//! is deferred to a later step.

mod auth;
mod box512;
mod crypto_box;
mod error;
mod generichash;
mod kdf;
mod pwhash;
mod randombytes;
mod secretbox;
mod secretstream;
mod sign;
mod sign257;
mod stream;
mod util;

use magnus::{function, prelude::*, Error, Ruby};

/// See `dstu_core::selftest` on the Rust side for what this does and does not cover.
fn self_test() -> Result<(), Error> {
    let ruby = Ruby::get().expect("must be called from a Ruby thread");
    dstu_core::selftest::run()
        .map_err(|report| Error::new(error::dstu_error(&ruby), report.to_string()))
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("DstuCore")?;
    error::force(ruby);

    module.define_singleton_method("self_test", function!(self_test, 0))?;

    module.define_singleton_method(
        "secretbox_keygen",
        function!(secretbox::secretbox_keygen, 0),
    )?;
    module.define_singleton_method("secretbox_seal", function!(secretbox::secretbox_seal, 2))?;
    module.define_singleton_method("secretbox_open", function!(secretbox::secretbox_open, 2))?;

    module.define_singleton_method("box_keygen", function!(crypto_box::box_keygen, 0))?;
    module.define_singleton_method("box_public_key", function!(crypto_box::box_public_key, 1))?;
    module.define_singleton_method("box_seal", function!(crypto_box::box_seal, 2))?;
    module.define_singleton_method("box_open", function!(crypto_box::box_open, 2))?;

    module.define_singleton_method("box512_keygen", function!(box512::box512_keygen, 0))?;
    module.define_singleton_method("box512_public_key", function!(box512::box512_public_key, 1))?;
    module.define_singleton_method("box512_seal", function!(box512::box512_seal, 2))?;
    module.define_singleton_method("box512_open", function!(box512::box512_open, 2))?;

    module.define_singleton_method("sign_keygen", function!(sign::sign_keygen, 0))?;
    module.define_singleton_method("sign_verifying_key", function!(sign::sign_verifying_key, 1))?;
    module.define_singleton_method("sign_message", function!(sign::sign_message, 2))?;
    module.define_singleton_method("sign_verify", function!(sign::sign_verify, 3))?;

    module.define_singleton_method("sign257_keygen", function!(sign257::sign257_keygen, 0))?;
    module.define_singleton_method(
        "sign257_verifying_key",
        function!(sign257::sign257_verifying_key, 1),
    )?;
    module.define_singleton_method("sign257_message", function!(sign257::sign257_message, 2))?;
    module.define_singleton_method("sign257_verify", function!(sign257::sign257_verify, 3))?;

    module.define_singleton_method("auth_keygen", function!(auth::auth_keygen, 0))?;
    module.define_singleton_method("auth", function!(auth::auth, 2))?;
    module.define_singleton_method("auth_verify", function!(auth::auth_verify, 3))?;

    module.define_singleton_method("kdf_keygen", function!(kdf::kdf_keygen, 0))?;
    module.define_singleton_method("kdf_derive_subkey", function!(kdf::kdf_derive_subkey, 3))?;

    generichash::init(ruby, module)?;

    module.define_singleton_method("stream_keygen", function!(stream::stream_keygen, 0))?;
    module.define_singleton_method("stream_encrypt", function!(stream::stream_encrypt, 2))?;
    module.define_singleton_method("stream_decrypt", function!(stream::stream_decrypt, 2))?;

    module.define_singleton_method(
        "pwhash_hash_password",
        function!(pwhash::pwhash_hash_password, 2),
    )?;
    module.define_singleton_method(
        "pwhash_verify_password",
        function!(pwhash::pwhash_verify_password, 2),
    )?;
    module.const_set("PWHASH_INTERACTIVE", 0u8)?;
    module.const_set("PWHASH_MODERATE", 1u8)?;
    module.const_set("PWHASH_SENSITIVE", 2u8)?;

    module.define_singleton_method(
        "randombytes_buf",
        function!(randombytes::randombytes_buf, 1),
    )?;

    secretstream::init(ruby, module)?;
    module.const_set("SECRETSTREAM_TAG_MESSAGE", 0x00u8)?;
    module.const_set("SECRETSTREAM_TAG_PUSH", 0x01u8)?;
    module.const_set("SECRETSTREAM_TAG_REKEY", 0x02u8)?;
    module.const_set("SECRETSTREAM_TAG_FINAL", 0x03u8)?;

    Ok(())
}

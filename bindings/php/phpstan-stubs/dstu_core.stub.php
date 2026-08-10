<?php

// T-208: PHPStan analysis-time stub for the dstu_core_php compiled extension's own surface -
// every dstu_core_* function/class below is defined in Rust (src/*.rs, ext-php-rs), not in any
// .php file, so PHPStan would otherwise report every call as an unknown function/class. Never
// loaded at runtime (PHPStan's own stubFiles mechanism, phpstan.neon) - this file only teaches the
// analyzer the real signatures src/*.rs already implements; it does not implement anything itself.
// Keep this file in sync by hand when a new function/class/constant is added to src/*.rs - there is
// no automated generator for this (same manual-sync tradeoff this project already accepts for
// FUZZ_TARGETS/CAPI_EXAMPLES in xtask/src/main.rs).

// --- crypto_secretbox ---
function dstu_core_secretbox_keygen(): string {}
function dstu_core_secretbox_seal(string $key, string $plaintext): string {}
function dstu_core_secretbox_open(string $key, string $sealed): string {}

// --- crypto_box ---
function dstu_core_box_keygen(): string {}
function dstu_core_box_public_key(string $secret_key): string {}
function dstu_core_box_seal(string $public_key, string $message): string {}
function dstu_core_box_open(string $secret_key, string $sealed): string {}

// --- crypto_box512 (l(p)=512 sibling of crypto_box, T-193/T-204) ---
function dstu_core_box512_keygen(): string {}
function dstu_core_box512_public_key(string $secret_key): string {}
function dstu_core_box512_seal(string $public_key, string $message): string {}
function dstu_core_box512_open(string $secret_key, string $sealed): string {}

// --- crypto_secretstream ---
function dstu_core_secretstream_keygen(): string {}

/** Encrypting half of a crypto_secretstream session - see DstuCoreSecretStreamPullState. */
class DstuCoreSecretStreamPushState
{
    public function __construct(string $key) {}

    public function header(): string
    {
        return '';
    }

    public function is_finalized(): bool
    {
        return false;
    }

    /** @return string[] [ciphertext, auth_tag] */
    public function push(int $tag, string $plaintext): array
    {
        return [];
    }
}

/** Decrypting half of a crypto_secretstream session. */
class DstuCoreSecretStreamPullState
{
    public function __construct(string $key, string $header) {}

    public function is_finalized(): bool
    {
        return false;
    }

    /** @return array{0: int, 1: string} [tag, plaintext] */
    public function pull(int $tag_byte, string $ciphertext, string $auth_tag): array
    {
        return [0, ''];
    }
}

// --- crypto_sign (DSTU 4145 m=163) ---
function dstu_core_sign_keygen(): string {}
function dstu_core_sign_verifying_key(string $signing_key): string {}
function dstu_core_sign_message(string $signing_key, string $message): string {}
function dstu_core_sign_verify(string $verifying_key, string $message, string $signature): bool {}

// --- crypto_sign257 (DSTU 4145 m=257, T-199/T-204) ---
function dstu_core_sign257_keygen(): string {}
function dstu_core_sign257_verifying_key(string $signing_key): string {}
function dstu_core_sign257_message(string $signing_key, string $message): string {}
function dstu_core_sign257_verify(string $verifying_key, string $message, string $signature): bool {}

// --- crypto_pwhash ---
const DSTU_CORE_PWHASH_INTERACTIVE = 0;
const DSTU_CORE_PWHASH_MODERATE = 1;
const DSTU_CORE_PWHASH_SENSITIVE = 2;

function dstu_core_pwhash_hash_password(string $password, int $strength): string {}
function dstu_core_pwhash_verify_password(string $password, string $hash): bool {}

// --- crypto_auth ---
function dstu_core_auth_keygen(): string {}
function dstu_core_auth(string $key, string $message): string {}
function dstu_core_auth_verify(string $key, string $message, string $tag): void {}

// --- crypto_kdf ---
function dstu_core_kdf_keygen(): string {}
function dstu_core_kdf_derive_subkey(string $master_key, int $subkey_id, string $context): string {}

// --- crypto_generichash ---
function dstu_core_generichash_kupyna256(string $message): string {}
function dstu_core_generichash_kupyna512(string $message): string {}

class DstuCoreKupyna256Hasher
{
    public function __construct() {}

    public function update(string $data): void {}

    public function finalize(): string
    {
        return '';
    }
}

class DstuCoreKupyna512Hasher
{
    public function __construct() {}

    public function update(string $data): void {}

    public function finalize(): string
    {
        return '';
    }
}

// --- crypto_stream ---
function dstu_core_stream_keygen(): string {}
function dstu_core_stream_encrypt(string $key, string $plaintext): string {}
function dstu_core_stream_decrypt(string $key, string $sealed): string {}

// --- randombytes ---
function dstu_core_randombytes_buf(int $size): string {}

// --- misc ---
function dstu_core_self_test(): void {}

/** Always throws DstuCoreException carrying $message - see src/error.rs's own doc comment.
 * `lib/DstuCoreSecretStream.php` calls this instead of `throw new DstuCoreException(...)` since
 * that class has no public constructor reachable from pure PHP. */
function dstu_core_throw_error(string $message): never {}

const DSTU_CORE_SECRETSTREAM_TAG_MESSAGE = 0x00;
const DSTU_CORE_SECRETSTREAM_TAG_PUSH = 0x01;
const DSTU_CORE_SECRETSTREAM_TAG_REKEY = 0x02;
const DSTU_CORE_SECRETSTREAM_TAG_FINAL = 0x03;

/** Thrown by every crypto-operation failure this extension can raise - see src/error.rs. Only
 * ever constructed internally (no #[php_impl]) - not constructible from pure PHP. */
class DstuCoreException extends \Exception
{
}

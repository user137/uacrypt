using System.Runtime.InteropServices;

namespace DstuCore.Native;

/// <summary>
/// Raw P/Invoke surface over <c>crates/dstu-core-capi</c>'s <c>dstu_core.h</c> (T-158). Internal -
/// nothing outside <c>DstuCore</c> itself calls these directly; every wrapper class in the parent
/// namespace exposes the idiomatic .NET shape instead (cross-language style guide principle 4/7).
///
/// Uses <see cref="LibraryImportAttribute"/> (source-generated interop), not classic
/// <c>DllImport</c>, specifically because its marshaller requires an explicit
/// <c>[MarshalAs(UnmanagedType.U1)]</c> on every non-blittable <see cref="bool"/> return - the
/// default P/Invoke marshalling for <see cref="bool"/> is the 4-byte Win32 <c>BOOL</c>, while
/// Rust's <c>extern "C" fn() -> bool</c> is a single byte; getting this wrong on
/// <c>dstu_verify</c>/<c>dstu_verify_digest</c> would silently corrupt a signature-verification
/// result rather than fail a test (the .NET analogue of D-151's ARM <c>c_char</c>/<c>i8</c>
/// finding). <c>LibraryImport</c> makes omitting the marshalling attribute a compile error instead
/// of a silent wrong default.
///
/// <c>size_t</c> parameters/out-params are <see cref="nuint"/>, never <see cref="int"/>/
/// <see cref="uint"/> - the header is built with <c>usize_is_size_t = true</c>, so a 32-bit type
/// here would leave the upper half of a 64-bit slot undefined on any 64-bit target.
/// </summary>
internal static partial class NativeMethods
{
    private const string LibName = "dstu_core_capi";

    // ---- crypto_auth ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_auth_key_generate(out AuthKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial AuthKeyHandle dstu_auth_key_from_bytes(byte[] key);

    [LibraryImport(LibName)]
    internal static partial void dstu_auth_key_bytes(AuthKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_auth_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial void dstu_auth(AuthKeyHandle key, byte[]? message, nuint messageLen, byte[] tagOut);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_auth_verify(AuthKeyHandle key, byte[]? message, nuint messageLen, byte[] tag);

    // ---- crypto_box ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_box_secretkey_generate(out BoxSecretKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_box_secretkey_from_bytes(byte[] bytes, out BoxSecretKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial void dstu_box_secretkey_bytes(BoxSecretKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial BoxPublicKeyHandle dstu_box_secretkey_public_key(BoxSecretKeyHandle key);

    [LibraryImport(LibName)]
    internal static partial void dstu_box_secretkey_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_box_publickey_from_bytes(byte[] bytes, out BoxPublicKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial void dstu_box_publickey_bytes(BoxPublicKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_box_publickey_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_box_seal(
        BoxPublicKeyHandle recipient,
        byte[]? message,
        nuint messageLen,
        byte[] sealedOut,
        nuint sealedOutCap,
        out nuint sealedLenOut);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_box_open(
        BoxSecretKeyHandle secret,
        byte[]? sealedIn,
        nuint sealedLen,
        byte[] plaintextOut,
        nuint plaintextOutCap,
        out nuint plaintextLenOut);

    // ---- crypto_generichash ----

    [LibraryImport(LibName)]
    internal static partial void dstu_generichash_256(byte[]? message, nuint messageLen, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_generichash_512(byte[]? message, nuint messageLen, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial Kupyna256HasherHandle dstu_kupyna256_hasher_new();

    [LibraryImport(LibName)]
    internal static partial void dstu_kupyna256_hasher_update(Kupyna256HasherHandle hasher, byte[]? data, nuint len);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_kupyna256_hasher_finalize(Kupyna256HasherHandle hasher, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_kupyna256_hasher_free(IntPtr hasher);

    [LibraryImport(LibName)]
    internal static partial Kupyna512HasherHandle dstu_kupyna512_hasher_new();

    [LibraryImport(LibName)]
    internal static partial void dstu_kupyna512_hasher_update(Kupyna512HasherHandle hasher, byte[]? data, nuint len);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_kupyna512_hasher_finalize(Kupyna512HasherHandle hasher, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_kupyna512_hasher_free(IntPtr hasher);

    // ---- crypto_kdf ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_kdf_master_key_generate(out KdfMasterKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial KdfMasterKeyHandle dstu_kdf_master_key_from_bytes(byte[] key);

    [LibraryImport(LibName)]
    internal static partial void dstu_kdf_master_key_bytes(KdfMasterKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_kdf_master_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial void dstu_kdf_derive_subkey(KdfMasterKeyHandle key, ulong subkeyId, byte[] context, byte[] outBytes);

    // ---- crypto_pwhash ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_pwhash_hash_password(byte[] password, nuint passwordLen, PwhashStrength strength, byte[] outBytes);

    [LibraryImport(LibName)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dstu_pwhash_verify_password(byte[] password, nuint passwordLen, byte[] hash);

    // ---- randombytes ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_randombytes_buf(byte[] buf, nuint len);

    // ---- crypto_secretbox ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretbox_key_generate(out SecretboxKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial SecretboxKeyHandle dstu_secretbox_key_from_bytes(byte[] key);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretbox_key_bytes(SecretboxKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretbox_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretbox_seal(
        SecretboxKeyHandle key,
        byte[]? plaintext,
        nuint plaintextLen,
        byte[] sealedOut,
        nuint sealedOutCap,
        out nuint sealedLenOut);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretbox_open(
        SecretboxKeyHandle key,
        byte[]? sealedIn,
        nuint sealedLen,
        byte[] plaintextOut,
        nuint plaintextOutCap,
        out nuint plaintextLenOut);

    // ---- crypto_secretstream ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretstream_key_generate(out SecretstreamKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial SecretstreamKeyHandle dstu_secretstream_key_from_bytes(byte[] key);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretstream_key_bytes(SecretstreamKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretstream_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretstream_push_init(SecretstreamKeyHandle key, out PushStateHandle handle, byte[] headerOut);

    [LibraryImport(LibName)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dstu_secretstream_push_is_finalized(PushStateHandle state);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretstream_push(
        PushStateHandle state,
        SecretStreamTag tag,
        byte[]? plaintext,
        nuint plaintextLen,
        byte[] ciphertextOut,
        nuint ciphertextOutLen,
        byte[] tagOut);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretstream_push_free(IntPtr state);

    [LibraryImport(LibName)]
    internal static partial PullStateHandle dstu_secretstream_pull_init(SecretstreamKeyHandle key, byte[] header);

    [LibraryImport(LibName)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dstu_secretstream_pull_is_finalized(PullStateHandle state);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_secretstream_pull(
        PullStateHandle state,
        byte tagByte,
        byte[]? ciphertext,
        nuint ciphertextLen,
        byte[] authTag,
        byte[] plaintextOut,
        nuint plaintextOutLen,
        out SecretStreamTag tagOut);

    [LibraryImport(LibName)]
    internal static partial void dstu_secretstream_pull_free(IntPtr state);

    // ---- selftest ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_selftest();

    // ---- crypto_sign ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_sign_key_generate(out SigningKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_sign_key_from_bytes(byte[] d, out SigningKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial void dstu_sign_key_bytes(SigningKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_sign_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial VerifyingKeyHandle dstu_sign_verifying_key(SigningKeyHandle key);

    [LibraryImport(LibName)]
    internal static partial void dstu_verifying_key_to_bytes(VerifyingKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial VerifyingKeyHandle dstu_verifying_key_from_bytes(byte[] bytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_verifying_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial void dstu_sign(SigningKeyHandle key, byte[]? message, nuint messageLen, byte[] sigOut);

    [LibraryImport(LibName)]
    internal static partial void dstu_sign_digest(SigningKeyHandle key, byte[] digest, byte[] sigOut);

    [LibraryImport(LibName)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dstu_verify(VerifyingKeyHandle key, byte[]? message, nuint messageLen, byte[] sig);

    [LibraryImport(LibName)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool dstu_verify_digest(VerifyingKeyHandle key, byte[] digest, byte[] sig);

    // ---- crypto_stream ----

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_stream_key_generate(out StreamKeyHandle handle);

    [LibraryImport(LibName)]
    internal static partial StreamKeyHandle dstu_stream_key_from_bytes(byte[] key);

    [LibraryImport(LibName)]
    internal static partial void dstu_stream_key_bytes(StreamKeyHandle key, byte[] outBytes);

    [LibraryImport(LibName)]
    internal static partial void dstu_stream_key_free(IntPtr key);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_stream_encrypt(
        StreamKeyHandle key,
        byte[]? plaintext,
        nuint plaintextLen,
        byte[] sealedOut,
        nuint sealedOutCap,
        out nuint sealedLenOut);

    [LibraryImport(LibName)]
    internal static partial DstuStatus dstu_stream_decrypt(
        StreamKeyHandle key,
        byte[]? sealedIn,
        nuint sealedLen,
        byte[] plaintextOut,
        nuint plaintextOutCap,
        out nuint plaintextLenOut);
}

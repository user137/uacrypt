using System.Text;
using DstuCore.Native;

namespace DstuCore;

/// <summary>Argon2id password hashing (<c>crypto_pwhash</c>, PHC string format).</summary>
public static class Pwhash
{
    /// <summary>Hashes <paramref name="password"/> into a PHC-formatted string. Throws
    /// <see cref="DstuException"/> on OS CSPRNG or internal Argon2 failure.</summary>
    public static string HashPassword(byte[] password, PwhashStrength strength = PwhashStrength.Interactive)
    {
        ArgumentNullException.ThrowIfNull(password);
        var outBytes = new byte[DstuConstants.PwhashStrBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_pwhash_hash_password(password, (nuint)password.Length, strength, outBytes));
        var nul = Array.IndexOf(outBytes, (byte)0);
        return Encoding.ASCII.GetString(outBytes, 0, nul < 0 ? outBytes.Length : nul);
    }

    /// <summary>Derives a <see cref="DstuConstants.PwhashKeyBytes"/>-byte key from
    /// <paramref name="password"/> and a <see cref="DstuConstants.PwhashSaltBytes"/>-byte
    /// <paramref name="salt"/> - libsodium's <c>crypto_pwhash</c> (Argon2id v1.3), byte for byte
    /// (T-269). Runs on the calling thread. Throws <see cref="DstuException"/> if Argon2 cannot get
    /// its memory.</summary>
    public static byte[] DeriveKey(byte[] password, byte[] salt, PwhashStrength strength = PwhashStrength.Moderate)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length != DstuConstants.PwhashSaltBytes)
        {
            throw new ArgumentException($"salt must be exactly {DstuConstants.PwhashSaltBytes} bytes", nameof(salt));
        }

        var key = new byte[DstuConstants.PwhashKeyBytes];
        NativeStatus.ThrowIfError(NativeMethods.dstu_pwhash_derive_key(password, (nuint)password.Length, salt, strength, key));
        return key;
    }

    /// <summary>Verifies <paramref name="password"/> against a PHC string produced by
    /// <see cref="HashPassword"/>. Returns <c>false</c> for a wrong password or a malformed hash -
    /// there is nothing for a caller to branch differently on between those two cases.</summary>
    public static bool VerifyPassword(byte[] password, string hash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);
        var hashBytes = new byte[Encoding.ASCII.GetByteCount(hash) + 1];
        Encoding.ASCII.GetBytes(hash, 0, hash.Length, hashBytes, 0);
        return NativeMethods.dstu_pwhash_verify_password(password, (nuint)password.Length, hashBytes);
    }
}

using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary>The remaining <c>crypto_*</c> modules, each small enough to share one file:
/// <c>crypto_auth</c> (Kupyna-KMAC), <c>crypto_kdf</c>, <c>crypto_generichash</c> (Kupyna-256/512),
/// <c>crypto_stream</c> (Strumok-256, unauthenticated), <see cref="RandomBytes"/>.</summary>
internal static class MiscExample
{
    public static void Run()
    {
        AuthExample();
        KdfExample();
        GenericHashExample();
        StreamExample();
        RandomBytesExample();
    }

    private static void AuthExample()
    {
        using var key = AuthKey.Generate();
        var message = Encoding.ASCII.GetBytes("a message both parties want to confirm is unmodified");
        var tag = key.Compute(message);
        key.Verify(message, tag);
        Console.WriteLine("auth: tag verified");
    }

    private static void KdfExample()
    {
        using var masterKey = KdfMasterKey.Generate();
        var context = Encoding.ASCII.GetBytes("encrypt_");
        var subkeyA = masterKey.DeriveSubkey(0, context);
        var subkeyB = masterKey.DeriveSubkey(1, context);
        if (subkeyA.SequenceEqual(subkeyB))
        {
            throw new InvalidOperationException("subkeys should differ");
        }

        Console.WriteLine("kdf: subkey 0 and subkey 1 differ, as expected");
    }

    private static void GenericHashExample()
    {
        var message = Encoding.ASCII.GetBytes("hello world");
        var oneShot = GenericHash.Hash256(message);
        using var hasher = new Kupyna256Hasher();
        hasher.Update(Encoding.ASCII.GetBytes("hello "));
        hasher.Update(Encoding.ASCII.GetBytes("world"));
        if (!hasher.Finalize().SequenceEqual(oneShot))
        {
            throw new InvalidOperationException("streaming/one-shot mismatch");
        }

        Console.WriteLine($"generichash: kupyna256(\"hello world\") = {Convert.ToHexString(oneShot).ToLowerInvariant()}");
    }

    private static void StreamExample()
    {
        using var key = StreamCipherKey.Generate();
        var sealedMessage = key.Encrypt(Encoding.ASCII.GetBytes("a message"));
        if (!key.Decrypt(sealedMessage).SequenceEqual(Encoding.ASCII.GetBytes("a message")))
        {
            throw new InvalidOperationException("round trip failed");
        }

        Console.WriteLine("stream: round-tripped (note: unauthenticated, no tamper detection)");
    }

    private static void RandomBytesExample()
    {
        var a = RandomBytes.Buf(16);
        var b = RandomBytes.Buf(16);
        if (a.SequenceEqual(b))
        {
            throw new InvalidOperationException("two independent draws should differ");
        }

        Console.WriteLine($"randombytes: two independent 16-byte draws, e.g. {Convert.ToHexString(a).ToLowerInvariant()}");
    }
}

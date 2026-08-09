using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_sign257</c> (DSTU 4145 `m=257`, T-199/T-204): generate a signing keypair,
/// sign a message, verify it.</summary>
internal static class Sign257Example
{
    public static void Run()
    {
        using var signingKey = SigningKey257.Generate();
        using var verifyingKey = signingKey.VerifyingKey();

        var message = Encoding.ASCII.GetBytes("a message whose origin and integrity matter");
        var signature = signingKey.Sign(message);
        if (!verifyingKey.Verify(message, signature))
        {
            throw new InvalidOperationException("verification failed");
        }

        Console.WriteLine($"signed and verified a {message.Length}-byte message");

        if (!verifyingKey.Verify(Encoding.ASCII.GetBytes("a different message"), signature))
        {
            Console.WriteLine("signature over a different message correctly rejected");
        }
    }
}

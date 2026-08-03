using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_sign</c> (DSTU 4145): generate a signing keypair, sign a message, verify it.</summary>
internal static class SignExample
{
    public static void Run()
    {
        using var signingKey = SigningKey.Generate();
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

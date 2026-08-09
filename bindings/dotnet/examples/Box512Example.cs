using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_box512</c> (`l(p)=512` sibling of `crypto_box`, T-193/T-204): generate a
/// keypair, seal a message to the public key, open it with the secret key.</summary>
internal static class Box512Example
{
    public static void Run()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey(); // safe to share/publish

        var message = Encoding.ASCII.GetBytes("a message for the public key's holder only");
        var sealedMessage = publicKey.Seal(message);
        var opened = secretKey.Open(sealedMessage);
        if (!opened.SequenceEqual(message))
        {
            throw new InvalidOperationException("round trip failed");
        }

        Console.WriteLine($"sealed {opened.Length} bytes -> {sealedMessage.Length} bytes, round-tripped OK");

        sealedMessage[^1] ^= 1;
        try
        {
            secretKey.Open(sealedMessage);
        }
        catch (DstuException)
        {
            Console.WriteLine("tampered ciphertext correctly rejected");
        }
    }
}

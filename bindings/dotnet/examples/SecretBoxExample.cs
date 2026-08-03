using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_secretbox</c>: seal/open a single message with a symmetric key.</summary>
internal static class SecretBoxExample
{
    public static void Run()
    {
        using var key = SecretboxKey.Generate();
        var plaintext = Encoding.ASCII.GetBytes("a message worth protecting");
        var sealedMessage = key.Seal(plaintext);
        var opened = key.Open(sealedMessage);
        if (!opened.SequenceEqual(plaintext))
        {
            throw new InvalidOperationException("round trip failed");
        }

        Console.WriteLine($"sealed {opened.Length} bytes -> {sealedMessage.Length} bytes, round-tripped OK");

        sealedMessage[^1] ^= 1;
        try
        {
            key.Open(sealedMessage);
        }
        catch (DstuException)
        {
            Console.WriteLine("tampered ciphertext correctly rejected");
        }
    }
}

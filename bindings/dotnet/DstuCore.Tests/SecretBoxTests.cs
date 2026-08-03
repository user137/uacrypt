using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_secretbox</c> - correctness (round trip - no official vector exists for this
/// construction, D-51), rejection (tamper/wrong key), misuse (wrong-length key, truncated input).</summary>
public sealed class SecretBoxTests
{
    [Fact]
    public void SealOpenRoundTrips()
    {
        using var key = SecretboxKey.Generate();
        var plaintext = Encoding.ASCII.GetBytes("a message worth protecting");
        var sealedMessage = key.Seal(plaintext);
        Assert.Equal(plaintext, key.Open(sealedMessage));
    }

    [Fact]
    public void SealHandlesEmptyMessage()
    {
        using var key = SecretboxKey.Generate();
        var sealedMessage = key.Seal([]);
        Assert.Empty(key.Open(sealedMessage));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        using var key = SecretboxKey.Generate();
        var sealedMessage = key.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[^1] ^= 1;
        Assert.Throws<DstuException>(() => key.Open(sealedMessage));
    }

    [Fact]
    public void TamperedNonceIsRejected()
    {
        using var key = SecretboxKey.Generate();
        var sealedMessage = key.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[0] ^= 1;
        Assert.Throws<DstuException>(() => key.Open(sealedMessage));
    }

    [Fact]
    public void WrongKeyIsRejected()
    {
        using var key = SecretboxKey.Generate();
        using var otherKey = SecretboxKey.Generate();
        var sealedMessage = key.Seal(Encoding.ASCII.GetBytes("message"));
        Assert.Throws<DstuException>(() => otherKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongLengthKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SecretboxKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void TruncatedSealedInputIsRejected()
    {
        using var key = SecretboxKey.Generate();
        Assert.Throws<DstuException>(() => key.Open(Encoding.ASCII.GetBytes("short")));
    }
}

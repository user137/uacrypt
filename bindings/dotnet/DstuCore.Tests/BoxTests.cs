using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_box</c> - no official vector exists for this composite construction (same
/// posture as <c>crypto_secretbox</c>, D-51/D-169's own "Provenance" section) - correctness
/// (round trip, including a message larger than the 25-byte KEM payload), rejection (tampered
/// wire segments, wrong key), misuse (wrong-length/invalid key encodings, truncated input).</summary>
public sealed class BoxTests
{
    [Fact]
    public void SealOpenRoundTrips()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("a message for the public key's holder only");
        var sealedMessage = publicKey.Seal(message);
        Assert.Equal(message, secretKey.Open(sealedMessage));
    }

    [Fact]
    public void SealHandlesEmptyMessage()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal([]);
        Assert.Empty(secretKey.Open(sealedMessage));
    }

    [Fact]
    public void SealHandlesMessageLargerThanTheKemPayload()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = new byte[10_000];
        Array.Fill(message, (byte)'x');
        var sealedMessage = publicKey.Seal(message);
        Assert.Equal(message, secretKey.Open(sealedMessage));
    }

    [Fact]
    public void TwoSealsUseDifferentEphemeralMaterial()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("same message twice");
        Assert.NotEqual(publicKey.Seal(message), publicKey.Seal(message));
    }

    [Fact]
    public void TamperedKemPrefixIsRejected()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[0] ^= 1;
        Assert.Throws<DstuException>(() => secretKey.Open(sealedMessage));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[^1] ^= 1;
        Assert.Throws<DstuException>(() => secretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongSecretKeyIsRejected()
    {
        using var secretKey = BoxSecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        using var otherSecretKey = BoxSecretKey.Generate();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        Assert.Throws<DstuException>(() => otherSecretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongLengthSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => BoxSecretKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void ZeroSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => BoxSecretKey.FromBytes(new byte[32]));
    }

    [Fact]
    public void WrongLengthPublicKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => BoxPublicKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void DegeneratePublicKeyXIsRejected()
    {
        Assert.Throws<ArgumentException>(() => BoxPublicKey.FromBytes(new byte[32])); // x = 0
    }

    [Fact]
    public void TruncatedSealedInputIsRejected()
    {
        using var secretKey = BoxSecretKey.Generate();
        Assert.Throws<DstuException>(() => secretKey.Open(Encoding.ASCII.GetBytes("short")));
    }
}

using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_box384</c> - `l(p)=384` sibling of <see cref="BoxTests"/> (T-297). No
/// official vector exists for this composite construction (same posture as `crypto_box`) -
/// correctness (round trip), rejection (tampered wire segments, wrong key), misuse (wrong-length/
/// invalid key encodings, truncated input).</summary>
public sealed class Box384Tests
{
    [Fact]
    public void SealOpenRoundTrips()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("a message for the public key's holder only");
        var sealedMessage = publicKey.Seal(message);
        Assert.Equal(message, secretKey.Open(sealedMessage));
    }

    [Fact]
    public void SealHandlesEmptyMessage()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal([]);
        Assert.Empty(secretKey.Open(sealedMessage));
    }

    /// <summary>T-265: a multi-record message opens to exactly its own bytes, no trailing padding.</summary>
    [Fact]
    public void SealHandlesAMultiRecordMessage()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = new byte[20_000];
        Array.Fill(message, (byte)'x');
        Assert.Equal(message, secretKey.Open(publicKey.Seal(message)));
    }

    [Fact]
    public void TwoSealsUseDifferentEphemeralMaterial()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("same message twice");
        Assert.NotEqual(publicKey.Seal(message), publicKey.Seal(message));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[^1] ^= 1;
        Assert.Throws<DstuException>(() => secretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongSecretKeyIsRejected()
    {
        using var secretKey = Box384SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        using var otherSecretKey = Box384SecretKey.Generate();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        Assert.Throws<DstuException>(() => otherSecretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongLengthSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box384SecretKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void ZeroSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box384SecretKey.FromBytes(new byte[DstuConstants.Box384SecretKeyBytes]));
    }

    [Fact]
    public void WrongLengthPublicKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box384PublicKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void DegeneratePublicKeyXIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box384PublicKey.FromBytes(new byte[DstuConstants.Box384PublicKeyBytes])); // x = 0
    }

    [Fact]
    public void TruncatedSealedInputIsRejected()
    {
        using var secretKey = Box384SecretKey.Generate();
        Assert.Throws<DstuException>(() => secretKey.Open(Encoding.ASCII.GetBytes("short")));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site across Box384SecretKey/Box384PublicKey.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "Box384SecretKey.FromBytes(null)", () => { Box384SecretKey.FromBytes(null!); } };
        yield return new object[] { "Box384PublicKey.FromBytes(null)", () => { Box384PublicKey.FromBytes(null!); } };
        var secretKey = Box384SecretKey.Generate();
        var publicKey = secretKey.PublicKey();
        yield return new object[] { "secretKey.Open(null)", () => { secretKey.Open(null!); } };
        yield return new object[] { "publicKey.Seal(null)", () => { publicKey.Seal(null!); } };
    }

    [Theory]
    [MemberData(nameof(NullArgumentCases))]
#pragma warning disable xUnit1026 // description exists only to label this Theory row in test output
    public void NullArgumentThrows(string description, Action action)
#pragma warning restore xUnit1026
    {
        Assert.Throws<ArgumentNullException>(action);
    }
}

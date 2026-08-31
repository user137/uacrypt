using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_box512</c> - `l(p)=512` sibling of <see cref="BoxTests"/> (T-193/T-204). No
/// official vector exists for this composite construction (same posture as `crypto_box`) -
/// correctness (round trip), rejection (tampered wire segments, wrong key), misuse (wrong-length/
/// invalid key encodings, truncated input).</summary>
public sealed class Box512Tests
{
    [Fact]
    public void SealOpenRoundTrips()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("a message for the public key's holder only");
        var sealedMessage = publicKey.Seal(message);
        Assert.Equal(message, secretKey.Open(sealedMessage));
    }

    [Fact]
    public void SealHandlesEmptyMessage()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal([]);
        Assert.Empty(secretKey.Open(sealedMessage));
    }

    [Fact]
    public void TwoSealsUseDifferentEphemeralMaterial()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var message = Encoding.ASCII.GetBytes("same message twice");
        Assert.NotEqual(publicKey.Seal(message), publicKey.Seal(message));
    }

    [Fact]
    public void TamperedCiphertextIsRejected()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        sealedMessage[^1] ^= 1;
        Assert.Throws<DstuException>(() => secretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongSecretKeyIsRejected()
    {
        using var secretKey = Box512SecretKey.Generate();
        using var publicKey = secretKey.PublicKey();
        using var otherSecretKey = Box512SecretKey.Generate();
        var sealedMessage = publicKey.Seal(Encoding.ASCII.GetBytes("message"));
        Assert.Throws<DstuException>(() => otherSecretKey.Open(sealedMessage));
    }

    [Fact]
    public void WrongLengthSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box512SecretKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void ZeroSecretKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box512SecretKey.FromBytes(new byte[DstuConstants.Box512SecretKeyBytes]));
    }

    [Fact]
    public void WrongLengthPublicKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box512PublicKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void DegeneratePublicKeyXIsRejected()
    {
        Assert.Throws<ArgumentException>(() => Box512PublicKey.FromBytes(new byte[DstuConstants.Box512PublicKeyBytes])); // x = 0
    }

    [Fact]
    public void TruncatedSealedInputIsRejected()
    {
        using var secretKey = Box512SecretKey.Generate();
        Assert.Throws<DstuException>(() => secretKey.Open(Encoding.ASCII.GetBytes("short")));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site across Box512SecretKey/Box512PublicKey.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "Box512SecretKey.FromBytes(null)", () => { Box512SecretKey.FromBytes(null!); } };
        yield return new object[] { "Box512PublicKey.FromBytes(null)", () => { Box512PublicKey.FromBytes(null!); } };
        var secretKey = Box512SecretKey.Generate();
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

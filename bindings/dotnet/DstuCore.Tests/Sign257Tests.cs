using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_sign257</c> (DSTU 4145 `m=257`) - `m=257` sibling of <see cref="SignTests"/>
/// (T-199/T-204). Correctness (round trip, determinism of the nonce derivation), rejection (wrong
/// message/wrong key), misuse (invalid signing key - zero/out-of-range, wrong-length key/
/// signature).</summary>
public sealed class Sign257Tests
{
    [Fact]
    public void SignVerifyRoundTrips()
    {
        using var signingKey = SigningKey257.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("a message whose origin and integrity matter");
        var signature = signingKey.Sign(message);
        Assert.True(verifyingKey.Verify(message, signature));
    }

    [Fact]
    public void SigningIsDeterministic()
    {
        using var signingKey = SigningKey257.Generate();
        var message = Encoding.ASCII.GetBytes("same message every time");
        Assert.Equal(signingKey.Sign(message), signingKey.Sign(message));
    }

    [Fact]
    public void WrongMessageIsRejected()
    {
        using var signingKey = SigningKey257.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var signature = signingKey.Sign(Encoding.ASCII.GetBytes("original message"));
        Assert.False(verifyingKey.Verify(Encoding.ASCII.GetBytes("a different message"), signature));
    }

    [Fact]
    public void WrongKeyIsRejected()
    {
        using var signingKey = SigningKey257.Generate();
        using var otherSigningKey = SigningKey257.Generate();
        using var otherVerifyingKey = otherSigningKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("message");
        var signature = signingKey.Sign(message);
        Assert.False(otherVerifyingKey.Verify(message, signature));
    }

    [Fact]
    public void ZeroSigningKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SigningKey257.FromBytes(new byte[DstuConstants.Sign257PrivateKeyBytes]));
    }

    [Fact]
    public void WrongLengthSigningKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SigningKey257.FromBytes(new byte[5]));
    }

    [Fact]
    public void WrongLengthVerifyingKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => VerifyingKey257.FromBytes(new byte[5]));
    }

    [Fact]
    public void WrongLengthSignatureIsRejected()
    {
        using var signingKey = SigningKey257.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        Assert.Throws<ArgumentException>(() => verifyingKey.Verify(Encoding.ASCII.GetBytes("message"), new byte[5]));
    }
}

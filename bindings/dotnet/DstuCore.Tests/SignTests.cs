using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_sign</c> (DSTU 4145) - the official Annex B.1 verify vector is already
/// covered by <see cref="Selftest"/> (<see cref="SelftestTests"/>); this file covers what that
/// single vector doesn't reach: correctness (round trip, determinism of the nonce derivation),
/// rejection (wrong message/wrong key), misuse (invalid signing key - zero/out-of-range,
/// wrong-length key/signature).</summary>
public sealed class SignTests
{
    [Fact]
    public void SignVerifyRoundTrips()
    {
        using var signingKey = SigningKey.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("a message whose origin and integrity matter");
        var signature = signingKey.Sign(message);
        Assert.True(verifyingKey.Verify(message, signature));
    }

    [Fact]
    public void SigningIsDeterministic()
    {
        using var signingKey = SigningKey.Generate();
        var message = Encoding.ASCII.GetBytes("same message every time");
        Assert.Equal(signingKey.Sign(message), signingKey.Sign(message));
    }

    [Fact]
    public void WrongMessageIsRejected()
    {
        using var signingKey = SigningKey.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var signature = signingKey.Sign(Encoding.ASCII.GetBytes("original message"));
        Assert.False(verifyingKey.Verify(Encoding.ASCII.GetBytes("a different message"), signature));
    }

    [Fact]
    public void WrongKeyIsRejected()
    {
        using var signingKey = SigningKey.Generate();
        using var otherSigningKey = SigningKey.Generate();
        using var otherVerifyingKey = otherSigningKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("message");
        var signature = signingKey.Sign(message);
        Assert.False(otherVerifyingKey.Verify(message, signature));
    }

    [Fact]
    public void ZeroSigningKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SigningKey.FromBytes(new byte[DstuConstants.SignPrivateKeyBytes]));
    }

    [Fact]
    public void WrongLengthSigningKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SigningKey.FromBytes(new byte[5]));
    }

    [Fact]
    public void WrongLengthVerifyingKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => VerifyingKey.FromBytes(new byte[5]));
    }

    [Fact]
    public void WrongLengthSignatureIsRejected()
    {
        using var signingKey = SigningKey.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        Assert.Throws<ArgumentException>(() => verifyingKey.Verify(Encoding.ASCII.GetBytes("message"), new byte[5]));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site across SigningKey/VerifyingKey.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "SigningKey.FromBytes(null)", () => { SigningKey.FromBytes(null!); } };
        yield return new object[] { "VerifyingKey.FromBytes(null)", () => { VerifyingKey.FromBytes(null!); } };
        var signingKey = SigningKey.Generate();
        var verifyingKey = signingKey.VerifyingKey();
        var digest = new byte[DstuConstants.SignDigestBytes];
        var sig = new byte[DstuConstants.SignSignatureBytes];
        yield return new object[] { "signingKey.Sign(null)", () => { signingKey.Sign(null!); } };
        yield return new object[] { "signingKey.SignDigest(null)", () => { signingKey.SignDigest(null!); } };
        yield return new object[] { "verifyingKey.Verify(null, sig)", () => { verifyingKey.Verify(null!, sig); } };
        yield return new object[]
        {
            "verifyingKey.Verify(message, null)", () => { verifyingKey.Verify(Encoding.ASCII.GetBytes("m"), null!); }
        };
        yield return new object[] { "verifyingKey.VerifyDigest(null, sig)", () => { verifyingKey.VerifyDigest(null!, sig); } };
        yield return new object[]
        {
            "verifyingKey.VerifyDigest(digest, null)", () => { verifyingKey.VerifyDigest(digest, null!); }
        };
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

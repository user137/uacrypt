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

    // T-217: every ArgumentNullException.ThrowIfNull call site in this class, one Theory.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "FromBytes(null)", () => { SecretboxKey.FromBytes(null!); } };
        var key = SecretboxKey.Generate();
        yield return new object[] { "Seal(null)", () => { key.Seal(null!); } };
        yield return new object[] { "Open(null)", () => { key.Open(null!); } };
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

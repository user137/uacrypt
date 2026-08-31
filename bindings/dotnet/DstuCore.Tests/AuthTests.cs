using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_auth</c> - correctness (round trip), rejection (tampered message, wrong
/// key), misuse (wrong-length key/tag).</summary>
public sealed class AuthTests
{
    [Fact]
    public void VerifyRoundTrips()
    {
        using var key = AuthKey.Generate();
        var message = Encoding.ASCII.GetBytes("a message both parties want to confirm is unmodified");
        var tag = key.Compute(message);
        key.Verify(message, tag);
    }

    [Fact]
    public void TamperedMessageIsRejected()
    {
        using var key = AuthKey.Generate();
        var tag = key.Compute(Encoding.ASCII.GetBytes("original message"));
        Assert.Throws<DstuException>(() => key.Verify(Encoding.ASCII.GetBytes("a different message"), tag));
    }

    [Fact]
    public void WrongKeyIsRejected()
    {
        using var key = AuthKey.Generate();
        using var otherKey = AuthKey.Generate();
        var message = Encoding.ASCII.GetBytes("message");
        var tag = key.Compute(message);
        Assert.Throws<DstuException>(() => otherKey.Verify(message, tag));
    }

    [Fact]
    public void WrongLengthKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => AuthKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void WrongLengthTagIsRejected()
    {
        using var key = AuthKey.Generate();
        Assert.Throws<ArgumentException>(() => key.Verify(Encoding.ASCII.GetBytes("message"), new byte[4]));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site in this class, one Theory.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "FromBytes(null)", () => { AuthKey.FromBytes(null!); } };
        var key = AuthKey.Generate();
        yield return new object[] { "Compute(null)", () => { key.Compute(null!); } };
        yield return new object[] { "Verify(null, tag)", () => { key.Verify(null!, new byte[DstuConstants.AuthTagBytes]); } };
        yield return new object[] { "Verify(message, null)", () => { key.Verify(Encoding.ASCII.GetBytes("m"), null!); } };
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

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
}

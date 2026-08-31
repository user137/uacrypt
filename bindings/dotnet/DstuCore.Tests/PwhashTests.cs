using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_pwhash</c> (Argon2id). Correctness: round trip. Rejection: wrong password,
/// malformed hash string. <see cref="PwhashStrength.Interactive"/> throughout (not the type's own
/// default in other bindings) so this file stays fast - <c>Sensitive</c> alone takes real seconds.</summary>
public sealed class PwhashTests
{
    [Fact]
    public void HashVerifyRoundTrips()
    {
        var password = Encoding.ASCII.GetBytes("correct horse battery staple");
        var stored = Pwhash.HashPassword(password, PwhashStrength.Interactive);
        Assert.True(Pwhash.VerifyPassword(password, stored));
    }

    [Fact]
    public void WrongPasswordIsRejected()
    {
        var stored = Pwhash.HashPassword(Encoding.ASCII.GetBytes("correct horse battery staple"), PwhashStrength.Interactive);
        Assert.False(Pwhash.VerifyPassword(Encoding.ASCII.GetBytes("wrong guess"), stored));
    }

    [Fact]
    public void MalformedHashStringIsRejected()
    {
        Assert.False(Pwhash.VerifyPassword(Encoding.ASCII.GetBytes("anything"), "not a real PHC string"));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site in this class, one Theory.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "HashPassword(null)", () => { Pwhash.HashPassword(null!, PwhashStrength.Interactive); } };
        yield return new object[] { "VerifyPassword(null, hash)", () => { Pwhash.VerifyPassword(null!, "irrelevant"); } };
        yield return new object[]
        {
            "VerifyPassword(password, null)", () => { Pwhash.VerifyPassword(Encoding.ASCII.GetBytes("x"), null!); }
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

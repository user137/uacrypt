using System.Text;
using System.Text.Json;
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

    // T-240: a C# enum can hold any int, so an out-of-range strength reaches the C ABI, which now
    // takes a uint32_t and rejects it instead of reading an invalid Rust enum.
    [Fact]
    public void UnknownStrengthIsAnArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Pwhash.HashPassword(Encoding.ASCII.GetBytes("anything"), (PwhashStrength)7));
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

    private static readonly string VerifyVectorPath = Path.Combine(
        RepoRoot.Path, "crates", "dstu-core", "tests", "vectors", "pwhash", "verify.json");

    public static TheoryData<string, string, string, string> VerifyCases()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VerifyVectorPath));
        var cases = new TheoryData<string, string, string, string>();
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            cases.Add(c.GetProperty("name").GetString()!, c.GetProperty("password").GetString()!,
                c.GetProperty("hash").GetString()!, c.GetProperty("expect").GetString()!);
        }

        return cases;
    }

    /// <summary>T-272/D-222: a crafted hash string returns false instead of aborting the process.</summary>
    [Theory]
    [MemberData(nameof(VerifyCases))]
#pragma warning disable xUnit1026 // name exists only to label this Theory row in test output
    public void SharedVerifyVector(string name, string password, string hash, string expect)
#pragma warning restore xUnit1026
    {
        Assert.Equal(expect == "accept", Pwhash.VerifyPassword(Encoding.UTF8.GetBytes(password), hash));
        Assert.False(Pwhash.VerifyPassword(Encoding.UTF8.GetBytes(password + "x"), hash));
    }
}

using System.Text;
using System.Text.Json;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_generichash</c> (Kupyna-256/512) - correctness against a real official
/// Kupyna-256 vector loaded directly from the same JSON the Rust crate's own tests and
/// <see cref="Selftest"/> use, plus one-shot/streaming agreement. Misuse: finalizing twice.</summary>
public sealed class GenericHashTests
{
    private static readonly string VectorPath = Path.Combine(
        RepoRoot.Path, "crates", "dstu-core", "tests", "vectors", "kupyna", "kupyna-256.json");

    [Fact]
    public void Kupyna256MatchesOfficialVector()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath));
        var firstCase = doc.RootElement.GetProperty("cases")[0];
        var message = Convert.FromHexString(firstCase.GetProperty("message_hex").GetString()!);
        var expected = Convert.FromHexString(firstCase.GetProperty("hash_hex").GetString()!);
        Assert.Equal(expected, GenericHash.Hash256(message));
    }

    [Fact]
    public void StreamingHasherMatchesOneShot256()
    {
        var message = Encoding.ASCII.GetBytes("hello world");
        var whole = GenericHash.Hash256(message);
        using var hasher = new Kupyna256Hasher();
        hasher.Update(Encoding.ASCII.GetBytes("hello "));
        hasher.Update(Encoding.ASCII.GetBytes("world"));
        Assert.Equal(whole, hasher.Finalize());
    }

    [Fact]
    public void StreamingHasherMatchesOneShot512()
    {
        var message = Encoding.ASCII.GetBytes("hello world");
        var whole = GenericHash.Hash512(message);
        using var hasher = new Kupyna512Hasher();
        hasher.Update(Encoding.ASCII.GetBytes("hello "));
        hasher.Update(Encoding.ASCII.GetBytes("world"));
        Assert.Equal(whole, hasher.Finalize());
    }

    [Fact]
    public void FinalizeTwiceIsRejected()
    {
        using var hasher = new Kupyna256Hasher();
        hasher.Update(Encoding.ASCII.GetBytes("data"));
        hasher.Finalize();
        Assert.Throws<InvalidOperationException>(() => hasher.Finalize());
    }

    [Fact]
    public void UpdateAfterFinalizeIsRejected()
    {
        using var hasher = new Kupyna256Hasher();
        hasher.Finalize();
        Assert.Throws<InvalidOperationException>(() => hasher.Update(Encoding.ASCII.GetBytes("more")));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site across GenericHash/Kupyna256Hasher/
    // Kupyna512Hasher.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "GenericHash.Hash256(null)", () => { GenericHash.Hash256(null!); } };
        yield return new object[] { "GenericHash.Hash512(null)", () => { GenericHash.Hash512(null!); } };
        var hasher256 = new Kupyna256Hasher();
        yield return new object[] { "Kupyna256Hasher.Update(null)", () => { hasher256.Update(null!); } };
        var hasher512 = new Kupyna512Hasher();
        yield return new object[] { "Kupyna512Hasher.Update(null)", () => { hasher512.Update(null!); } };
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

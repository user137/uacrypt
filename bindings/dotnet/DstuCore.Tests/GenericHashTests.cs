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
}

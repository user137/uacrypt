using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_stream</c> (Strumok-256 keystream) - <b>no authentication</b>: no rejection
/// category, since <see cref="StreamCipherKey.Decrypt"/> never fails on tampered input, it
/// silently returns different, wrong plaintext instead. Correctness: round trip. Misuse:
/// wrong-length key, truncated input.</summary>
public sealed class StreamCipherTests
{
    [Fact]
    public void EncryptDecryptRoundTrips()
    {
        using var key = StreamCipherKey.Generate();
        var sealedMessage = key.Encrypt(Encoding.ASCII.GetBytes("message"));
        Assert.Equal(Encoding.ASCII.GetBytes("message"), key.Decrypt(sealedMessage));
    }

    [Fact]
    public void TamperingIsNotDetectedButProducesWrongPlaintext()
    {
        using var key = StreamCipherKey.Generate();
        var sealedMessage = key.Encrypt(Encoding.ASCII.GetBytes("message"));
        sealedMessage[^1] ^= 1;
        var garbage = key.Decrypt(sealedMessage);
        Assert.NotEqual(Encoding.ASCII.GetBytes("message"), garbage);
    }

    [Fact]
    public void WrongLengthKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => StreamCipherKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void TruncatedSealedInputIsRejected()
    {
        using var key = StreamCipherKey.Generate();
        Assert.Throws<DstuException>(() => key.Decrypt(Encoding.ASCII.GetBytes("short")));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site in this class, one Theory.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "FromBytes(null)", () => { StreamCipherKey.FromBytes(null!); } };
        var key = StreamCipherKey.Generate();
        yield return new object[] { "Encrypt(null)", () => { key.Encrypt(null!); } };
        yield return new object[] { "Decrypt(null)", () => { key.Decrypt(null!); } };
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

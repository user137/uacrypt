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
}

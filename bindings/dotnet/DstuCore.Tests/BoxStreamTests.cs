using System.Text.Json;
using Xunit;

namespace DstuCore.Tests;

/// <summary>
/// Streaming <c>crypto_box</c>/<c>crypto_box384</c>/<c>crypto_box512</c> (T-265 format v3, T-269, T-297):
/// <see cref="SecretStreamEncryptStream.ForBox"/>/<see cref="SecretStreamDecryptStream.ForBox"/>
/// and the 384/512 pairs over the C ABI's <c>_seal_stream</c>/<c>_open_stream</c>. Happy path: the
/// shared v3 vectors (one-shot <c>Open</c> and the streaming reader), a round trip across record
/// boundaries, one-shot/streaming byte equivalence. Security: tampering, a wrong key, trailing
/// data. Misuse: a cut prefix, the 0.4-0.6 format (reported as an unsupported version even when
/// shorter than a v3 blob - the T-265 "too short" mislabel). Error path: <c>Dispose()</c> without
/// <c>Complete()</c> leaves no <c>Final</c> record (D-118).
/// </summary>
public class BoxStreamTests
{
    private static readonly string VectorDir = Path.Combine(RepoRoot.Path, "crates", "dstu-core", "tests", "vectors", "box");

    public static IEnumerable<object[]> Curves() =>
        new[] { new object[] { 256 }, new object[] { 384 }, new object[] { 512 } };

    private static JsonElement Load(string name) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(VectorDir, name))).RootElement;

    private static byte[] Pattern(int n) => Enumerable.Range(0, n).Select(i => (byte)((i * 31 + 7) % 256)).ToArray();

    /// <summary>One curve's operations behind a common shape, so each test runs on every size.</summary>
    private sealed class Curve : IDisposable
    {
        private readonly BoxSecretKey? _s256;
        private readonly Box384SecretKey? _s384;
        private readonly Box512SecretKey? _s512;

        public Curve(int bits, byte[]? secret = null)
        {
            if (bits == 256)
            {
                _s256 = secret is null ? BoxSecretKey.Generate() : BoxSecretKey.FromBytes(secret);
            }
            else if (bits == 384)
            {
                _s384 = secret is null ? Box384SecretKey.Generate() : Box384SecretKey.FromBytes(secret);
            }
            else
            {
                _s512 = secret is null ? Box512SecretKey.Generate() : Box512SecretKey.FromBytes(secret);
            }
        }

        public byte[] OneShotOpen(byte[] sealedMessage) =>
            _s256 is not null ? _s256.Open(sealedMessage)
            : _s384 is not null ? _s384.Open(sealedMessage)
            : _s512!.Open(sealedMessage);

        public byte[] StreamOpen(byte[] sealedMessage)
        {
            var input = new MemoryStream(sealedMessage);
            using var dec = _s256 is not null
                ? SecretStreamDecryptStream.ForBox(input, _s256)
                : _s384 is not null
                    ? SecretStreamDecryptStream.ForBox384(input, _s384)
                    : SecretStreamDecryptStream.ForBox512(input, _s512!);
            using var output = new MemoryStream();
            dec.CopyTo(output);
            return output.ToArray();
        }

        public SecretStreamEncryptStream Writer(Stream sink)
        {
            if (_s256 is not null)
            {
                using var pk = _s256.PublicKey();
                return SecretStreamEncryptStream.ForBox(sink, pk, leaveOpen: true);
            }

            if (_s384 is not null)
            {
                using var pk384 = _s384.PublicKey();
                return SecretStreamEncryptStream.ForBox384(sink, pk384, leaveOpen: true);
            }

            using var pk512 = _s512!.PublicKey();
            return SecretStreamEncryptStream.ForBox512(sink, pk512, leaveOpen: true);
        }

        public byte[] StreamSeal(byte[] message)
        {
            using var sink = new MemoryStream();
            using (var enc = Writer(sink))
            {
                var first = Math.Min(7, message.Length);
                enc.Write(message, 0, first);
                enc.Write(message, first, message.Length - first);
                enc.Complete();
            }

            return sink.ToArray();
        }

        public void Dispose()
        {
            _s256?.Dispose();
            _s384?.Dispose();
            _s512?.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void SharedV3VectorsGiveTheirExpectedOutcome(int bits)
    {
        var vectors = Load("v3.json");
        using var curve = new Curve(bits, Convert.FromHexString(vectors.GetProperty($"box{bits}_secret_key_hex").GetString()!));
        var seen = 0;
        foreach (var c in vectors.GetProperty("cases").EnumerateArray().Where(c => c.GetProperty("curve").GetInt32() == bits))
        {
            var sealedMessage = Convert.FromHexString(c.GetProperty("sealed_hex").GetString()!);
            if (c.GetProperty("expect").GetString() == "ok")
            {
                var expected = Pattern(c.GetProperty("plaintext_len").GetInt32());
                Assert.Equal(expected, curve.OneShotOpen(sealedMessage));
                Assert.Equal(expected, curve.StreamOpen(sealedMessage));
            }
            else
            {
                Assert.Throws<DstuException>(() => curve.OneShotOpen(sealedMessage));
                Assert.Throws<DstuException>(() => curve.StreamOpen(sealedMessage));
            }

            seen++;
        }

        Assert.True(seen > 0);
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void TheZeroSixFormatIsRefusedAsAnUnsupportedVersion(int bits)
    {
        if (bits == 384)
        {
            // 0.4-0.6 had no l(p)=384 (T-297): a version-2 byte stands in for such a file.
            using var fresh = new Curve(bits);
            var v2 = new byte[DstuConstants.Box384OpenMinOverhead + 10];
            v2[0] = 2;
            Assert.Contains("version", Assert.Throws<DstuException>(() => fresh.OneShotOpen(v2)).Message);
            Assert.Contains("version", Assert.Throws<DstuException>(() => fresh.StreamOpen(v2)).Message);
            return;
        }

        var vectors = Load("legacy_v2.json");
        using var curve = new Curve(bits, Convert.FromHexString(vectors.GetProperty($"box{bits}_secret_key_hex").GetString()!));
        foreach (var c in vectors.GetProperty("cases").EnumerateArray().Where(c => c.GetProperty("curve").GetInt32() == bits))
        {
            var sealedMessage = Convert.FromHexString(c.GetProperty("sealed_hex").GetString()!);
            Assert.Contains("version", Assert.Throws<DstuException>(() => curve.OneShotOpen(sealedMessage)).Message);
            Assert.Contains("version", Assert.Throws<DstuException>(() => curve.StreamOpen(sealedMessage)).Message);
        }
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void StreamRoundTripReadsBackStreamingAndOneShot(int bits)
    {
        using var curve = new Curve(bits);
        foreach (var size in new[] { 0, 1, 8 * 1024, 8 * 1024 + 1, 3 * 8 * 1024 + 5 })
        {
            var message = Pattern(size);
            var sealedMessage = curve.StreamSeal(message);
            Assert.Equal(message, curve.StreamOpen(sealedMessage));
            Assert.Equal(message, curve.OneShotOpen(sealedMessage));
        }
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void TamperingAWrongKeyAndTrailingDataFailClosed(int bits)
    {
        using var curve = new Curve(bits);
        using var other = new Curve(bits);
        var sealedMessage = curve.StreamSeal(Pattern(100));
        Assert.Throws<DstuException>(() => other.StreamOpen(sealedMessage));
        foreach (var index in new[] { 1, sealedMessage.Length / 2, sealedMessage.Length - 1 })
        {
            var bad = (byte[])sealedMessage.Clone();
            bad[index] ^= 1;
            Assert.Throws<DstuException>(() => curve.StreamOpen(bad));
        }

        Assert.Throws<DstuException>(() => curve.StreamOpen([.. sealedMessage, 0]));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void ACutPrefixIsRefusedAsTooShort(int bits)
    {
        using var curve = new Curve(bits);
        var sealedMessage = curve.StreamSeal(Pattern(10));
        foreach (var cut in new[] { 0, 1, 50 })
        {
            var e = Assert.Throws<DstuException>(() => curve.StreamOpen(sealedMessage[..cut]));
            Assert.Contains("too short", e.Message);
        }
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void DisposeWithoutCompleteLeavesNoFinalRecord(int bits)
    {
        using var curve = new Curve(bits);
        using var sink = new MemoryStream();
        using (var enc = curve.Writer(sink))
        {
            enc.Write(Pattern(3 * 8 * 1024), 0, 3 * 8 * 1024);
        }

        Assert.Throws<DstuException>(() => curve.StreamOpen(sink.ToArray()));
    }
}

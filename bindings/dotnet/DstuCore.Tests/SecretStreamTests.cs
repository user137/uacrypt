using System.Diagnostics;
using System.Security.Cryptography;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_secretstream</c> - correctness (round trip across chunk-boundary sizes, plus
/// real byte-for-byte interop with <c>uacrypt encrypt</c>/<c>decrypt</c>'s own wire format),
/// rejection (tamper, oversized chunk, trailing data, truncation), misuse (wrong-length key,
/// write-after-<see cref="SecretStreamEncryptStream.Complete"/>).</summary>
public sealed class SecretStreamTests
{
    private static readonly string[] UacryptCandidates =
    [
        Path.Combine(RepoRoot.Path, "target", "debug", "uacrypt.exe"),
        Path.Combine(RepoRoot.Path, "target", "release", "uacrypt.exe"),
        Path.Combine(RepoRoot.Path, "target", "debug", "uacrypt"),
        Path.Combine(RepoRoot.Path, "target", "release", "uacrypt"),
    ];

    private static string? FindUacrypt() => UacryptCandidates.FirstOrDefault(File.Exists);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(8 * 1024)]
    [InlineData(8 * 1024 + 1)]
    [InlineData(8 * 1024 * 3)]
    [InlineData(8 * 1024 * 3 + 777)]
    public void RoundTripsAcrossChunkBoundaries(int size)
    {
        using var key = SecretstreamKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(size);

        using var encryptedStream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(encryptedStream, key, leaveOpen: true))
        {
            const int step = 777;
            for (var i = 0; i < plaintext.Length; i += step)
            {
                var take = Math.Min(step, plaintext.Length - i);
                enc.Write(plaintext, i, take);
            }

            enc.Complete();
        }

        encryptedStream.Position = 0;
        using var dec = new SecretStreamDecryptStream(encryptedStream, key, leaveOpen: true);
        using var decrypted = new MemoryStream();
        dec.CopyTo(decrypted);
        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public void InteropWithUacryptCli()
    {
        var uacrypt = FindUacrypt();
        if (uacrypt is null)
        {
            return; // uacrypt binary not built (cargo build -p uacrypt) - skip, matching bindings/python's own skipif
        }

        using var tempDir = new TempDirectory();
        using var key = SecretstreamKey.Generate();
        var keyPath = Path.Combine(tempDir.Path, "key.bin");
        File.WriteAllBytes(keyPath, key.ToBytes());
        var plaintext = RandomNumberGenerator.GetBytes(8 * 1024 * 2 + 555);
        var plainPath = Path.Combine(tempDir.Path, "plain.bin");
        File.WriteAllBytes(plainPath, plaintext);

        var netEncryptedPath = Path.Combine(tempDir.Path, "net_encrypted.bin");
        using (var f = File.Create(netEncryptedPath))
        using (var enc = new SecretStreamEncryptStream(f, key))
        {
            enc.Write(plaintext, 0, plaintext.Length);
            enc.Complete();
        }

        var uacryptDecryptedPath = Path.Combine(tempDir.Path, "uacrypt_decrypted.bin");
        RunUacrypt(uacrypt, "decrypt", "--key", keyPath, "--in", netEncryptedPath, "--out", uacryptDecryptedPath);
        Assert.Equal(plaintext, File.ReadAllBytes(uacryptDecryptedPath));

        var uacryptEncryptedPath = Path.Combine(tempDir.Path, "uacrypt_encrypted.bin");
        RunUacrypt(uacrypt, "encrypt", "--key", keyPath, "--in", plainPath, "--out", uacryptEncryptedPath);
        using (var f = File.OpenRead(uacryptEncryptedPath))
        using (var dec = new SecretStreamDecryptStream(f, key))
        using (var decrypted = new MemoryStream())
        {
            dec.CopyTo(decrypted);
            Assert.Equal(plaintext, decrypted.ToArray());
        }
    }

    private static void RunUacrypt(string uacrypt, params string[] args)
    {
        var psi = new ProcessStartInfo(uacrypt)
        {
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"uacrypt failed: {process.StandardError.ReadToEnd()}");
    }

    [Fact]
    public void TamperedChunkIsRejected()
    {
        using var key = SecretstreamKey.Generate();
        using var stream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true))
        {
            enc.Write("secret message"u8.ToArray(), 0, "secret message"u8.Length);
            enc.Complete();
        }

        var data = stream.ToArray();
        data[^1] ^= 1; // last byte of the Final chunk's auth tag
        using var dec = new SecretStreamDecryptStream(new MemoryStream(data), key);
        Assert.Throws<DstuException>(() => dec.CopyTo(new MemoryStream()));
    }

    [Fact]
    public void TruncatedStreamIsRejected()
    {
        using var key = SecretstreamKey.Generate();
        using var stream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true))
        {
            var data = new byte[20000];
            enc.Write(data, 0, data.Length);
            enc.Complete();
        }

        var truncated = stream.ToArray()[..100];
        using var dec = new SecretStreamDecryptStream(new MemoryStream(truncated), key);
        Assert.Throws<DstuException>(() => dec.CopyTo(new MemoryStream()));
    }

    [Fact]
    public void OversizedDeclaredChunkLengthIsRejected()
    {
        using var key = SecretstreamKey.Generate();
        var malicious = new byte[32 + 1 + 4];
        malicious[32] = 0x03; // Final tag
        BitConverter.GetBytes(0xFFFFFFFFu).CopyTo(malicious, 33);
        using var dec = new SecretStreamDecryptStream(new MemoryStream(malicious), key);
        var ex = Assert.Throws<DstuException>(() => dec.CopyTo(new MemoryStream()));
        Assert.Contains("exceeds the maximum", ex.Message);
    }

    [Fact]
    public void TrailingDataAfterFinalIsRejected()
    {
        using var key = SecretstreamKey.Generate();
        using var stream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true))
        {
            enc.Write("msg"u8.ToArray(), 0, "msg"u8.Length);
            enc.Complete();
        }

        stream.Write("unexpected trailing bytes"u8.ToArray());
        var data = stream.ToArray();
        using var dec = new SecretStreamDecryptStream(new MemoryStream(data), key);
        var ex = Assert.Throws<DstuException>(() => dec.CopyTo(new MemoryStream()));
        Assert.Contains("trailing", ex.Message);
    }

    [Fact]
    public void NotCallingCompleteLeavesStreamUnfinalized()
    {
        // D-118: Dispose() never emits a Final chunk (unlike CryptoStream/GZipStream's own
        // close-flushes convention) - C# has no way to distinguish an exception-unwind Dispose from
        // a clean one, so this holds unconditionally, not just on an exception path.
        using var key = SecretstreamKey.Generate();
        using var stream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true))
        {
            enc.Write("chunk one"u8.ToArray(), 0, "chunk one"u8.Length);
            // deliberately no Complete() call
        }

        stream.Position = 0;
        using var dec = new SecretStreamDecryptStream(stream, key, leaveOpen: true);
        Assert.Throws<DstuException>(() => dec.CopyTo(new MemoryStream()));
    }

    [Fact]
    public void WrongLengthKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SecretstreamKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void WriteAfterCompleteIsRejected()
    {
        using var key = SecretstreamKey.Generate();
        using var stream = new MemoryStream();
        using var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true);
        enc.Write("data"u8.ToArray(), 0, "data"u8.Length);
        enc.Complete();
        Assert.Throws<InvalidOperationException>(() => enc.Write("more data"u8.ToArray(), 0, "more data"u8.Length));
    }

    // T-217: every ArgumentNullException.ThrowIfNull call site across SecretstreamKey/
    // SecretStreamEncryptStream/SecretStreamDecryptStream.
    public static IEnumerable<object[]> NullArgumentCases()
    {
        yield return new object[] { "SecretstreamKey.FromBytes(null)", () => { SecretstreamKey.FromBytes(null!); } };
        var key = SecretstreamKey.Generate();

        yield return new object[]
        {
            "new SecretStreamEncryptStream(null, key)",
            () => { using var _ = new SecretStreamEncryptStream(null!, key); }
        };
        yield return new object[]
        {
            "new SecretStreamEncryptStream(stream, null)",
            () => { using var s = new MemoryStream(); using var _ = new SecretStreamEncryptStream(s, null!); }
        };
        yield return new object[]
        {
            "new SecretStreamDecryptStream(null, key)",
            () => { using var _ = new SecretStreamDecryptStream(null!, key); }
        };
        yield return new object[]
        {
            "new SecretStreamDecryptStream(stream, null)",
            () => { using var s = new MemoryStream(); using var _ = new SecretStreamDecryptStream(s, null!); }
        };

        var encryptedStream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(encryptedStream, key, leaveOpen: true))
        {
            enc.Write("data"u8.ToArray(), 0, "data"u8.Length);
            enc.Complete();
        }

        encryptedStream.Position = 0;
        var enc2 = new SecretStreamEncryptStream(new MemoryStream(), key, leaveOpen: true);
        yield return new object[] { "enc.Write(null, 0, 0)", () => { enc2.Write(null!, 0, 0); } };

        var dec2 = new SecretStreamDecryptStream(encryptedStream, key, leaveOpen: true);
        yield return new object[] { "dec.Read(null, 0, 0)", () => { dec2.Read(null!, 0, 0); } };
    }

    [Theory]
    [MemberData(nameof(NullArgumentCases))]
#pragma warning disable xUnit1026 // description exists only to label this Theory row in test output
    public void NullArgumentThrows(string description, Action action)
#pragma warning restore xUnit1026
    {
        Assert.Throws<ArgumentNullException>(action);
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateDirectory(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dstu-core-tests-" + Guid.NewGuid())).FullName;

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}

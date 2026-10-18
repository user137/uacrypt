using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Xunit;

namespace DstuCore.Tests;

/// <summary>
/// Passphrase files (D-219, moved into the core by T-269/D-240):
/// <see cref="SecretStreamEncryptStream.ForPassphrase"/>/<see cref="SecretStreamDecryptStream.ForPassphrase"/>,
/// the same bytes <c>uacrypt encrypt --passphrase-file</c> writes. Argon2 is 256 MiB, t=3 per
/// run, so only the shared-vector test and the uacrypt interop run it; every header refusal stops
/// before Argon2. Mirrors <c>bindings/python/tests/test_passphrase_file.py</c>; the C ABI reports
/// statuses, not the core's own messages, so the messages checked are this binding's.
/// </summary>
public class PassphraseFileTests
{
    private static readonly string Vectors = Path.Combine(RepoRoot.Path, "crates", "dstu-core", "tests", "vectors", "pwhash", "passphrase_file.json");

    private static IEnumerable<JsonElement> Cases(bool argon2) =>
        JsonDocument.Parse(File.ReadAllText(Vectors)).RootElement.GetProperty("cases").EnumerateArray()
            .Where(c => c.GetProperty("argon2").GetBoolean() == argon2).ToList();

    private static byte[] Pattern(int n) => Enumerable.Range(0, n).Select(i => (byte)((i * 31 + 7) % 256)).ToArray();

    private static byte[] Open(byte[] passphrase, byte[] data)
    {
        using var dec = SecretStreamDecryptStream.ForPassphrase(new MemoryStream(data), passphrase);
        using var output = new MemoryStream();
        dec.CopyTo(output);
        return output.ToArray();
    }

    [Fact]
    public void HeaderVectorsAreRefusedBeforeArgon2()
    {
        var messages = new Dictionary<string, string>
        {
            ["not_passphrase_file"] = "unsupported format version",
            ["unsupported_format"] = "unsupported format version",
            ["unsupported_params"] = "Argon2 parameters",
            ["truncated"] = "too short",
        };
        var refused = Cases(false).ToList();
        Assert.Equal(6, refused.Count);
        foreach (var c in refused)
        {
            var e = Assert.Throws<DstuException>(() => Open(
                Convert.FromHexString(c.GetProperty("passphrase_hex").GetString()!),
                Convert.FromHexString(c.GetProperty("sealed_hex").GetString()!)));
            Assert.Contains(messages[c.GetProperty("expect").GetString()!], e.Message);
        }
    }

    [Fact]
    public void FilesWrittenByUacrypt060GiveTheirExpectedOutcome()
    {
        var argon2 = Cases(true).ToList();
        Assert.Equal(4, argon2.Count);
        foreach (var c in argon2)
        {
            var passphrase = Convert.FromHexString(c.GetProperty("passphrase_hex").GetString()!);
            var sealedFile = Convert.FromHexString(c.GetProperty("sealed_hex").GetString()!);
            if (c.GetProperty("expect").GetString() == "ok")
            {
                Assert.Equal(Pattern(c.GetProperty("plaintext_len").GetInt32()), Open(passphrase, sealedFile));
            }
            else
            {
                Assert.Throws<DstuException>(() => Open(passphrase, sealedFile));
            }
        }
    }

    [Fact]
    public void AnEmptyPassphraseIsRefusedOnBothSides()
    {
        Assert.Throws<ArgumentException>(() => SecretStreamEncryptStream.ForPassphrase(new MemoryStream(), []));
        var sealedFile = Convert.FromHexString(Cases(true).First().GetProperty("sealed_hex").GetString()!);
        Assert.Throws<ArgumentException>(() => Open([], sealedFile));
    }

    [Fact]
    public void AKeyEncryptedStreamIsNotAPassphraseFile()
    {
        using var key = SecretstreamKey.Generate();
        using var sink = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(sink, key, leaveOpen: true))
        {
            enc.Write("x"u8.ToArray(), 0, 1);
            enc.Complete();
        }

        Assert.Throws<DstuException>(() => Open("pw"u8.ToArray(), sink.ToArray()));
    }

    private static readonly string[] UacryptCandidates =
    {
        Path.Combine(RepoRoot.Path, "target", "debug", "uacrypt.exe"),
        Path.Combine(RepoRoot.Path, "target", "release", "uacrypt.exe"),
        Path.Combine(RepoRoot.Path, "target", "debug", "uacrypt"),
        Path.Combine(RepoRoot.Path, "target", "release", "uacrypt"),
    };

    private static void RunUacrypt(string uacrypt, params string[] args)
    {
        var psi = new ProcessStartInfo(uacrypt) { RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)!;
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"uacrypt failed: {process.StandardError.ReadToEnd()}");
    }

    [Fact]
    public void InteroperatesWithUacryptInBothDirections()
    {
        var uacrypt = UacryptCandidates.FirstOrDefault(File.Exists);
        if (uacrypt is null)
        {
            return; // uacrypt binary not built (cargo build -p uacrypt) - skip, as SecretStreamTests does
        }

        var dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "dstu-pf-" + Guid.NewGuid())).FullName;
        try
        {
            var message = Pattern(8 * 1024 + 9);
            var passphrase = Encoding.UTF8.GetBytes("спільний пароль");
            var pw = Path.Combine(dir, "pw.txt");
            File.WriteAllBytes(pw, passphrase);

            var ours = Path.Combine(dir, "ours.uac");
            using (var file = File.Create(ours))
            using (var enc = SecretStreamEncryptStream.ForPassphrase(file, passphrase))
            {
                enc.Write(message, 0, message.Length);
                enc.Complete();
            }

            var back = Path.Combine(dir, "ours.back");
            RunUacrypt(uacrypt, "decrypt", "--passphrase-file", pw, "--in", ours, "--out", back);
            Assert.Equal(message, File.ReadAllBytes(back));

            var plain = Path.Combine(dir, "plain.bin");
            File.WriteAllBytes(plain, message);
            var theirs = Path.Combine(dir, "theirs.uac");
            RunUacrypt(uacrypt, "encrypt", "--passphrase-file", pw, "--in", plain, "--out", theirs);
            Assert.Equal(message, Open(passphrase, File.ReadAllBytes(theirs)));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

using System.Text;
using DstuCore;

namespace DstuCore.Examples;

/// <summary><c>crypto_secretstream</c>: encrypt/decrypt a file incrementally, chunk by chunk, via
/// <see cref="SecretStreamEncryptStream"/>/<see cref="SecretStreamDecryptStream"/> (D-118). The
/// wire format matches <c>uacrypt encrypt</c>/<c>decrypt</c> exactly - a file this writes is
/// decryptable by the <c>uacrypt</c> CLI and vice versa.</summary>
internal static class SecretStreamFileExample
{
    public static void Run()
    {
        using var key = SecretstreamKey.Generate();
        var line = Encoding.ASCII.GetBytes("a message spread across more than one 8 KiB chunk\n");
        var plaintext = new byte[line.Length * 1000];
        for (var i = 0; i < 1000; i++)
        {
            line.CopyTo(plaintext, i * line.Length);
        }

        var tempDir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "dstu-core-example-" + Guid.NewGuid()));
        try
        {
            var encryptedPath = Path.Combine(tempDir.FullName, "message.enc");
            var decryptedPath = Path.Combine(tempDir.FullName, "message.dec");

            using (var f = File.Create(encryptedPath))
            using (var enc = new SecretStreamEncryptStream(f, key))
            {
                enc.Write(plaintext, 0, plaintext.Length);
                enc.Complete();
            }

            byte[] recovered;
            using (var f = File.OpenRead(encryptedPath))
            using (var dec = new SecretStreamDecryptStream(f, key))
            using (var recoveredStream = new MemoryStream())
            {
                dec.CopyTo(recoveredStream);
                recovered = recoveredStream.ToArray();
            }

            if (!recovered.SequenceEqual(plaintext))
            {
                throw new InvalidOperationException("round trip failed");
            }

            var encryptedSize = new FileInfo(encryptedPath).Length;
            Console.WriteLine($"{plaintext.Length} bytes -> {encryptedSize} bytes on disk, round-tripped OK");
            File.WriteAllBytes(decryptedPath, recovered);
        }
        finally
        {
            Directory.Delete(tempDir.FullName, recursive: true);
        }
    }
}

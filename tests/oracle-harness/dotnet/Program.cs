// Cross-checks this project's extracted test vectors (crates/dstu-core/tests/vectors/) against
// Bouncy Castle's own Kalyna (Dstu7624Engine) and Kupyna (Dstu7564Digest) implementations, via
// the published BouncyCastle.Cryptography NuGet package - not the vendored partial clone under
// oracles/bouncycastle-dotnet/ (see TASKS.md "Infrastructure" for why).
//
// Note on evidentiary value (see ORACLES.md / DECISIONS.md D-10): Bouncy Castle's Kalyna/Kupyna
// code is itself a port of Roman Oliynykov's C reference, not an independent implementation - a
// pass here mostly re-confirms this project's own PDF vector extraction, not a second independent
// reading of the algorithm. Still worth running: the pdftotext extraction hazards documented in
// ORACLES.md are exactly the kind of error a second consumer of the same vectors can catch.

using System.Text.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

var vectorsDir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..",
    "crates", "dstu-core", "tests", "vectors");
vectorsDir = Path.GetFullPath(vectorsDir);

if (!Directory.Exists(vectorsDir))
{
    Console.Error.WriteLine($"vectors directory not found: {vectorsDir}");
    return 2;
}

int failures = 0;
failures += RunKalyna(Path.Combine(vectorsDir, "kalyna"));
failures += RunKupyna(Path.Combine(vectorsDir, "kupyna"));

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILURE(S)");
return failures == 0 ? 0 : 1;

static int RunKalyna(string dir)
{
    int failures = 0;
    foreach (var file in Directory.GetFiles(dir, "*.json").OrderBy(f => f))
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        var root = doc.RootElement;
        int blockBits = root.GetProperty("block_bits").GetInt32();

        foreach (var testCase in root.GetProperty("cases").EnumerateArray())
        {
            string name = testCase.GetProperty("name").GetString()!;
            byte[] key = Hex.Decode(testCase.GetProperty("key_hex").GetString()!);
            byte[] plaintext = Hex.Decode(testCase.GetProperty("plaintext_hex").GetString()!);
            byte[] ciphertext = Hex.Decode(testCase.GetProperty("ciphertext_hex").GetString()!);

            var engine = new Dstu7624Engine(blockBits);
            bool forEncryption = name == "encryption";
            engine.Init(forEncryption, new KeyParameter(key));

            byte[] input = forEncryption ? plaintext : ciphertext;
            byte[] expected = forEncryption ? ciphertext : plaintext;
            byte[] output = new byte[input.Length];
            engine.ProcessBlock(input, 0, output, 0);

            if (!output.AsSpan().SequenceEqual(expected))
            {
                failures++;
                Console.Error.WriteLine(
                    $"[FAIL] {Path.GetFileName(file)} case={name}: " +
                    $"expected={Hex.ToHexString(expected)} actual={Hex.ToHexString(output)}");
            }
            else
            {
                Console.WriteLine($"[ok] {Path.GetFileName(file)} case={name}");
            }
        }
    }
    return failures;
}

static int RunKupyna(string dir)
{
    int failures = 0;
    foreach (var file in Directory.GetFiles(dir, "*.json").OrderBy(f => f))
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        var root = doc.RootElement;
        int hashBits = root.GetProperty("hash_bits").GetInt32();

        foreach (var testCase in root.GetProperty("cases").EnumerateArray())
        {
            byte[] message = Hex.Decode(testCase.GetProperty("message_hex").GetString() ?? "");
            byte[] expected = Hex.Decode(testCase.GetProperty("hash_hex").GetString()!);

            var digest = new Dstu7564Digest(hashBits);
            digest.BlockUpdate(message, 0, message.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);

            int messageBits = testCase.GetProperty("message_bits").GetInt32();
            if (!output.AsSpan().SequenceEqual(expected))
            {
                failures++;
                Console.Error.WriteLine(
                    $"[FAIL] {Path.GetFileName(file)} message_bits={messageBits}: " +
                    $"expected={Hex.ToHexString(expected)} actual={Hex.ToHexString(output)}");
            }
            else
            {
                Console.WriteLine($"[ok] {Path.GetFileName(file)} message_bits={messageBits}");
            }
        }
    }
    return failures;
}

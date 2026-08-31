using System.Collections.Concurrent;
using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary>
/// T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
/// than assumed. Two shapes, both backed by real concurrent execution (not just a design review):
/// <list type="bullet">
/// <item><description><b>Read-only key types are safe to share across threads.</b>
/// <see cref="VerifyingKey"/>/<see cref="SigningKey"/> wrap an immutable native key through a
/// <see cref="System.Runtime.InteropServices.SafeHandle"/> and every operation on them
/// (<see cref="VerifyingKey.Verify"/>, <see cref="SigningKey.Sign"/>) only reads that key - no
/// caller-visible mutable state exists to race on. Verified below with the SAME instance called
/// concurrently from many threads.</description></item>
/// <item><description><b>Stateful streaming types are NOT safe to share across threads</b> -
/// <see cref="SecretStreamEncryptStream"/>/<see cref="SecretStreamDecryptStream"/> hold an
/// internal buffer and a native push/pull state that advances (nonce/counter) with every call, so
/// concurrent calls on the SAME instance would race on that mutable state with no synchronization
/// anywhere in this wrapper. This binding does not attempt to make them thread-safe (no internal
/// lock) - the supported concurrency model is one stream per thread, each with its own instance.
/// Verified below: many threads, each driving its OWN encrypt/decrypt pair concurrently, all
/// round-trip correctly - deliberately not tested by racing a single shared instance, since that
/// would just be inducing undefined behavior rather than testing a contract.</description></item>
/// </list>
/// </summary>
public sealed class ThreadSafetyTests
{
    [Fact]
    public void ConcurrentVerifyOnSharedKeyIsSafe()
    {
        using var signingKey = SigningKey.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("shared-key concurrent verify");
        var signature = signingKey.Sign(message);

        const int threadCount = 16;
        const int perThread = 200;
        var exceptions = new ConcurrentBag<Exception>();
        var failures = new ConcurrentBag<string>();

        Parallel.For(0, threadCount, _ =>
        {
            try
            {
                for (var i = 0; i < perThread; i++)
                {
                    if (!verifyingKey.Verify(message, signature))
                    {
                        failures.Add("Verify returned false on a valid signature");
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Empty(failures);
    }

    [Fact]
    public void ConcurrentSignOnSharedKeyIsSafe()
    {
        using var signingKey = SigningKey.Generate();
        using var verifyingKey = signingKey.VerifyingKey();
        var message = Encoding.ASCII.GetBytes("shared-key concurrent sign");

        const int threadCount = 16;
        const int perThread = 50;
        var exceptions = new ConcurrentBag<Exception>();
        var failures = new ConcurrentBag<string>();

        Parallel.For(0, threadCount, _ =>
        {
            try
            {
                for (var i = 0; i < perThread; i++)
                {
                    var sig = signingKey.Sign(message);
                    if (!verifyingKey.Verify(message, sig))
                    {
                        failures.Add("a concurrently-produced signature failed to verify");
                    }
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Empty(failures);
    }

    [Fact]
    public void ConcurrentIndependentSecretstreamLoopsAreSafe()
    {
        const int threadCount = 8;
        const int perThreadChunks = 20;
        var exceptions = new ConcurrentBag<Exception>();
        var failures = new ConcurrentBag<string>();

        Parallel.For(0, threadCount, threadIndex =>
        {
            try
            {
                using var key = SecretstreamKey.Generate();
                var chunks = new byte[perThreadChunks][];
                for (var i = 0; i < perThreadChunks; i++)
                {
                    chunks[i] = Encoding.ASCII.GetBytes($"thread {threadIndex} chunk {i}");
                }

                using var stream = new MemoryStream();
                using (var enc = new SecretStreamEncryptStream(stream, key, leaveOpen: true))
                {
                    foreach (var chunk in chunks)
                    {
                        enc.Write(chunk, 0, chunk.Length);
                    }

                    enc.Complete();
                }

                stream.Position = 0;
                using var dec = new SecretStreamDecryptStream(stream, key, leaveOpen: true);
                using var decrypted = new MemoryStream();
                dec.CopyTo(decrypted);

                using var expected = new MemoryStream();
                foreach (var chunk in chunks)
                {
                    expected.Write(chunk, 0, chunk.Length);
                }

                if (!expected.ToArray().AsSpan().SequenceEqual(decrypted.ToArray()))
                {
                    failures.Add($"thread {threadIndex}: round trip mismatch");
                }
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        Assert.Empty(exceptions);
        Assert.Empty(failures);
    }
}

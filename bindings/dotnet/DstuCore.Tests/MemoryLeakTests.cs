using System.Runtime.InteropServices;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary>
/// T-213: FFI memory-leak smoke test. Like the Java binding (not the direct-Rust Python/Node/Ruby/
/// PHP bindings), this binding's <see cref="Native.SecretstreamKeyHandle"/>-family types wrap a
/// native pointer through <c>dstu-core-capi</c>'s C ABI via <see cref="System.Runtime.InteropServices.SafeHandle"/>.
/// Two Windows-local measurement attempts were tried and rejected before this one - documented so a
/// future session doesn't re-try the same two dead ends:
/// <list type="number">
/// <item><description><c>GC.GetTotalMemory</c> - structurally blind, it only reports the managed
/// heap and the native buffer <c>dstu_*_free</c> releases isn't on it at all.</description></item>
/// <item><description><c>Process.GetCurrentProcess().WorkingSet64</c>, sampled in-process (no
/// subprocess spawn, unlike the Java attempt) - still too noisy on this project's own Windows dev
/// machine even with a warmup pass and N=20000: one run showed *negative* growth for a
/// deliberately-never-disposed loop and *positive* growth for the properly-disposed one, backwards
/// from what a real leak would show. GC/JIT/working-set churn dominates the actual (small,
/// per-handle) leak signal.</description></item>
/// </list>
/// Per this project's three-attempts rule (two here plus the same finding already made for the Java
/// binding counts as the pattern, not each language its own fresh three), this uses the one
/// mechanism already confirmed low-noise: <c>/proc/self/status</c>'s <c>VmRSS</c> line, Linux-only,
/// skipped elsewhere (xUnit 2.x has no first-class runtime-conditional skip - an early return is the
/// standard idiom, matching how a genuinely inapplicable-on-this-OS test is handled elsewhere in
/// .NET test suites). Not verified on this project's own Windows dev machine, matching the existing
/// documented precedent for <c>uacrypt_with_peak_rss</c>'s own Linux/macOS paths in the CLI test
/// suite (reviewed, not run, before their first real CI confirmation) and this same T-213 batch's
/// Java binding test.
/// </summary>
public class MemoryLeakTests
{
    private static long CurrentVmRssBytes()
    {
        foreach (var line in File.ReadLines("/proc/self/status"))
        {
            if (line.StartsWith("VmRSS:", StringComparison.Ordinal))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                return long.Parse(parts[1]) * 1024;
            }
        }

        throw new InvalidOperationException("VmRSS line not found in /proc/self/status");
    }

    private static void RunLoop(SecretstreamKey key, BoxSecretKey boxSecret, BoxPublicKey boxPublic, int count)
    {
        for (int i = 0; i < count; i++)
        {
            using var ms = new MemoryStream();
            using (var enc = new SecretStreamEncryptStream(ms, key, leaveOpen: true))
            {
                enc.Write(System.Text.Encoding.UTF8.GetBytes("leak-check chunk"));
                enc.Complete();
            }

            ms.Position = 0;
            using var dec = new SecretStreamDecryptStream(ms, key);
            using var outMs = new MemoryStream();
            dec.CopyTo(outMs);
            Assert.Equal("leak-check chunk", System.Text.Encoding.UTF8.GetString(outMs.ToArray()));

            var sealedMsg = boxPublic.Seal(System.Text.Encoding.UTF8.GetBytes("leak-check message"));
            var opened = boxSecret.Open(sealedMsg);
            Assert.Equal("leak-check message", System.Text.Encoding.UTF8.GetString(opened));
        }
    }

    [Fact]
    public void SecretstreamAndBoxLoopDoesNotLeak()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            // VmRSS-based leak check only runs on Linux - see class doc for why the Windows-local
            // alternatives were rejected. Trivially passes elsewhere rather than asserting
            // something this test can't reliably observe there.
            return;
        }

        const int warmup = 2000;
        const int n = 20000;
        // Comfortable margin above normal .NET GC/JIT churn but far below what N leaked handles
        // would show at this scale - same order of magnitude as the Java binding's own threshold.
        const long maxAcceptableGrowthBytes = 8L * 1024 * 1024;

        using var key = SecretstreamKey.Generate();
        using var boxSecret = BoxSecretKey.Generate();
        using var boxPublic = boxSecret.PublicKey();

        RunLoop(key, boxSecret, boxPublic, warmup);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long before = CurrentVmRssBytes();

        RunLoop(key, boxSecret, boxPublic, n);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long after = CurrentVmRssBytes();
        long growth = after - before;
        Assert.True(
            growth < maxAcceptableGrowthBytes,
            $"VmRSS grew by {growth} bytes over {n} iterations (threshold {maxAcceptableGrowthBytes}) - possible native handle leak");
    }
}

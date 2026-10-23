using System.Runtime.InteropServices;
using DstuCore;
using Xunit;
using Xunit.Abstractions;

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
/// T-311 (D-255): raw VmRSS growth on CI is mostly managed GC retention (+26.80 of +27.68 MB), so
/// the assert is on VmRSS growth minus managed committed growth, each reading after an aggressive
/// compacting collect.
/// </summary>
public class MemoryLeakTests
{
    private readonly ITestOutputHelper _output;

    public MemoryLeakTests(ITestOutputHelper output)
    {
        _output = output;
    }

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

    private const int Warmup = 2000;
    private const int N = 20000;

    // T-311: the assert is on the native remainder (VmRSS growth minus managed committed growth),
    // not raw VmRSS - CI saw +27.68 MB VmRSS of which +26.80 MB was managed committed (GC
    // retention, levels off by n/2). 2 MiB over N iterations is a detection floor of ~105 B per
    // iteration; normal passes stay at 0.14-0.88 MB. The leak control below shows the metric
    // fails on a real native leak.
    private const long MaxNativeRemainderBytes = 2L * 1024 * 1024;

    // T-311: Aggressive decommits what it can at every reading, so committed-but-never-resident
    // slack does not shrink between readings and inflate the remainder (seen on the Pi: committed
    // -2.6 MB, VmRSS -0.9 MB, remainder 1.72 MB with a default collect).
    private static void FullCollect()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
    }

    private readonly record struct Reading(long VmRss, long Committed);

    private static Reading Read() => new(CurrentVmRssBytes(), GC.GetGCMemoryInfo().TotalCommittedBytes);

    private long MeasureNativeRemainder(Action<int> loop)
    {
        loop(Warmup);
        FullCollect();
        var before = Read();

        // T-231: a midpoint reading tells a leak (grows linearly) from allocator/GC retention
        // (levels off).
        loop(N / 2);
        FullCollect();
        var mid = Read();
        loop(N - N / 2);
        FullCollect();
        var after = Read();

        long vmRss = after.VmRss - before.VmRss;
        long committed = after.Committed - before.Committed;
        long remainder = vmRss - committed;
        long midRemainder = (mid.VmRss - before.VmRss) - (mid.Committed - before.Committed);
        // T-231: logged on every run (CI uses the detailed console logger) - data the Pi cannot
        // reproduce.
        _output.WriteLine($"MemoryLeakTests: native remainder {remainder} bytes over {N} iterations (threshold {MaxNativeRemainderBytes}); " +
            $"VmRSS {vmRss}, managed committed {committed}; " +
            $"at n/2: remainder {midRemainder}, VmRSS {mid.VmRss - before.VmRss}, managed committed {mid.Committed - before.Committed}; " +
            $"server GC {System.Runtime.GCSettings.IsServerGC}, {Environment.ProcessorCount} CPUs");
        return remainder;
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

        using var key = SecretstreamKey.Generate();
        using var boxSecret = BoxSecretKey.Generate();
        using var boxPublic = boxSecret.PublicKey();

        long remainder = MeasureNativeRemainder(count => RunLoop(key, boxSecret, boxPublic, count));
        Assert.True(
            remainder < MaxNativeRemainderBytes,
            $"native remainder {remainder} bytes over {N} iterations (threshold {MaxNativeRemainderBytes}) - possible native handle leak");
    }

    /// <summary>
    /// T-311 leak control, run by hand only (<c>DSTU_LEAK_CONTROL=1</c>): the normal loop plus one
    /// never-freed <c>dstu_kupyna512_hasher_new</c> per iteration (~300 B of native payload, ~6 MB
    /// over N, ~3x the threshold). It must fail the threshold, i.e. this test passes when the
    /// metric sees the leak. "Never Dispose" is no control here: <see cref="SafeHandle"/>
    /// finalizers free it (T-231).
    /// </summary>
    [Fact]
    public void LeakControlIsDetected()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            Environment.GetEnvironmentVariable("DSTU_LEAK_CONTROL") != "1")
        {
            return;
        }

        using var key = SecretstreamKey.Generate();
        using var boxSecret = BoxSecretKey.Generate();
        using var boxPublic = boxSecret.PublicKey();

        long remainder = MeasureNativeRemainder(count =>
        {
            RunLoop(key, boxSecret, boxPublic, count);
            for (int i = 0; i < count; i++)
            {
                Assert.NotEqual(IntPtr.Zero, LeakControlNative.dstu_kupyna512_hasher_new());
            }
        });
        Assert.True(
            remainder >= MaxNativeRemainderBytes,
            $"leak control: native remainder {remainder} bytes is under the threshold {MaxNativeRemainderBytes} - the metric missed a real leak");
    }
}

internal static partial class LeakControlNative
{
    [LibraryImport("dstu_core_capi")]
    internal static partial IntPtr dstu_kupyna512_hasher_new();
}

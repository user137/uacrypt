using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary>
/// T-218: <c>crypto_secretstream</c> push/pull with a forced full-generation GC between every
/// caller-level call. <see cref="Native.DstuNativeHandle"/> (see <c>Native/NativeHandles.cs</c>)
/// is a <see cref="System.Runtime.InteropServices.SafeHandle"/> specifically so the CLR's P/Invoke
/// marshaller keeps the handle object alive - and its finalizer/<c>ReleaseHandle</c> from running -
/// for the exact duration of each native call, even when the call is the object's last managed use.
/// This is the stress test that actually exercises that guarantee under GC pressure rather than
/// only trusting it by design review.
/// </summary>
public sealed class GcStressTests
{
    [Fact]
    public void SecretstreamPushPullSurvivesForcedGcBetweenEveryCall()
    {
        const int chunkCount = 40;
        // Larger than DstuConstants.SecretstreamChunkBytes so the loop below crosses several real
        // chunk boundaries (several native push calls, not just one buffered Final).
        var chunks = new byte[chunkCount][];
        for (var i = 0; i < chunkCount; i++)
        {
            chunks[i] = Encoding.ASCII.GetBytes($"gc-stress chunk #{i} " + new string('x', 500));
        }

        using var key = SecretstreamKey.Generate();

        using var encryptedStream = new MemoryStream();
        using (var enc = new SecretStreamEncryptStream(encryptedStream, key, leaveOpen: true))
        {
            foreach (var chunk in chunks)
            {
                enc.Write(chunk, 0, chunk.Length);
                ForceFullCollection();
            }

            enc.Complete();
            ForceFullCollection();
        }

        encryptedStream.Position = 0;
        using var dec = new SecretStreamDecryptStream(encryptedStream, key, leaveOpen: true);
        using var decrypted = new MemoryStream();
        var buffer = new byte[64];
        int read;
        while ((read = dec.Read(buffer, 0, buffer.Length)) > 0)
        {
            decrypted.Write(buffer, 0, read);
            ForceFullCollection();
        }

        using var expected = new MemoryStream();
        foreach (var chunk in chunks)
        {
            expected.Write(chunk, 0, chunk.Length);
        }

        Assert.Equal(expected.ToArray(), decrypted.ToArray());
    }

    private static void ForceFullCollection()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
    }
}

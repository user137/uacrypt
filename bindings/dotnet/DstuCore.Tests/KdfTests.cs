using System.Text;
using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>crypto_kdf</c> - no official vector exists (D-45). Correctness here means
/// determinism/distinctness. Misuse: wrong-length master key/context.</summary>
public sealed class KdfTests
{
    [Fact]
    public void DeriveSubkeyIsDeterministic()
    {
        using var key = KdfMasterKey.Generate();
        var context = Encoding.ASCII.GetBytes("encrypt_");
        Assert.Equal(key.DeriveSubkey(0, context), key.DeriveSubkey(0, context));
    }

    [Fact]
    public void DifferentSubkeyIdGivesDifferentSubkey()
    {
        using var key = KdfMasterKey.Generate();
        var context = Encoding.ASCII.GetBytes("context1");
        Assert.NotEqual(key.DeriveSubkey(0, context), key.DeriveSubkey(1, context));
    }

    [Fact]
    public void DifferentContextGivesDifferentSubkey()
    {
        using var key = KdfMasterKey.Generate();
        Assert.NotEqual(
            key.DeriveSubkey(0, Encoding.ASCII.GetBytes("context1")),
            key.DeriveSubkey(0, Encoding.ASCII.GetBytes("context2")));
    }

    [Fact]
    public void WrongLengthMasterKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => KdfMasterKey.FromBytes(new byte[10]));
    }

    [Fact]
    public void WrongLengthContextIsRejected()
    {
        using var key = KdfMasterKey.Generate();
        Assert.Throws<ArgumentException>(() => key.DeriveSubkey(0, Encoding.ASCII.GetBytes("short")));
    }
}

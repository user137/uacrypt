using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary><c>randombytes</c> - correctness: returns the requested length, two calls are not
/// identical. No rejection/misuse category (a single length parameter).</summary>
public sealed class RandomBytesTests
{
    [Fact]
    public void ReturnsRequestedLength()
    {
        Assert.Equal(32, RandomBytes.Buf(32).Length);
    }

    [Fact]
    public void ZeroLengthReturnsEmpty()
    {
        Assert.Empty(RandomBytes.Buf(0));
    }

    [Fact]
    public void TwoCallsAreNotIdentical()
    {
        Assert.NotEqual(RandomBytes.Buf(32), RandomBytes.Buf(32));
    }
}

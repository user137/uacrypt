using DstuCore;
using Xunit;

namespace DstuCore.Tests;

/// <summary>Correctness gate: <see cref="Selftest.Run"/> re-verifies one official vector per
/// primitive (Kalyna, Kupyna, Strumok, DSTU 4145) against this exact compiled native library -
/// T-161. Every other test file adds its own correctness/rejection/misuse coverage on top of this
/// baseline (D-64/D-65).</summary>
public sealed class SelftestTests
{
    [Fact]
    public void SelftestPasses()
    {
        Selftest.Run();
    }
}

using System.Runtime.CompilerServices;

namespace DstuCore.Tests;

/// <summary>Locates the repo root from this file's own compile-time path (<c>[CallerFilePath]</c>),
/// stable regardless of <c>dotnet test</c>'s working directory - the C# analogue of
/// <c>bindings/python/tests</c>'s own <c>Path(__file__).resolve().parents[3]</c> pattern, used to
/// find the shared JSON vectors under <c>crates/dstu-core/tests/vectors/</c> and the built
/// <c>uacrypt</c> binary without hand-copying either.</summary>
internal static class RepoRoot
{
    public static string Path { get; } = Compute();

    private static string Compute([CallerFilePath] string sourceFile = "")
    {
        // This file lives at bindings/dotnet/DstuCore.Tests/RepoRoot.cs - three levels up is the
        // repo root.
        var dir = System.IO.Path.GetDirectoryName(sourceFile)!;
        return System.IO.Path.GetFullPath(System.IO.Path.Combine(dir, "..", "..", ".."));
    }
}

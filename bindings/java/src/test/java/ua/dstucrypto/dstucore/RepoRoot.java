package ua.dstucrypto.dstucore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Locates the repository root from a test's working directory - Maven always runs a module's
 * tests with the working directory set to that module's own basedir ({@code bindings/java} here),
 * so this walks up from there rather than parsing a {@code getResource().getPath()} URL (which
 * mangles Windows drive-letter paths). Mirrors {@code bindings/dotnet/DstuCore.Tests/RepoRoot.cs}.
 */
final class RepoRoot {
    private RepoRoot() {
    }

    static Path find() {
        Path dir = Paths.get("").toAbsolutePath();
        for (int i = 0; i < 20; i++) {
            if (Files.exists(dir.resolve("docs").resolve("DECISIONS.md"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("could not locate repo root from " + Paths.get("").toAbsolutePath());
    }
}

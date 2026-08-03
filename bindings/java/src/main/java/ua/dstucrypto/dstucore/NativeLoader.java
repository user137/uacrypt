package ua.dstucrypto.dstucore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Loads the native {@code dstu_core_java} library bundled on the classpath under
 * {@code native/<os-arch classifier>/<libname>} (see {@code pom.xml}'s resource-copy step, which
 * places the sibling Rust crate's build output there). Always extracts to a temp file and calls
 * {@link System#load}, never {@link System#loadLibrary} with {@code java.library.path} - a
 * packaged jar has no reliable {@code java.library.path} entry pointing at itself, so this is the
 * only approach that works uniformly in both a dev checkout and an installed dependency.
 */
final class NativeLoader {
    private static volatile boolean loaded = false;

    private NativeLoader() {
    }

    static synchronized void ensureLoaded() {
        if (loaded) {
            return;
        }
        String classifier = detectClassifier();
        String libFileName = System.mapLibraryName("dstu_core_java");
        String resourcePath = "/native/" + classifier + "/" + libFileName;
        try (InputStream in = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new UnsatisfiedLinkError(
                        "native library not found on classpath: " + resourcePath);
            }
            Path tempDir = Files.createTempDirectory("dstu-core-java");
            tempDir.toFile().deleteOnExit();
            Path tempFile = tempDir.resolve(libFileName);
            Files.copy(in, tempFile, StandardCopyOption.REPLACE_EXISTING);
            tempFile.toFile().deleteOnExit();
            System.load(tempFile.toAbsolutePath().toString());
        } catch (IOException e) {
            throw new UnsatisfiedLinkError(
                    "failed to extract native library " + resourcePath + ": " + e.getMessage());
        }
        loaded = true;
    }

    private static String detectClassifier() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

        String osPart;
        if (os.contains("win")) {
            osPart = "windows";
        } else if (os.contains("mac") || os.contains("darwin")) {
            osPart = "osx";
        } else if (os.contains("linux")) {
            osPart = "linux";
        } else {
            throw new UnsatisfiedLinkError("unsupported OS for dstu_core_java: " + os);
        }

        String archPart;
        if (arch.contains("aarch64") || arch.contains("arm64")) {
            archPart = "aarch_64";
        } else if (arch.contains("64")) {
            archPart = "x86_64";
        } else {
            throw new UnsatisfiedLinkError("unsupported architecture for dstu_core_java: " + arch);
        }

        return osPart + "-" + archPart;
    }
}

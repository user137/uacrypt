import ua.dstucrypto.dstucore.SecretStream;
import ua.dstucrypto.dstucore.SecretStreamDecryptor;
import ua.dstucrypto.dstucore.SecretStreamEncryptor;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * {@code crypto_secretstream}: encrypt/decrypt a file incrementally, chunk by chunk, via
 * {@link SecretStreamEncryptor}/{@link SecretStreamDecryptor} (D-118). The wire format matches
 * {@code uacrypt encrypt}/{@code decrypt} exactly - a file this writes is decryptable by the
 * {@code uacrypt} CLI and vice versa.
 */
final class SecretStreamFileExample {
    private SecretStreamFileExample() {
    }

    static void run() throws Exception {
        byte[] key = SecretStream.keygen();
        byte[] line = "a message spread across more than one 8 KiB chunk\n".getBytes("UTF-8");
        byte[] plaintext = new byte[line.length * 1000];
        for (int i = 0; i < 1000; i++) {
            System.arraycopy(line, 0, plaintext, i * line.length, line.length);
        }

        Path tempDir = Files.createTempDirectory("dstu-core-example");
        try {
            Path encryptedPath = tempDir.resolve("message.enc");
            Path decryptedPath = tempDir.resolve("message.dec");

            try (OutputStream fileOut = Files.newOutputStream(encryptedPath);
                    SecretStreamEncryptor enc = new SecretStreamEncryptor(key, fileOut)) {
                enc.write(plaintext);
                enc.complete();
            }

            byte[] recovered;
            try (InputStream fileIn = Files.newInputStream(encryptedPath);
                    SecretStreamDecryptor dec = new SecretStreamDecryptor(key, fileIn)) {
                ByteArrayOutputStream recoveredStream = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = dec.read(buf)) != -1) {
                    recoveredStream.write(buf, 0, n);
                }
                recovered = recoveredStream.toByteArray();
            }

            if (!Arrays.equals(recovered, plaintext)) {
                throw new IllegalStateException("round trip failed");
            }

            long encryptedSize = Files.size(encryptedPath);
            System.out.println(plaintext.length + " bytes -> " + encryptedSize + " bytes on disk, round-tripped OK");
            Files.write(decryptedPath, recovered);
        } finally {
            Files.walk(tempDir)
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> p.toFile().delete());
        }
    }
}

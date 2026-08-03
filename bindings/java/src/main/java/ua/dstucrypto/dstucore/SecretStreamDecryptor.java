package ua.dstucrypto.dstucore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Read-only, streaming {@code crypto_secretstream} pipeline - the decrypting counterpart of
 * {@link SecretStreamEncryptor}. Reads and decrypts one chunk from the underlying stream at a
 * time. Throws {@link DstuException} on authentication failure or truncation - a
 * dropped/tampered/reordered chunk, or a stream that ends before a {@code Final} chunk, both fail
 * closed rather than yielding wrong plaintext.
 *
 * <p>Unlike {@code bindings/python}'s own decryptor, {@link #close} here is <strong>not</strong> a
 * no-op: Python's {@code PullState} is a garbage-collected {@code #[pyclass]} object with nothing
 * for the caller to release explicitly, but this binding's {@link SecretStreamPullState} holds a
 * native handle (D-153's hand-rolled equivalent of a framework-generated wrapper) that must be
 * freed - {@code close()} does that here.
 */
public final class SecretStreamDecryptor extends InputStream {
    private static final int CHUNK_BYTES = 8 * 1024;
    private static final int AUTH_TAG_BYTES = 16;

    private final InputStream in;
    private final SecretStreamPullState pull;
    private byte[] currentChunk = new byte[0];
    private int currentChunkPos = 0;
    private boolean done = false;
    private boolean closed = false;

    public SecretStreamDecryptor(byte[] key, InputStream in) throws IOException {
        this.in = in;
        byte[] header = readExact(in, 32, "header");
        this.pull = new SecretStreamPullState(key, header);
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n == -1 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        while (currentChunkPos >= currentChunk.length) {
            if (done) {
                return -1;
            }
            currentChunk = readNextChunk();
            currentChunkPos = 0;
        }
        int n = Math.min(len, currentChunk.length - currentChunkPos);
        System.arraycopy(currentChunk, currentChunkPos, b, off, n);
        currentChunkPos += n;
        return n;
    }

    private byte[] readNextChunk() throws IOException {
        int tagByte = readExact(in, 1, "chunk tag")[0] & 0xFF;
        byte[] lenBytes = readExact(in, 4, "chunk length");
        int chunkLen = (lenBytes[0] & 0xFF)
                | ((lenBytes[1] & 0xFF) << 8)
                | ((lenBytes[2] & 0xFF) << 16)
                | ((lenBytes[3] & 0xFF) << 24);
        // `chunkLen` is untrusted wire input, read before any tag verification - reject an
        // oversized declared length before acting on it, matching `uacrypt decrypt`'s own
        // `CliError::SecretstreamChunkTooLarge` bound.
        if (chunkLen < 0 || chunkLen > CHUNK_BYTES) {
            throw new DstuException(
                    "secretstream chunk too large: declared " + chunkLen + " bytes, max " + CHUNK_BYTES);
        }
        byte[] ciphertext = readExact(in, chunkLen, "chunk ciphertext");
        byte[] authTag = readExact(in, AUTH_TAG_BYTES, "chunk auth tag");
        SecretStreamPullResult result = pull.pull(tagByte, ciphertext, authTag);
        if (result.tag() == SecretStreamTag.FINAL) {
            // Matches `uacrypt decrypt`'s own `CliError::SecretstreamTrailingData` check - reject
            // bytes remaining after `Final` rather than silently ignoring them.
            if (in.read() != -1) {
                throw new DstuException("trailing data after the secretstream's Final chunk");
            }
            done = true;
        }
        return result.plaintext();
    }

    private static byte[] readExact(InputStream in, int size, String what) throws IOException {
        byte[] data = new byte[size];
        int total = 0;
        while (total < size) {
            int n = in.read(data, total, size - total);
            if (n == -1) {
                break;
            }
            total += n;
        }
        if (total != size) {
            throw new DstuException(
                    "truncated secretstream: expected " + size + " bytes for " + what + ", got " + total);
        }
        return data;
    }

    /** Reads and decrypts the entire remaining stream, bounded only by available memory. */
    public byte[] readAll() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[CHUNK_BYTES];
        int n;
        while ((n = read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** Releases the native pull-state handle. */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        pull.close();
    }
}

package ua.dstucrypto.dstucore;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Read-only, streaming {@code crypto_secretstream} pipeline - the decrypting counterpart of
 * {@link SecretStreamEncryptor}. Reads and decrypts one chunk from the underlying stream at a
 * time. Throws {@link DstuException} on authentication failure, truncation or a malformed file -
 * a dropped/tampered/reordered chunk, or a stream that ends before a {@code Final} chunk, fails
 * closed rather than yielding wrong plaintext. The checks are dstu-core's stream-file codec
 * (T-284); this class only reads. The {@code Final} chunk is returned only once the input is
 * known to end right after it, so a stream with trailing data never yields its last chunk.
 *
 * <p>{@link #close} releases the native handle and closes the source ({@code java.io}'s
 * filter-stream convention, D-220 O-F).
 */
public final class SecretStreamDecryptor extends InputStream {
    static {
        NativeLoader.ensureLoaded();
    }

    private static final int CHUNK_BYTES = SecretStreamEncryptor.CHUNK_BYTES;
    // The version byte and KEM ciphertext in front of a box stream file (D-239), and the
    // passphrase-file header (D-240); the native side refuses any other length.
    private static final int BOX_OPEN_PREFIX_BYTES = 1 + 128;
    private static final int BOX512_OPEN_PREFIX_BYTES = 1 + 256;
    private static final int PASSPHRASE_HEADER_BYTES = 28;

    private final InputStream in;
    private long handle;
    private byte[] currentChunk = new byte[0];
    private int currentChunkPos = 0;
    private boolean done = false;
    private boolean closed = false;

    public SecretStreamDecryptor(byte[] key, InputStream in) throws IOException {
        this(in, nativeNew(key));
    }

    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "streaming decryptor must retain the caller's source to read from it, same as java.io.FilterInputStream")
    private SecretStreamDecryptor(InputStream in, long handle) throws IOException {
        this.in = in;
        this.handle = handle;
        try {
            // The version byte and header, read now so a wrong version fails at construction.
            step();
            step();
        } catch (IOException | RuntimeException e) {
            nativeFree(handle);
            handle = 0;
            throw e;
        }
    }

    /** Reads a {@code crypto_box} stream (or a {@link Box#seal} blob) with bounded memory. */
    public static SecretStreamDecryptor forBox(byte[] secretKey, InputStream in) throws IOException {
        byte[] prefix = readPrefix(in, BOX_OPEN_PREFIX_BYTES, "sealed message");
        return new SecretStreamDecryptor(in, nativeBoxOpen(secretKey, prefix));
    }

    /** {@code crypto_box512} counterpart of {@link #forBox}. */
    public static SecretStreamDecryptor forBox512(byte[] secretKey, InputStream in) throws IOException {
        byte[] prefix = readPrefix(in, BOX512_OPEN_PREFIX_BYTES, "sealed message");
        return new SecretStreamDecryptor(in, nativeBox512Open(secretKey, prefix));
    }

    /**
     * Reads a passphrase file. The header is checked before Argon2 runs (on the calling thread);
     * a wrong passphrase throws {@link DstuException} at the first record.
     */
    public static SecretStreamDecryptor forPassphrase(byte[] passphrase, InputStream in) throws IOException {
        byte[] header = readPrefix(in, PASSPHRASE_HEADER_BYTES, "passphrase file header");
        return new SecretStreamDecryptor(in, nativePassphraseOpen(header, passphrase));
    }

    /** The bytes in front of the stream file; a shorter input cannot be opened at all. */
    private static byte[] readPrefix(InputStream in, int size, String what) throws IOException {
        byte[] prefix = new byte[size];
        int got = 0;
        while (got < size) {
            int n = in.read(prefix, got, size - got);
            if (n == -1) {
                throw new DstuException("input too short to contain a " + what);
            }
            got += n;
        }
        return prefix;
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n == -1 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IllegalStateException("SecretStreamDecryptor already closed");
        }
        if (len == 0) {
            return 0;
        }
        while (currentChunkPos >= currentChunk.length) {
            if (done) {
                return -1;
            }
            currentChunk = step();
            currentChunkPos = 0;
        }
        int n = Math.min(len, currentChunk.length - currentChunkPos);
        System.arraycopy(currentChunk, currentChunkPos, b, off, n);
        currentChunkPos += n;
        return n;
    }

    /**
     * Feeds the codec one {@code nextLen} read: the plaintext that read released (possibly
     * empty), or at end of input the {@code Final} chunk's (after which the stream is done).
     */
    private byte[] step() throws IOException {
        int want = nativeNextLen(handle);
        byte[] data = new byte[want];
        int got = 0;
        while (got < want) {
            int n = in.read(data, got, want - got);
            if (n == -1) {
                break;
            }
            got += n;
        }
        if (got < want) {
            done = true;
            return nativeFinish(handle);
        }
        return nativeFeed(handle, data);
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

    /** Releases the native handle and closes the source. */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        nativeFree(handle);
        handle = 0;
        in.close();
    }

    private static native long nativeNew(byte[] key);

    private static native long nativeBoxOpen(byte[] secretKey, byte[] prefix);

    private static native long nativeBox512Open(byte[] secretKey, byte[] prefix);

    private static native long nativePassphraseOpen(byte[] header, byte[] passphrase);

    private static native int nativeNextLen(long handle);

    private static native byte[] nativeFeed(long handle, byte[] data);

    private static native byte[] nativeFinish(long handle);

    private static native void nativeFree(long handle);
}

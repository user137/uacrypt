package ua.dstucrypto.dstucore;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Write-only, streaming {@code crypto_secretstream} pipeline (D-118, matching
 * {@code bindings/python/python/dstu_core/secretstream.py}'s own step-3 split) - hides
 * header/tag/framing bookkeeping behind {@link #write}. The framing itself (record layout, the
 * 8 KiB rule, {@code Final}) is dstu-core's stream-file codec (T-284); this class only buffers and
 * writes.
 *
 * <p><strong>Wire format matches {@code uacrypt encrypt}/{@code decrypt} exactly</strong> (D-68,
 * D-208): a version byte and a 32-byte header, followed by one record per chunk,
 * {@code tagByte(1) || chunkLenLE(4) || ciphertext(chunkLen) || authTag(16)}. Every record but the
 * {@code Final} one is exactly 8 KiB; the shared vectors in
 * {@code crates/dstu-core/tests/vectors/secretstream-file/} pin this.
 *
 * <p><strong>The sink follows {@code java.io}'s filter-stream convention</strong> (D-220 O-F,
 * T-275): {@link #complete} writes the {@code Final} record and flushes the sink, {@link #flush}
 * flushes it, and {@link #close} closes it. <strong>{@link #close} never finalizes the
 * stream</strong> - only {@link #complete} does. A {@code try}-with-resources {@code close()}
 * cannot see whether the block exited via exception or normally, so finalizing there would turn
 * a failed write into a complete-looking but truncated stream (D-65, D-118). Call
 * {@link #complete} explicitly on every success path. A caller who must keep the sink open
 * wraps it in a stream whose {@code close()} does nothing.
 */
public final class SecretStreamEncryptor extends OutputStream {
    static {
        NativeLoader.ensureLoaded();
    }

    // dstu-core's crypto_secretstream::CHUNK_BYTES (D-208): the codec seals and checks it; this
    // class only needs it to cut input into chunks.
    static final int CHUNK_BYTES = 8 * 1024;
    private static final int FILE_PREFIX_BYTES = 33;
    // The box/passphrase prefix in front of the stream file's own (D-239/D-240); the native side
    // refuses any other length, so a drift fails every test.
    private static final int BOX_SEAL_PREFIX_BYTES = 1 + 128 + FILE_PREFIX_BYTES;
    private static final int BOX512_SEAL_PREFIX_BYTES = 1 + 256 + FILE_PREFIX_BYTES;
    private static final int PASSPHRASE_SEAL_PREFIX_BYTES = 28 + FILE_PREFIX_BYTES;

    private final OutputStream out;
    private long handle;
    private final byte[] buffer = new byte[CHUNK_BYTES];
    private int buffered = 0;
    private boolean completed = false;
    private boolean closed = false;

    // A streaming encryptor's entire purpose is writing to the caller's sink repeatedly over its
    // lifetime (SpotBugs EI_EXPOSE_REP2, T-208) - the same "store the wrapped stream by reference"
    // shape java.io.FilterOutputStream/DeflaterOutputStream use in the JDK itself. There is no
    // meaningful defensive copy of an OutputStream to make here.
    public SecretStreamEncryptor(byte[] key, OutputStream out) throws IOException {
        this(out, startWithKey(key));
    }

    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "streaming encryptor must retain the caller's sink to write to it, same as java.io.FilterOutputStream")
    private SecretStreamEncryptor(OutputStream out, Started started) throws IOException {
        this.out = out;
        this.handle = started.handle;
        try {
            out.write(started.prefix);
        } catch (IOException | RuntimeException e) {
            nativeFree(handle);
            handle = 0;
            throw e;
        }
    }

    /**
     * {@code crypto_box} sealed to {@code publicKey} as a stream (format v3, T-265/T-269): the
     * same bytes {@link Box#seal} returns, written chunk by chunk.
     */
    public static SecretStreamEncryptor forBox(byte[] publicKey, OutputStream out) throws IOException {
        byte[] prefix = new byte[BOX_SEAL_PREFIX_BYTES];
        return new SecretStreamEncryptor(out, new Started(nativeBoxSeal(publicKey, prefix), prefix));
    }

    /** {@code crypto_box512} counterpart of {@link #forBox}. */
    public static SecretStreamEncryptor forBox512(byte[] publicKey, OutputStream out) throws IOException {
        byte[] prefix = new byte[BOX512_SEAL_PREFIX_BYTES];
        return new SecretStreamEncryptor(out, new Started(nativeBox512Seal(publicKey, prefix), prefix));
    }

    /**
     * A passphrase file (D-219/D-240) - the bytes {@code uacrypt encrypt --passphrase} writes.
     * Runs Argon2id (256 MiB, t=3, about a second) on the calling thread before writing anything.
     */
    public static SecretStreamEncryptor forPassphrase(byte[] passphrase, OutputStream out) throws IOException {
        byte[] prefix = new byte[PASSPHRASE_SEAL_PREFIX_BYTES];
        return new SecretStreamEncryptor(out, new Started(nativePassphraseSeal(passphrase, prefix), prefix));
    }

    private static Started startWithKey(byte[] key) {
        byte[] prefix = new byte[FILE_PREFIX_BYTES];
        return new Started(nativeInit(key, prefix), prefix);
    }

    /** A native encryptor handle and the bytes to write before its first record. */
    private static final class Started {
        final long handle;
        final byte[] prefix;

        Started(long handle, byte[] prefix) {
            this.handle = handle;
            this.prefix = prefix;
        }
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    /**
     * Buffers the bytes, sealing every full 8 KiB chunk that is certain not to be the last one.
     * The trailing partial (or exactly-8-KiB) chunk is held back until {@link #complete}, since
     * only {@code complete()} knows no more data is coming. Full chunks are sealed straight from
     * {@code b} by offset, so one large write costs linear time (T-276).
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        checkWritable();
        if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException("off " + off + ", len " + len + ", length " + b.length);
        }
        if (buffered + len <= CHUNK_BYTES) {
            System.arraycopy(b, off, buffer, buffered, len);
            buffered += len;
            return;
        }
        int pos = off;
        int end = off + len;
        if (buffered > 0) {
            int taken = CHUNK_BYTES - buffered;
            System.arraycopy(b, pos, buffer, buffered, taken);
            pos += taken;
            out.write(nativeSealChunk(handle, buffer, 0));
            buffered = 0;
        }
        while (end - pos > CHUNK_BYTES) {
            out.write(nativeSealChunk(handle, b, pos));
            pos += CHUNK_BYTES;
        }
        System.arraycopy(b, pos, buffer, 0, end - pos);
        buffered = end - pos;
    }

    /**
     * Writes the buffered bytes as the stream's {@code Final} record and flushes the sink.
     * Idempotent - safe to call more than once.
     */
    public void complete() throws IOException {
        if (completed) {
            return;
        }
        checkOpen();
        out.write(nativeSealFinal(handle, buffer, buffered));
        buffered = 0;
        completed = true;
        out.flush();
    }

    /** Flushes the sink. Bytes held back for the next record stay buffered. */
    @Override
    public void flush() throws IOException {
        checkOpen();
        out.flush();
    }

    /**
     * Releases the native handle and closes the sink. Does not finalize the stream - see the
     * class doc.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        nativeFree(handle);
        handle = 0;
        out.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("SecretStreamEncryptor already closed");
        }
    }

    private void checkWritable() {
        checkOpen();
        if (completed) {
            throw new IllegalStateException("write after complete()");
        }
    }

    private static native long nativeInit(byte[] key, byte[] prefixOut);

    private static native long nativeBoxSeal(byte[] publicKey, byte[] prefixOut);

    private static native long nativeBox512Seal(byte[] publicKey, byte[] prefixOut);

    private static native long nativePassphraseSeal(byte[] passphrase, byte[] prefixOut);

    private static native byte[] nativeSealChunk(long handle, byte[] src, int offset);

    private static native byte[] nativeSealFinal(long handle, byte[] src, int len);

    private static native void nativeFree(long handle);
}

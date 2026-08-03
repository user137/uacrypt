package ua.dstucrypto.dstucore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Write-only, streaming {@code crypto_secretstream} pipeline (D-118, matching
 * {@code bindings/python/python/dstu_core/secretstream.py}'s own step-3 split) - hides
 * header/tag/framing bookkeeping behind {@link #write}, built in pure Java on top of the raw
 * {@link SecretStreamPushState} the native layer already exposes (step 2).
 *
 * <p><strong>Wire format matches {@code uacrypt encrypt}/{@code decrypt} exactly</strong>
 * ({@code crates/uacrypt/src/lib.rs}'s {@code run_secretstream_encrypt}/
 * {@code run_secretstream_decrypt}, D-68): a 32-byte header followed by one record per chunk,
 * {@code tagByte(1) || chunkLenLE(4) || ciphertext(chunkLen) || authTag(16)}, chunks capped at
 * 8 KiB.
 *
 * <p><strong>{@link #close} never finalizes the stream</strong> - only an explicit call to
 * {@link #complete} pushes the buffered bytes as the {@code Final} chunk. This is the same
 * deliberate deviation from {@code java.util.zip.DeflaterOutputStream}'s own close-flushes
 * convention that T-52/D-152 made for C#'s {@code Dispose()}: a {@code try}-with-resources
 * {@code close()} cannot see whether the block exited via exception or normally, so relying on
 * it to finalize would risk a truncated-but-complete-looking stream if a write partway through
 * throws (violates D-65's "no partial output treated as valid on failure"). Call {@link #complete}
 * explicitly on every success path.
 */
public final class SecretStreamEncryptor extends OutputStream {
    // Matches crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES exactly - required for
    // wire-format interop with `uacrypt encrypt`/`decrypt`, not an independent choice.
    private static final int CHUNK_BYTES = 8 * 1024;

    private final OutputStream out;
    private final SecretStreamPushState push;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private boolean completed = false;
    private boolean closed = false;

    public SecretStreamEncryptor(byte[] key, OutputStream out) throws IOException {
        this.out = out;
        this.push = new SecretStreamPushState(key);
        out.write(push.header());
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    /**
     * Buffers {@code data}, pushing any now-complete 8 KiB chunks immediately. The trailing
     * partial (or exactly-8-KiB) chunk is always held back until {@link #complete}, since only
     * {@code complete()} knows no more data is coming.
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IllegalStateException("write to closed SecretStreamEncryptor");
        }
        buffer.write(b, off, len);
        while (buffer.size() > CHUNK_BYTES) {
            byte[] all = buffer.toByteArray();
            byte[] chunk = Arrays.copyOfRange(all, 0, CHUNK_BYTES);
            byte[] rest = Arrays.copyOfRange(all, CHUNK_BYTES, all.length);
            buffer.reset();
            buffer.write(rest);
            pushChunk(SecretStreamTag.MESSAGE, chunk);
        }
    }

    private void pushChunk(SecretStreamTag tag, byte[] data) throws IOException {
        SecretStreamPushResult result = push.push(tag, data);
        out.write(tag.ordinal());
        out.write(leBytes(data.length));
        out.write(result.ciphertext());
        out.write(result.authTag());
    }

    private static byte[] leBytes(int value) {
        return new byte[] {
                (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24)
        };
    }

    /**
     * Flushes any buffered bytes as the stream's {@code Final} chunk. Idempotent - safe to call
     * more than once.
     */
    public void complete() throws IOException {
        if (completed) {
            return;
        }
        pushChunk(SecretStreamTag.FINAL, buffer.toByteArray());
        buffer.reset();
        completed = true;
    }

    /** Releases the native push-state handle. Does not finalize the stream - see the class doc. */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        push.close();
    }
}

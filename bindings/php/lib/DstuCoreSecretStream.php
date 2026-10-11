<?php

declare(strict_types=1);

/**
 * `crypto_secretstream` idiomatic wrapper (docs/DECISIONS.md D-118, D-143;
 * docs/bindings-strategy.md T-159 step 3) - hides chunk/tag/header bookkeeping behind
 * write()/read(). The framing itself (record layout, length rules, Final, trailing data) is
 * dstu-core's stream-file codec, exposed as DstuCoreSecretStreamFileEncryptor/
 * DstuCoreSecretStreamFileDecryptor (T-284); this file does only I/O.
 *
 * A native PHP stream filter (`stream_filter_register`/`php_user_filter`) was investigated
 * first (docs/DECISIONS.md D-143 has the detail) and rejected: that framework has no clean hook
 * for writing a one-time header before any filtered bytes, and its own internal buffer size does
 * not align with this wire format's fixed 8 KiB chunk boundary - a plain wrapper class matches
 * Python's `SecretStreamEncryptor`/`SecretStreamDecryptor` and Ruby's `SecretStreamWriter`/
 * `SecretStreamReader` instead, this project's own KISS-for-bindings instinct.
 *
 * **Wire format matches `uacrypt encrypt`/`decrypt` exactly**
 * (crates/uacrypt/src/lib.rs's `run_secretstream_encrypt`/`run_secretstream_decrypt`, D-68):
 * a version byte and a 32-byte header, followed by one record per chunk, `tag_byte (1) ||
 * chunk_len_u32_le (4) || ciphertext (chunk_len) || auth_tag (16)`. Every record but the Final one
 * is exactly 8 KiB (SECRETSTREAM_CHUNK_BYTES, part of the format since D-208, not an independent
 * choice) - a file DstuCoreSecretStreamWriter writes is decryptable by `uacrypt decrypt` and vice
 * versa. The shared vectors in crates/dstu-core/tests/vectors/secretstream-file/ pin this.
 */

/**
 * Write-only wrapper: buffers input and pushes each full 8 KiB chunk to the underlying resource
 * as it fills, hiding the header/tag/framing bookkeeping entirely.
 *
 *   $out = fopen('out.bin', 'wb');
 *   DstuCoreSecretStreamWriter::withStream($key, $out, function ($w) {
 *       $w->write('a whole file, incrementally');
 *   });
 *   fclose($out);
 */
final class DstuCoreSecretStreamWriter
{
    public const CHUNK_BYTES = 8192;
    // Matches dstu-core's crypto_secretstream::FORMAT_VERSION (D-208); the shared vectors pin it.
    public const FORMAT_VERSION = 2;

    /** @var resource */
    private $out;
    private DstuCoreSecretStreamFileEncryptor $enc;
    private string $buf = '';
    private bool $closed = false;

    /** @param resource $out */
    public function __construct($key, $out)
    {
        $this->out = $out;
        $this->enc = new DstuCoreSecretStreamFileEncryptor($key);
        $this->writeAll($this->enc->prefix());
    }

    /**
     * Block form: runs $fn with a fresh writer, then closes it - **only on the success path**.
     * The D-118 pitfall this deliberately avoids: PHP's own "always runs, even on error" cleanup
     * idiom (a `finally` block, or `__destruct`) would finalize (emit the Final chunk) even when
     * $fn threw partway through, producing a stream that looks complete but silently drops data -
     * violates D-65's "no partial output treated as valid on failure." There is deliberately no
     * try/finally here: if $fn throws, close() is simply never reached, and the exception
     * propagates to the caller unchanged.
     *
     * @param resource $out
     */
    public static function withStream($key, $out, callable $fn): self
    {
        $writer = new self($key, $out);
        $fn($writer);
        $writer->close();

        return $writer;
    }

    public function isClosed(): bool
    {
        return $this->closed;
    }

    /**
     * Buffers $data, sealing every full 8 KiB chunk that is certain not to be the last one. The
     * trailing partial (or exactly-8-KiB) chunk is held back until close(), since only close()
     * knows no more data is coming - an exact multiple of 8 KiB must end in a full Final record
     * (D-208). Full chunks are cut from $data by offset, so one large write costs linear time
     * (T-276).
     */
    public function write(string $data): int
    {
        if ($this->closed) {
            dstu_core_throw_error('cannot write to a closed stream');
        }

        $size = strlen($data);
        $pos = $this->topUpBuffer($data);
        while ($size - $pos > self::CHUNK_BYTES) {
            $this->writeAll($this->enc->seal_chunk(substr($data, $pos, self::CHUNK_BYTES)));
            $pos += self::CHUNK_BYTES;
        }
        $this->buf .= substr($data, $pos);

        return $size;
    }

    /**
     * Writes any buffered bytes as the stream's Final record. Idempotent - safe to call more than
     * once, matching normal PHP resource-close semantics.
     */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }

        $this->writeAll($this->enc->seal_final($this->buf));
        $this->buf = '';
        $this->closed = true;
    }

    /**
     * Adds $data to the held-back chunk if it all fits; otherwise tops that chunk up to a full one
     * and seals it, since more data follows. Returns how many bytes of $data it consumed.
     */
    private function topUpBuffer(string $data): int
    {
        if ($this->buf === '') {
            return 0;
        }
        if (strlen($this->buf) + strlen($data) <= self::CHUNK_BYTES) {
            $this->buf .= $data;

            return strlen($data);
        }
        $taken = self::CHUNK_BYTES - strlen($this->buf);
        $this->writeAll($this->enc->seal_chunk($this->buf . substr($data, 0, $taken)));
        $this->buf = '';

        return $taken;
    }

    /**
     * T-274: a failed or short write throws instead of leaving a corrupt stream behind a normal
     * return (fwrite() alone only raises a notice). The notice itself is suppressed: this
     * exception replaces it. Nothing more is written after a failure, so no Final follows it.
     */
    private function writeAll(string $bytes): void
    {
        $written = @fwrite($this->out, $bytes);
        if ($written !== strlen($bytes)) {
            $got = $written === false ? 'failed' : "wrote {$written} of " . strlen($bytes) . ' bytes';
            dstu_core_throw_error("secretstream: write to the output stream {$got}");
        }
    }
}

/**
 * Read-only, chunk-iterating wrapper: reads and decrypts one chunk from the underlying resource
 * at a time. Implements PHP's `Iterator` so `foreach ($reader as $chunk)` works directly -
 * forward-only, like a real stream; `rewind()` is only valid before iteration starts (mirrors
 * `\Generator`'s own restriction, the closest stdlib precedent for a forward-only iterator).
 * `readAll()` joins every plaintext chunk into one string, bounded only by available memory (the
 * same caveat `crypto_secretbox` already carries). Throws `DstuCoreException` on authentication
 * failure or truncation - a dropped/tampered/reordered chunk, or a stream that ends before a
 * Final chunk, both fail closed rather than yielding wrong plaintext.
 *
 *   $in = fopen('out.bin', 'rb');
 *   $plaintext = DstuCoreSecretStreamReader::withStream($key, $in, fn ($r) => $r->readAll());
 *   fclose($in);
 */
final class DstuCoreSecretStreamReader implements Iterator
{
    /** @var resource */
    private $inp;
    private DstuCoreSecretStreamFileDecryptor $dec;
    private bool $done = false;
    private bool $started = false;
    private bool $hasCurrent = false;
    private ?string $current = null;
    private int $index = -1;

    /** @param resource $inp */
    public function __construct($key, $inp)
    {
        $this->inp = $inp;
        $this->dec = new DstuCoreSecretStreamFileDecryptor($key);
        // The version byte and header, read now so a wrong version fails at construction.
        $this->step();
        $this->step();
    }

    /** @param resource $inp */
    public static function withStream($key, $inp, callable $fn): mixed
    {
        return $fn(new self($key, $inp));
    }

    public function readAll(): string
    {
        $chunks = [];
        foreach ($this as $chunk) {
            $chunks[] = $chunk;
        }

        return implode('', $chunks);
    }

    // --- Iterator ---

    public function rewind(): void
    {
        if ($this->started) {
            dstu_core_throw_error('DstuCoreSecretStreamReader is forward-only, cannot rewind once started');
        }
        $this->started = true;
        $this->advance();
    }

    public function valid(): bool
    {
        return $this->hasCurrent;
    }

    public function current(): string
    {
        return $this->current ?? '';
    }

    public function key(): int
    {
        return $this->index;
    }

    public function next(): void
    {
        $this->advance();
    }

    // Steps the codec until a read releases plaintext, or the stream ends. `hasCurrent` stays true
    // for the last chunk so `foreach` still processes it; the following advance() sees `$done`
    // and ends iteration.
    private function advance(): void
    {
        while (!$this->done) {
            $plaintext = $this->step();
            if ($plaintext !== '') {
                $this->index++;
                $this->current = $plaintext;
                $this->hasCurrent = true;

                return;
            }
        }
        $this->hasCurrent = false;
        $this->current = null;
    }

    /**
     * Feeds the codec one next_len() read: the plaintext that read released (possibly empty), or
     * at end of input the Final chunk's (after which the stream is done).
     */
    private function step(): string
    {
        $want = $this->dec->next_len();
        $data = '';
        while (strlen($data) < $want) {
            $piece = fread($this->inp, $want - strlen($data));
            if ($piece === false || $piece === '') {
                break;
            }
            $data .= $piece;
        }
        if (strlen($data) < $want) {
            $this->done = true;

            return $this->dec->finish();
        }

        return $this->dec->feed($data);
    }
}

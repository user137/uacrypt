<?php

declare(strict_types=1);

/**
 * `crypto_secretstream` idiomatic wrapper (docs/DECISIONS.md D-118, D-143;
 * docs/bindings-strategy.md T-159 step 3) - hides chunk/tag/header bookkeeping behind
 * write()/read(), built in pure PHP on top of the low-level DstuCoreSecretStreamPushState/
 * PullState the compiled extension already exposes (step 2), rather than new Rust glue.
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
 * a 32-byte header followed by one record per chunk, `tag_byte (1) || chunk_len_u32_le (4) ||
 * ciphertext (chunk_len) || auth_tag (16)`, chunks capped at 8 KiB (matching
 * SECRETSTREAM_CHUNK_BYTES, not an independent choice) - a file DstuCoreSecretStreamWriter writes
 * is decryptable by `uacrypt decrypt` and vice versa.
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

    /** @var resource */
    private $out;
    private DstuCoreSecretStreamPushState $push;
    private string $buf = '';
    private bool $closed = false;

    /** @param resource $out */
    public function __construct($key, $out)
    {
        $this->out = $out;
        $this->push = new DstuCoreSecretStreamPushState($key);
        fwrite($this->out, $this->push->header());
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
     * Buffers $data, pushing any now-complete 8 KiB chunks immediately. The trailing partial (or
     * exactly-8-KiB) chunk is always held back until close(), since only close() knows no more
     * data is coming - the same one-chunk-ahead reasoning `uacrypt encrypt` itself uses to tag the
     * true last chunk Final, not an extra empty one after it.
     */
    public function write(string $data): int
    {
        if ($this->closed) {
            dstu_core_throw_error('cannot write to a closed stream');
        }

        $this->buf .= $data;
        while (strlen($this->buf) > self::CHUNK_BYTES) {
            $this->pushChunk(DSTU_CORE_SECRETSTREAM_TAG_MESSAGE, substr($this->buf, 0, self::CHUNK_BYTES));
            $this->buf = substr($this->buf, self::CHUNK_BYTES);
        }

        return strlen($data);
    }

    /**
     * Flushes any buffered bytes as the stream's Final chunk. Idempotent - safe to call more than
     * once, matching normal PHP resource-close semantics.
     */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }

        $this->pushChunk(DSTU_CORE_SECRETSTREAM_TAG_FINAL, $this->buf);
        $this->buf = '';
        $this->closed = true;
    }

    private function pushChunk(int $tag, string $data): void
    {
        [$ciphertext, $authTag] = $this->push->push($tag, $data);
        fwrite($this->out, pack('C', $tag));
        fwrite($this->out, pack('V', strlen($data)));
        fwrite($this->out, $ciphertext);
        fwrite($this->out, $authTag);
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
    private const AUTH_TAG_BYTES = 16;

    /** @var resource */
    private $inp;
    private DstuCoreSecretStreamPullState $pull;
    private bool $done = false;
    private bool $started = false;
    private bool $hasCurrent = false;
    private ?string $current = null;
    private int $index = -1;

    /** @param resource $inp */
    public function __construct($key, $inp)
    {
        $this->inp = $inp;
        $header = $this->readExact(32, 'header');
        $this->pull = new DstuCoreSecretStreamPullState($key, $header);
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

    // Yields the current chunk, marking `$done` on the *same* call that yields the Final chunk -
    // `hasCurrent` stays true for that last chunk so `foreach` still processes it; only the
    // *following* `advance()` call (triggered by `foreach`'s own `next()`) sees `$done` and clears
    // `hasCurrent`, ending iteration. Standard forward-only-iterator shape.
    private function advance(): void
    {
        if ($this->done) {
            $this->hasCurrent = false;
            $this->current = null;

            return;
        }

        $tagByte = ord($this->readExact(1, 'chunk tag'));
        $chunkLen = unpack('V', $this->readExact(4, 'chunk length'))[1];
        // $chunkLen is untrusted wire input, read before any tag verification - reject an
        // oversized declared length before acting on it (matches `uacrypt decrypt`'s own
        // CliError::SecretstreamChunkTooLarge bound, crates/uacrypt/src/lib.rs).
        if ($chunkLen > DstuCoreSecretStreamWriter::CHUNK_BYTES) {
            dstu_core_throw_error(
                "secretstream chunk too large: declared {$chunkLen} bytes, max " . DstuCoreSecretStreamWriter::CHUNK_BYTES
            );
        }
        $ciphertext = $this->readExact($chunkLen, 'chunk ciphertext');
        $authTag = $this->readExact(self::AUTH_TAG_BYTES, 'chunk auth tag');
        [$tag, $plaintext] = $this->pull->pull($tagByte, $ciphertext, $authTag);

        if ($tag === DSTU_CORE_SECRETSTREAM_TAG_FINAL) {
            // Matches `uacrypt decrypt`'s own CliError::SecretstreamTrailingData check - reject
            // bytes remaining after Final rather than silently ignoring them. A single fread()
            // call: EOF returns '' or false, either way meaning "no trailing data."
            $trailing = fread($this->inp, 1);
            if ($trailing !== false && $trailing !== '') {
                dstu_core_throw_error("trailing data after the secretstream's Final chunk");
            }
            $this->done = true;
        }

        $this->index++;
        $this->current = $plaintext;
        $this->hasCurrent = true;
    }

    private function readExact(int $size, string $what): string
    {
        if ($size === 0) {
            return '';
        }
        $data = '';
        $remaining = $size;
        while ($remaining > 0) {
            $piece = fread($this->inp, $remaining);
            if ($piece === false || $piece === '') {
                break;
            }
            $data .= $piece;
            $remaining -= strlen($piece);
        }
        if (strlen($data) !== $size) {
            dstu_core_throw_error("truncated secretstream: expected {$size} bytes for {$what}, got " . strlen($data));
        }

        return $data;
    }
}

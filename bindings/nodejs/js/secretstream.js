'use strict';

/**
 * Idiomatic `crypto_secretstream` pipeline (docs/DECISIONS.md D-118, docs/bindings-strategy.md
 * T-50 step 3) - hides chunk/tag/length-prefix bookkeeping behind a `stream.Transform` pair, built
 * in pure JS on top of the low-level SecretStreamPushState/SecretStreamPullState the native addon
 * already exposes (step 2), rather than new Rust glue. Mirrors
 * bindings/python/python/dstu_core/secretstream.py's own design exactly (see D-118's two
 * standing pitfalls this port re-checks below).
 *
 * Wire format matches `uacrypt encrypt`/`decrypt` exactly (crates/uacrypt/src/lib.rs's
 * run_secretstream_encrypt/run_secretstream_decrypt, D-68): `header (32 bytes)` followed by one
 * record per chunk, `tagByte (1) || chunkLenU32LE (4) || ciphertext (chunkLen) || authTag (16)`,
 * chunks capped at 8 KiB (matching SECRETSTREAM_CHUNK_BYTES, not an independent choice).
 */

const { Transform } = require('node:stream');
const native = require('../native/index.js');

// Matches crates/uacrypt/src/lib.rs's SECRETSTREAM_CHUNK_BYTES exactly - required for wire-format
// interop with `uacrypt encrypt`/`decrypt`, not an independent choice.
const CHUNK_BYTES = 8 * 1024;
const AUTH_TAG_BYTES = 16;

/**
 * Write-only Transform: buffers input and pushes each full 8 KiB chunk downstream as it fills,
 * hiding the header/tag/framing bookkeeping entirely.
 *
 * Usage: `fs.createReadStream(inPath).pipe(new SecretStreamEncryptor(key)).pipe(fs.createWriteStream(outPath))`
 *
 * D-118 pitfall check #1: this class deliberately overrides only `_flush`, not `_destroy`, to
 * emit the Final chunk. Node's stream machinery calls `_flush` only when the writable side ends
 * gracefully (`.end()`) - never on `destroy()`/an upstream error, which instead skips straight to
 * `_destroy`. So a pipeline that errors partway leaves the output stream without a Final chunk,
 * and `SecretStreamDecryptor` reading that truncated output fails closed in `_flush` ("stream
 * ended before a Final chunk") rather than silently accepting a complete-looking but truncated
 * file - matching this project's standing "no partial output treated as valid on failure" rule
 * (D-65), the same property Python's own `__exit__` had to be fixed to provide (T-49 step 3).
 */
class SecretStreamEncryptor extends Transform {
  constructor(key, options) {
    super(options);
    this._pushState = new native.SecretStreamPushState(key);
    this._buf = Buffer.alloc(0);
    this.push(this._pushState.header);
  }

  _pushChunk(tag, data) {
    const { ciphertext, authTag } = this._pushState.push(tag, data);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32LE(data.length, 0);
    this.push(Buffer.concat([Buffer.from([tag]), lenBuf, ciphertext, authTag]));
  }

  _transform(chunk, _encoding, callback) {
    this._buf = Buffer.concat([this._buf, chunk]);
    let err;
    try {
      while (this._buf.length > CHUNK_BYTES) {
        const piece = this._buf.subarray(0, CHUNK_BYTES);
        this._buf = this._buf.subarray(CHUNK_BYTES);
        this._pushChunk(native.SECRETSTREAM_TAG_MESSAGE, piece);
      }
    } catch (e) {
      err = e;
    }
    // Deferred via process.nextTick, not called synchronously: Node's own stream docs warn that
    // invoking _transform's callback synchronously (this method never actually awaits any I/O)
    // makes an error passed to it throw synchronously out of the triggering write() call instead
    // of emitting 'error' asynchronously the documented way - confirmed the hard way, a real
    // deadlock/uncaught-throw found running this suite under node:test, not a defensive guess.
    process.nextTick(callback, err);
  }

  _flush(callback) {
    let err;
    try {
      this._pushChunk(native.SECRETSTREAM_TAG_FINAL, this._buf);
      this._buf = Buffer.alloc(0);
    } catch (e) {
      err = e;
    }
    process.nextTick(callback, err);
  }
}

/**
 * Read-only Transform: parses and decrypts one chunk at a time from arbitrarily-chunked input,
 * emitting plaintext downstream. Errors (via the stream's `'error'` event) on authentication
 * failure or truncation - a dropped/tampered/reordered chunk, or a stream that ends before a
 * Final chunk, both fail closed rather than yielding wrong plaintext.
 *
 * D-118 pitfall check #2: `chunkLen` is untrusted wire input, read before any tag verification -
 * rejected here the moment it is parsed (before ever buffering up to its declared length), the
 * same `CliError::SecretstreamChunkTooLarge` bound `uacrypt decrypt` enforces
 * (crates/uacrypt/src/lib.rs) and Python's own reader re-checked (T-49 step 3). Bytes remaining
 * after the Final chunk are rejected too (`CliError::SecretstreamTrailingData`'s equivalent),
 * checked both as more input arrives (`_transform`) and at end-of-stream (`_flush`) so trailing
 * data appended in the same write as the Final chunk, or arriving in a later write, is caught
 * either way - not just the case naive testing would think to check first.
 */
class SecretStreamDecryptor extends Transform {
  constructor(key, options) {
    super(options);
    this._key = key;
    this._pullState = null;
    this._buf = Buffer.alloc(0);
    this._done = false;
  }

  _transform(chunk, _encoding, callback) {
    this._buf = Buffer.concat([this._buf, chunk]);
    let err;
    try {
      this._drain();
    } catch (e) {
      err = e;
    }
    // See SecretStreamEncryptor._transform's comment - same synchronous-callback pitfall applies.
    process.nextTick(callback, err);
  }

  _drain() {
    if (!this._pullState) {
      if (this._buf.length < 32) return;
      const header = this._buf.subarray(0, 32);
      this._buf = this._buf.subarray(32);
      this._pullState = new native.SecretStreamPullState(this._key, header);
    }
    for (;;) {
      if (this._done) {
        if (this._buf.length > 0) {
          throw new Error('trailing data after the secretstream Final chunk');
        }
        return;
      }
      if (this._buf.length < 5) return;
      const tagByte = this._buf[0];
      const chunkLen = this._buf.readUInt32LE(1);
      if (chunkLen > CHUNK_BYTES) {
        throw new Error(`secretstream chunk too large: declared ${chunkLen} bytes, max ${CHUNK_BYTES}`);
      }
      const recordLen = 5 + chunkLen + AUTH_TAG_BYTES;
      if (this._buf.length < recordLen) return;
      const ciphertext = this._buf.subarray(5, 5 + chunkLen);
      const authTag = this._buf.subarray(5 + chunkLen, recordLen);
      this._buf = this._buf.subarray(recordLen);
      const { tag, plaintext } = this._pullState.pull(tagByte, ciphertext, authTag);
      this.push(plaintext);
      if (tag === native.SECRETSTREAM_TAG_FINAL) {
        this._done = true;
      }
    }
  }

  _flush(callback) {
    let err;
    try {
      if (!this._pullState) {
        throw new Error('truncated secretstream: missing header');
      }
      if (!this._done) {
        throw new Error('truncated secretstream: stream ended before a Final chunk');
      }
      if (this._buf.length > 0) {
        throw new Error('trailing data after the secretstream Final chunk');
      }
    } catch (e) {
      err = e;
    }
    process.nextTick(callback, err);
  }
}

module.exports = { SecretStreamEncryptor, SecretStreamDecryptor };

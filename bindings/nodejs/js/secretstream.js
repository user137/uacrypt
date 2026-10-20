'use strict';

/**
 * Idiomatic `crypto_secretstream` pipeline (docs/DECISIONS.md D-118, docs/bindings-strategy.md
 * T-50 step 3) - hides chunk/tag/length-prefix bookkeeping behind a `stream.Transform` pair. The
 * framing itself (record layout, length rules, Final, trailing data) is dstu-core's stream-file
 * codec, exposed as SecretStreamFileEncryptor/SecretStreamFileDecryptor (T-284); this module only
 * buffers. Mirrors
 * bindings/python/python/dstu_core/secretstream.py's own design exactly (see D-118's two
 * standing pitfalls this port re-checks below).
 *
 * Wire format matches `uacrypt encrypt`/`decrypt` exactly (crates/uacrypt/src/lib.rs's
 * run_secretstream_encrypt/run_secretstream_decrypt, D-68): `version (1) || header (32 bytes)`
 * followed by one record per chunk, `tagByte (1) || chunkLenU32LE (4) || ciphertext (chunkLen) ||
 * authTag (16)`. Every record but the Final one is exactly 8 KiB (SECRETSTREAM_CHUNK_BYTES, part of
 * the format since D-208, not an independent choice). The shared vectors in
 * crates/dstu-core/tests/vectors/secretstream-file/ pin this.
 */

const { Transform } = require('node:stream');
const native = require('../native/index.js');

// dstu-core's crypto_secretstream::CHUNK_BYTES (D-208): the codec seals and checks it; this module
// only needs it to cut input into chunks.
const CHUNK_BYTES = 8 * 1024;

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
    this._enc = this._startCodec(key);
    this._buf = Buffer.alloc(0);
    this.push(this._enc.prefix);
  }

  /** The native codec for `key`; the box/passphrase subclasses start it their own way. */
  _startCodec(key) {
    return new native.SecretStreamFileEncryptor(key);
  }

  _transform(chunk, _encoding, callback) {
    this._buf = Buffer.concat([this._buf, chunk]);
    let err;
    try {
      // Hold back the last chunk (even a full one) until _flush: only then is it known to be the
      // Final one (an exact multiple of 8 KiB ends in a full Final record, D-208).
      let pos = 0;
      while (this._buf.length - pos > CHUNK_BYTES) {
        this.push(this._enc.sealChunk(this._buf.subarray(pos, pos + CHUNK_BYTES)));
        pos += CHUNK_BYTES;
      }
      this._buf = this._buf.subarray(pos);
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
      this.push(this._enc.sealFinal(this._buf));
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
 * D-118 pitfall check #2: the untrusted length field, the 8 KiB rule, trailing data after Final
 * and truncation are all the codec's checks (T-284); this class only collects `nextLen()` bytes
 * at a time. A Final chunk's plaintext is pushed only in `_flush`, once the input is known to end
 * right after it.
 */
class SecretStreamDecryptor extends Transform {
  constructor(key, options) {
    super(options);
    this._dec = this._startCodec(key);
    this._buf = Buffer.alloc(0);
  }

  /** The native codec for `key`, or null while a subclass still collects its prefix. */
  _startCodec(key) {
    return new native.SecretStreamFileDecryptor(key);
  }

  _transform(chunk, _encoding, callback) {
    this._buf = Buffer.concat([this._buf, chunk]);
    let err;
    try {
      if (this._dec === null) {
        if (this._buf.length < this._prefixBytes) {
          process.nextTick(callback);
          return;
        }
        this._dec = this._openPrefixed(this._buf.subarray(0, this._prefixBytes));
        this._buf = this._buf.subarray(this._prefixBytes);
      }
      let pos = 0;
      for (let want = this._dec.nextLen(); this._buf.length - pos >= want; want = this._dec.nextLen()) {
        const plaintext = this._dec.feed(this._buf.subarray(pos, pos + want));
        pos += want;
        if (plaintext.length > 0) this.push(plaintext);
      }
      this._buf = this._buf.subarray(pos);
    } catch (e) {
      err = e;
    }
    // See SecretStreamEncryptor._transform's comment - same synchronous-callback pitfall applies.
    process.nextTick(callback, err);
  }

  _flush(callback) {
    let err;
    try {
      if (this._dec === null) throw new Error(`input too short to contain a ${this._prefixName}`);
      const plaintext = this._dec.finish();
      if (plaintext.length > 0) this.push(plaintext);
    } catch (e) {
      err = e;
    }
    process.nextTick(callback, err);
  }
}

function checkLength(buf, bytes, name) {
  if (!Buffer.isBuffer(buf) || buf.length !== bytes) {
    throw new TypeError(`${name} must be a ${bytes}-byte Buffer`);
  }
}

/**
 * `crypto_box` sealed to `publicKey` as a stream (format v3, T-265/T-269): the same bytes
 * `boxSeal` returns, written chunk by chunk; `boxOpen`/`BoxDecryptor` read them.
 */
class BoxEncryptor extends SecretStreamEncryptor {
  _startCodec(publicKey) {
    return native.SecretStreamFileEncryptor.boxSeal(publicKey);
  }
}

/** `crypto_box384` counterpart of `BoxEncryptor`. */
class Box384Encryptor extends SecretStreamEncryptor {
  _startCodec(publicKey) {
    return native.SecretStreamFileEncryptor.box384Seal(publicKey);
  }
}

/** `crypto_box512` counterpart of `BoxEncryptor`. */
class Box512Encryptor extends SecretStreamEncryptor {
  _startCodec(publicKey) {
    return native.SecretStreamFileEncryptor.box512Seal(publicKey);
  }
}

/**
 * A passphrase file (D-219/D-240) - the bytes `uacrypt encrypt --passphrase` writes. The
 * constructor runs Argon2id (256 MiB, t=3, about a second) on the calling thread.
 */
class PassphraseEncryptor extends SecretStreamEncryptor {
  _startCodec(passphrase) {
    return native.SecretStreamFileEncryptor.passphraseSeal(passphrase);
  }
}

/**
 * Collects the bytes in front of the stream file, then opens the codec with them. The secret is
 * held only until then.
 */
class PrefixedDecryptor extends SecretStreamDecryptor {
  _startCodec(secret) {
    this._secret = secret;
    return null;
  }

  _openPrefixed(prefix) {
    const dec = this._openCodec(this._secret, prefix);
    this._secret = null;
    return dec;
  }
}

/** Reads a `crypto_box` stream (or a `boxSeal` blob) with bounded memory. */
class BoxDecryptor extends PrefixedDecryptor {
  constructor(secretKey, options) {
    checkLength(secretKey, 32, 'secretKey');
    super(secretKey, options);
    this._prefixBytes = native.BOX_OPEN_STREAM_PREFIX_BYTES;
    this._prefixName = 'sealed message';
  }

  _openCodec(secretKey, prefix) {
    return native.SecretStreamFileDecryptor.boxOpen(secretKey, prefix);
  }
}

/** `crypto_box384` counterpart of `BoxDecryptor`. */
class Box384Decryptor extends PrefixedDecryptor {
  constructor(secretKey, options) {
    checkLength(secretKey, 48, 'secretKey');
    super(secretKey, options);
    this._prefixBytes = native.BOX384_OPEN_STREAM_PREFIX_BYTES;
    this._prefixName = 'sealed message';
  }

  _openCodec(secretKey, prefix) {
    return native.SecretStreamFileDecryptor.box384Open(secretKey, prefix);
  }
}

/** `crypto_box512` counterpart of `BoxDecryptor`. */
class Box512Decryptor extends PrefixedDecryptor {
  constructor(secretKey, options) {
    checkLength(secretKey, 64, 'secretKey');
    super(secretKey, options);
    this._prefixBytes = native.BOX512_OPEN_STREAM_PREFIX_BYTES;
    this._prefixName = 'sealed message';
  }

  _openCodec(secretKey, prefix) {
    return native.SecretStreamFileDecryptor.box512Open(secretKey, prefix);
  }
}

/**
 * Reads a passphrase file. The header is checked before Argon2 runs (on the calling thread, once
 * the header has arrived); a wrong passphrase errors at the first record.
 */
class PassphraseDecryptor extends PrefixedDecryptor {
  constructor(passphrase, options) {
    super(passphrase, options);
    this._prefixBytes = native.PASSPHRASE_FILE_HEADER_BYTES;
    this._prefixName = 'passphrase file header';
  }

  _openCodec(passphrase, header) {
    return native.SecretStreamFileDecryptor.passphraseOpen(header, passphrase);
  }
}

module.exports = {
  SecretStreamEncryptor,
  SecretStreamDecryptor,
  BoxEncryptor,
  BoxDecryptor,
  Box384Encryptor,
  Box384Decryptor,
  Box512Encryptor,
  Box512Decryptor,
  PassphraseEncryptor,
  PassphraseDecryptor,
};

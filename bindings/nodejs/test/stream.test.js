'use strict';

/**
 * `crypto_stream` (Strumok-256 keystream) - **no authentication** (see
 * `dstu_core::crypto_stream`'s own module doc): no rejection category, since there is no tag to
 * tamper with - `streamDecrypt` never fails on tampered input, it silently returns different,
 * wrong plaintext instead. Correctness: round trip. Misuse: wrong-length key, truncated input.
 * Mirrors bindings/python/tests/test_stream.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('encrypt/decrypt round-trips', () => {
  const key = dstu.streamKeygen();
  const sealed = dstu.streamEncrypt(key, Buffer.from('message'));
  assert.deepStrictEqual(dstu.streamDecrypt(key, sealed), Buffer.from('message'));
});

test('tampering is not detected but produces wrong plaintext', () => {
  // Documents the no-integrity property explicitly, per this project's own precedent
  // (hazmat::kalyna_xts's tampered_ciphertext_does_not_error_but_produces_garbage) - a
  // deliberate design property, not a missing rejection test.
  const key = dstu.streamKeygen();
  const sealed = Buffer.from(dstu.streamEncrypt(key, Buffer.from('message')));
  sealed[sealed.length - 1] ^= 1;
  const garbage = dstu.streamDecrypt(key, sealed);
  assert.notDeepStrictEqual(garbage, Buffer.from('message'));
});

test('wrong-length key is rejected', () => {
  assert.throws(() => dstu.streamEncrypt(Buffer.from('too short'), Buffer.from('message')));
});

test('truncated sealed input is rejected', () => {
  const key = dstu.streamKeygen();
  assert.throws(() => dstu.streamDecrypt(key, Buffer.from('short')));
});

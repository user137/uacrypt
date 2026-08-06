'use strict';

/**
 * `crypto_box` - no official vector exists for this composite construction (same posture as
 * `crypto_secretbox`, D-51/D-169's own "Provenance" section) - correctness (round trip, including
 * a message larger than the 25-byte KEM payload), rejection (tampered wire segments, wrong key),
 * misuse (wrong-length/invalid key encodings, truncated input). Mirrors
 * bindings/python/tests/test_box.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('seal/open round-trips', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const message = Buffer.from("a message for the public key's holder only");
  const sealed = dstu.boxSeal(publicKey, message);
  assert.deepStrictEqual(dstu.boxOpen(secretKey, sealed), message);
});

test('seal handles empty message', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const sealed = dstu.boxSeal(publicKey, Buffer.alloc(0));
  assert.deepStrictEqual(dstu.boxOpen(secretKey, sealed), Buffer.alloc(0));
});

test('seal handles message larger than the KEM payload', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const message = Buffer.alloc(10_000, 'x');
  const sealed = dstu.boxSeal(publicKey, message);
  assert.deepStrictEqual(dstu.boxOpen(secretKey, sealed), message);
});

test('two seals use different ephemeral material', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const message = Buffer.from('same message twice');
  assert.notDeepStrictEqual(dstu.boxSeal(publicKey, message), dstu.boxSeal(publicKey, message));
});

test('tampered KEM prefix is rejected', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const sealed = Buffer.from(dstu.boxSeal(publicKey, Buffer.from('message')));
  sealed[0] ^= 1;
  assert.throws(() => dstu.boxOpen(secretKey, sealed));
});

test('tampered ciphertext is rejected', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const sealed = Buffer.from(dstu.boxSeal(publicKey, Buffer.from('message')));
  sealed[sealed.length - 1] ^= 1;
  assert.throws(() => dstu.boxOpen(secretKey, sealed));
});

test('wrong secret key is rejected', () => {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey);
  const otherSecretKey = dstu.boxKeygen();
  const sealed = dstu.boxSeal(publicKey, Buffer.from('message'));
  assert.throws(() => dstu.boxOpen(otherSecretKey, sealed));
});

test('wrong-length secret key is rejected', () => {
  assert.throws(() => dstu.boxPublicKey(Buffer.from('too short')));
});

test('zero secret key is rejected', () => {
  assert.throws(() => dstu.boxPublicKey(Buffer.alloc(32)));
});

test('wrong-length public key is rejected', () => {
  assert.throws(() => dstu.boxSeal(Buffer.from('too short'), Buffer.from('message')));
});

test('degenerate public key x is rejected', () => {
  assert.throws(() => dstu.boxSeal(Buffer.alloc(32), Buffer.from('message'))); // x = 0
});

test('truncated sealed input is rejected', () => {
  const secretKey = dstu.boxKeygen();
  assert.throws(() => dstu.boxOpen(secretKey, Buffer.from('short')));
});

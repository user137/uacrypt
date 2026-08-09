'use strict';

/**
 * `crypto_box512` - `l(p)=512` sibling of `crypto_box` (T-193/T-204). No official vector exists
 * for this composite construction (same posture as `crypto_box`) - correctness (round trip),
 * rejection (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings,
 * truncated input). Mirrors bindings/python/tests/test_box512.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('seal/open round-trips', () => {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey);
  const message = Buffer.from("a message for the public key's holder only");
  const sealed = dstu.box512Seal(publicKey, message);
  assert.deepStrictEqual(dstu.box512Open(secretKey, sealed), message);
});

test('seal handles empty message', () => {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey);
  const sealed = dstu.box512Seal(publicKey, Buffer.alloc(0));
  assert.deepStrictEqual(dstu.box512Open(secretKey, sealed), Buffer.alloc(0));
});

test('two seals use different ephemeral material', () => {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey);
  const message = Buffer.from('same message twice');
  assert.notDeepStrictEqual(dstu.box512Seal(publicKey, message), dstu.box512Seal(publicKey, message));
});

test('tampered ciphertext is rejected', () => {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey);
  const sealed = Buffer.from(dstu.box512Seal(publicKey, Buffer.from('message')));
  sealed[sealed.length - 1] ^= 1;
  assert.throws(() => dstu.box512Open(secretKey, sealed));
});

test('wrong secret key is rejected', () => {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey);
  const otherSecretKey = dstu.box512Keygen();
  const sealed = dstu.box512Seal(publicKey, Buffer.from('message'));
  assert.throws(() => dstu.box512Open(otherSecretKey, sealed));
});

test('wrong-length secret key is rejected', () => {
  assert.throws(() => dstu.box512PublicKey(Buffer.from('too short')));
});

test('zero secret key is rejected', () => {
  assert.throws(() => dstu.box512PublicKey(Buffer.alloc(64)));
});

test('wrong-length public key is rejected', () => {
  assert.throws(() => dstu.box512Seal(Buffer.from('too short'), Buffer.from('message')));
});

test('degenerate public key x is rejected', () => {
  assert.throws(() => dstu.box512Seal(Buffer.alloc(64), Buffer.from('message'))); // x = 0
});

test('truncated sealed input is rejected', () => {
  const secretKey = dstu.box512Keygen();
  assert.throws(() => dstu.box512Open(secretKey, Buffer.from('short')));
});

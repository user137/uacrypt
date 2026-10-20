'use strict';

/**
 * `crypto_box384` - `l(p)=384` sibling of `crypto_box` (T-297). No official vector exists
 * for this composite construction (same posture as `crypto_box`) - correctness (round trip),
 * rejection (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings,
 * truncated input). Mirrors bindings/python/tests/test_box384.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('seal/open round-trips', () => {
  const secretKey = dstu.box384Keygen();
  const publicKey = dstu.box384PublicKey(secretKey);
  const message = Buffer.from("a message for the public key's holder only");
  const sealed = dstu.box384Seal(publicKey, message);
  assert.deepStrictEqual(dstu.box384Open(secretKey, sealed), message);
});

test('seal handles empty message', () => {
  const secretKey = dstu.box384Keygen();
  const publicKey = dstu.box384PublicKey(secretKey);
  const sealed = dstu.box384Seal(publicKey, Buffer.alloc(0));
  assert.deepStrictEqual(dstu.box384Open(secretKey, sealed), Buffer.alloc(0));
});

test('two seals use different ephemeral material', () => {
  const secretKey = dstu.box384Keygen();
  const publicKey = dstu.box384PublicKey(secretKey);
  const message = Buffer.from('same message twice');
  assert.notDeepStrictEqual(dstu.box384Seal(publicKey, message), dstu.box384Seal(publicKey, message));
});

test('tampered ciphertext is rejected', () => {
  const secretKey = dstu.box384Keygen();
  const publicKey = dstu.box384PublicKey(secretKey);
  const sealed = Buffer.from(dstu.box384Seal(publicKey, Buffer.from('message')));
  sealed[sealed.length - 1] ^= 1;
  assert.throws(() => dstu.box384Open(secretKey, sealed));
});

test('wrong secret key is rejected', () => {
  const secretKey = dstu.box384Keygen();
  const publicKey = dstu.box384PublicKey(secretKey);
  const otherSecretKey = dstu.box384Keygen();
  const sealed = dstu.box384Seal(publicKey, Buffer.from('message'));
  assert.throws(() => dstu.box384Open(otherSecretKey, sealed));
});

test('wrong-length secret key is rejected', () => {
  assert.throws(() => dstu.box384PublicKey(Buffer.from('too short')));
});

test('zero secret key is rejected', () => {
  assert.throws(() => dstu.box384PublicKey(Buffer.alloc(48)));
});

test('wrong-length public key is rejected', () => {
  assert.throws(() => dstu.box384Seal(Buffer.from('too short'), Buffer.from('message')));
});

test('degenerate public key x is rejected', () => {
  assert.throws(() => dstu.box384Seal(Buffer.alloc(48), Buffer.from('message'))); // x = 0
});

test('truncated sealed input is rejected', () => {
  const secretKey = dstu.box384Keygen();
  assert.throws(() => dstu.box384Open(secretKey, Buffer.from('short')));
});

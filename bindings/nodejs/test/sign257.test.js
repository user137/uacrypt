'use strict';

/**
 * `crypto_sign257` (DSTU 4145 `m=257`) - `m=257` sibling of `crypto_sign` (T-199/T-204).
 * Correctness (round trip, determinism of the nonce derivation), rejection (wrong message/wrong
 * key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
 * Mirrors bindings/python/tests/test_sign257.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('sign/verify round-trips', () => {
  const signingKey = dstu.sign257Keygen();
  const verifyingKey = dstu.sign257VerifyingKey(signingKey);
  const message = Buffer.from('a message whose origin and integrity matter');
  const signature = dstu.sign257Message(signingKey, message);
  assert.strictEqual(dstu.sign257Verify(verifyingKey, message, signature), true);
});

test('signing is deterministic', () => {
  const signingKey = dstu.sign257Keygen();
  const message = Buffer.from('same message every time');
  assert.deepStrictEqual(dstu.sign257Message(signingKey, message), dstu.sign257Message(signingKey, message));
});

test('wrong message is rejected', () => {
  const signingKey = dstu.sign257Keygen();
  const verifyingKey = dstu.sign257VerifyingKey(signingKey);
  const signature = dstu.sign257Message(signingKey, Buffer.from('original message'));
  assert.strictEqual(dstu.sign257Verify(verifyingKey, Buffer.from('a different message'), signature), false);
});

test('wrong key is rejected', () => {
  const signingKey = dstu.sign257Keygen();
  const otherVerifyingKey = dstu.sign257VerifyingKey(dstu.sign257Keygen());
  const message = Buffer.from('message');
  const signature = dstu.sign257Message(signingKey, message);
  assert.strictEqual(dstu.sign257Verify(otherVerifyingKey, message, signature), false);
});

test('zero signing key is rejected', () => {
  assert.throws(() => dstu.sign257VerifyingKey(Buffer.alloc(33)));
});

test('wrong-length signing key is rejected', () => {
  assert.throws(() => dstu.sign257Message(Buffer.from('too short'), Buffer.from('message')));
});

test('wrong-length verifying key is rejected', () => {
  assert.throws(() => dstu.sign257Verify(Buffer.from('too short'), Buffer.from('message'), Buffer.alloc(66)));
});

test('wrong-length signature is rejected', () => {
  const signingKey = dstu.sign257Keygen();
  const verifyingKey = dstu.sign257VerifyingKey(signingKey);
  assert.throws(() => dstu.sign257Verify(verifyingKey, Buffer.from('message'), Buffer.from('too short')));
});

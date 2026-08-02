'use strict';

/**
 * `crypto_sign` (DSTU 4145) - the official Annex B.1 verify vector is already covered by
 * `selfTest()` (selftest.test.js); this file covers what that single vector doesn't reach:
 * correctness (round trip, determinism of the nonce derivation), rejection (wrong message/wrong
 * key), misuse (invalid signing key - zero/out-of-range, wrong-length verifying key/signature).
 * Mirrors bindings/python/tests/test_sign.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('sign/verify round-trips', () => {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);
  const message = Buffer.from('a message whose origin and integrity matter');
  const signature = dstu.signMessage(signingKey, message);
  assert.strictEqual(dstu.signVerify(verifyingKey, message, signature), true);
});

test('signing is deterministic (D-46: no RNG-derived nonce)', () => {
  const signingKey = dstu.signKeygen();
  const message = Buffer.from('same message every time');
  assert.deepStrictEqual(dstu.signMessage(signingKey, message), dstu.signMessage(signingKey, message));
});

test('wrong message is rejected', () => {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);
  const signature = dstu.signMessage(signingKey, Buffer.from('original message'));
  assert.strictEqual(dstu.signVerify(verifyingKey, Buffer.from('a different message'), signature), false);
});

test('wrong key is rejected', () => {
  const signingKey = dstu.signKeygen();
  const otherVerifyingKey = dstu.signVerifyingKey(dstu.signKeygen());
  const message = Buffer.from('message');
  const signature = dstu.signMessage(signingKey, message);
  assert.strictEqual(dstu.signVerify(otherVerifyingKey, message, signature), false);
});

test('zero signing key is rejected', () => {
  assert.throws(() => dstu.signVerifyingKey(Buffer.alloc(21)));
});

test('wrong-length signing key is rejected', () => {
  assert.throws(() => dstu.signMessage(Buffer.from('too short'), Buffer.from('message')));
});

test('wrong-length verifying key is rejected', () => {
  assert.throws(() => dstu.signVerify(Buffer.from('too short'), Buffer.from('message'), Buffer.alloc(42)));
});

test('wrong-length signature is rejected', () => {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);
  assert.throws(() => dstu.signVerify(verifyingKey, Buffer.from('message'), Buffer.from('too short')));
});

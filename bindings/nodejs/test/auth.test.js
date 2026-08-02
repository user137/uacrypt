'use strict';

/**
 * `crypto_auth` - three categories per D-64/D-65: correctness (round trip), rejection (tampered
 * message, wrong key), misuse (wrong-length key/tag - foreclosed at the Rust layer by fixed-size
 * arrays, D-66, so `auth` itself is infallible; only the JS-boundary length checks are testable
 * here). Mirrors bindings/python/tests/test_auth.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('auth/verify round-trips', () => {
  const key = dstu.authKeygen();
  const message = Buffer.from('a message both parties want to confirm is unmodified');
  const tag = dstu.auth(key, message);
  dstu.authVerify(key, message, tag);
});

test('tampered message is rejected', () => {
  const key = dstu.authKeygen();
  const tag = dstu.auth(key, Buffer.from('original message'));
  assert.throws(() => dstu.authVerify(key, Buffer.from('a different message'), tag));
});

test('wrong key is rejected', () => {
  const key = dstu.authKeygen();
  const otherKey = dstu.authKeygen();
  const tag = dstu.auth(key, Buffer.from('message'));
  assert.throws(() => dstu.authVerify(otherKey, Buffer.from('message'), tag));
});

test('wrong-length key is rejected', () => {
  assert.throws(() => dstu.auth(Buffer.from('too short'), Buffer.from('message')));
});

test('wrong-length tag is rejected', () => {
  const key = dstu.authKeygen();
  assert.throws(() => dstu.authVerify(key, Buffer.from('message'), Buffer.from('too short')));
});

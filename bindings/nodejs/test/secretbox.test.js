'use strict';

/**
 * `crypto_secretbox` - three categories per D-64/D-65: correctness (round trip - no official
 * vector exists for this construction, same posture as the Rust crate's own tests, D-51),
 * rejection (tamper/wrong key), misuse (wrong-length key, truncated input). Mirrors
 * bindings/python/tests/test_secretbox.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('seal/open round-trips', () => {
  const key = dstu.secretboxKeygen();
  const sealed = dstu.secretboxSeal(key, Buffer.from('a message worth protecting'));
  assert.deepStrictEqual(dstu.secretboxOpen(key, sealed), Buffer.from('a message worth protecting'));
});

test('seal handles empty message', () => {
  const key = dstu.secretboxKeygen();
  const sealed = dstu.secretboxSeal(key, Buffer.alloc(0));
  assert.deepStrictEqual(dstu.secretboxOpen(key, sealed), Buffer.alloc(0));
});

test('tampered ciphertext is rejected', () => {
  const key = dstu.secretboxKeygen();
  const sealed = Buffer.from(dstu.secretboxSeal(key, Buffer.from('message')));
  sealed[sealed.length - 1] ^= 1;
  assert.throws(() => dstu.secretboxOpen(key, sealed));
});

test('tampered nonce is rejected', () => {
  const key = dstu.secretboxKeygen();
  const sealed = Buffer.from(dstu.secretboxSeal(key, Buffer.from('message')));
  sealed[0] ^= 1; // first byte of the nonce
  assert.throws(() => dstu.secretboxOpen(key, sealed));
});

test('wrong key is rejected', () => {
  const key = dstu.secretboxKeygen();
  const otherKey = dstu.secretboxKeygen();
  const sealed = dstu.secretboxSeal(key, Buffer.from('message'));
  assert.throws(() => dstu.secretboxOpen(otherKey, sealed));
});

test('wrong-length key is rejected', () => {
  assert.throws(() => dstu.secretboxSeal(Buffer.from('too short'), Buffer.from('message')));
});

test('truncated sealed input is rejected', () => {
  const key = dstu.secretboxKeygen();
  assert.throws(() => dstu.secretboxOpen(key, Buffer.from('short')));
});

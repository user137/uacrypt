'use strict';

/**
 * `crypto_pwhash` (Argon2id, the one deliberately non-DSTU component, D-49/D-50). Correctness:
 * round trip. Rejection: wrong password, malformed hash string. Misuse: invalid `strength` value.
 * `PWHASH_INTERACTIVE` is used throughout (not the default `PWHASH_MODERATE`) so this file's own
 * tests stay fast. Mirrors bindings/python/tests/test_pwhash.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('hash/verify round-trips', () => {
  const stored = dstu.pwhashHashPassword(Buffer.from('correct horse battery staple'), dstu.PWHASH_INTERACTIVE);
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('correct horse battery staple'), stored), true);
});

test('wrong password is rejected', () => {
  const stored = dstu.pwhashHashPassword(Buffer.from('correct horse battery staple'), dstu.PWHASH_INTERACTIVE);
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('wrong guess'), stored), false);
});

test('malformed hash string is rejected', () => {
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('anything'), 'not a real PHC string'), false);
});

test('invalid strength is rejected', () => {
  assert.throws(() => dstu.pwhashHashPassword(Buffer.from('password'), 255));
});

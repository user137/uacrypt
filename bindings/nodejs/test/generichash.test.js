'use strict';

/**
 * `crypto_generichash` (Kupyna-256/512) - three categories per D-64/D-65: correctness against a
 * real official Kupyna-256 vector (loaded directly from the same JSON the Rust crate's own tests
 * and `selfTest()` use - crates/dstu-core/tests/vectors/kupyna/kupyna-256.json, not just
 * round-trip self-consistency - this is what makes the check cross-language, D-124) plus
 * one-shot/streaming agreement, misuse (calling `finalize()` twice - there is no rejection
 * category, a hash has no key/tag to tamper with). Mirrors bindings/python/tests/test_generichash.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dstu = require('../js/index.js');

const VECTOR_PATH = path.resolve(
  __dirname,
  '..', '..', '..',
  'crates', 'dstu-core', 'tests', 'vectors', 'kupyna', 'kupyna-256.json',
);

test('kupyna256 matches the official vector', () => {
  const vectors = JSON.parse(fs.readFileSync(VECTOR_PATH, 'utf8'));
  const c = vectors.cases[0];
  const message = Buffer.from(c.message_hex, 'hex');
  const expected = Buffer.from(c.hash_hex, 'hex');
  assert.deepStrictEqual(dstu.kupyna256(message), expected);
});

test('streaming Kupyna256Hasher matches one-shot', () => {
  const whole = dstu.kupyna256(Buffer.from('hello world'));
  const hasher = new dstu.Kupyna256Hasher();
  hasher.update(Buffer.from('hello '));
  hasher.update(Buffer.from('world'));
  assert.deepStrictEqual(hasher.finalize(), whole);
});

test('streaming Kupyna512Hasher matches one-shot', () => {
  const whole = dstu.kupyna512(Buffer.from('hello world'));
  const hasher = new dstu.Kupyna512Hasher();
  hasher.update(Buffer.from('hello '));
  hasher.update(Buffer.from('world'));
  assert.deepStrictEqual(hasher.finalize(), whole);
});

test('finalize twice is rejected', () => {
  const hasher = new dstu.Kupyna256Hasher();
  hasher.update(Buffer.from('data'));
  hasher.finalize();
  assert.throws(() => hasher.finalize());
});

test('update after finalize is rejected', () => {
  const hasher = new dstu.Kupyna256Hasher();
  hasher.finalize();
  assert.throws(() => hasher.update(Buffer.from('more data')));
});

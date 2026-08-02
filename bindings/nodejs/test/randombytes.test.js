'use strict';

/**
 * `randombytes` - no rejection/misuse category (a single `size` parameter, nothing to tamper
 * with). Correctness: returns the requested length, and two calls are not identical. Mirrors
 * bindings/python/tests/test_randombytes.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('returns requested length', () => {
  assert.strictEqual(dstu.randombytesBuf(32).length, 32);
});

test('zero length returns empty', () => {
  assert.deepStrictEqual(dstu.randombytesBuf(0), Buffer.alloc(0));
});

test('two calls are not identical', () => {
  assert.notDeepStrictEqual(dstu.randombytesBuf(32), dstu.randombytesBuf(32));
});

'use strict';

/**
 * Correctness gate: `selfTest()` re-verifies one official vector per primitive (Kalyna, Kupyna,
 * Strumok, DSTU 4145) against this exact compiled addon - docs/TASKS.md T-161. Every other test
 * file in this suite adds its own correctness/rejection/misuse coverage on top of this baseline
 * (D-64/D-65). Mirrors bindings/python/tests/test_selftest.py.
 */

const test = require('node:test');
const dstu = require('../js/index.js');

test('selfTest passes', () => {
  dstu.selfTest(); // throws on any mismatch
});

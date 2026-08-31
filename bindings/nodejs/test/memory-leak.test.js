'use strict';

/**
 * T-213: FFI memory-leak smoke test. Loops `crypto_secretstream` push/pull (the most stateful,
 * longest-lived native object this binding wraps - `SecretStreamPushState`/`PullState`) and
 * `crypto_box` seal/open (a keyed one-shot primitive) N=1000+ times with normal cleanup, then
 * asserts `process.memoryUsage().heapUsed` stays far below what a real leak of that many
 * iterations would show. Needs `--expose-gc` (see `package.json`'s `test:leak` script) to force a
 * deterministic collection point before each measurement - without it, V8's own GC scheduling
 * makes any single-sample heap reading too noisy to assert on.
 *
 * Same reasoning as `bindings/python/tests/test_memory_leak.py` (T-213): these wrapper objects are
 * direct napi-rs handles around a Rust struct with no separate C ABI `free()` call, so once the JS
 * wrapper is garbage-collected, Rust's own `Drop` is guaranteed to run correctly - "the wrapper
 * object never gets collected" (a held reference, an unclosed stream, D-118's cleanup-hook pitfall)
 * is the leak risk this test targets, and a managed-heap measurement genuinely observes it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

const N = 1000;
// Same reasoning as the Python threshold: well below "N leaked handles" worth of growth, well
// above normal per-iteration bookkeeping noise.
const MAX_ACCEPTABLE_GROWTH_BYTES = N * 200;

test('secretstream and box loop does not leak', { skip: typeof global.gc !== 'function' && 'run with node --expose-gc (see package.json test:leak script)' }, () => {
  const key = dstu.secretstreamKeygen();
  const boxSecret = dstu.boxKeygen();
  const boxPublic = dstu.boxPublicKey(boxSecret);

  global.gc();
  const before = process.memoryUsage().heapUsed;

  for (let i = 0; i < N; i++) {
    const push = new dstu.SecretStreamPushState(key);
    const header = push.header;
    const { ciphertext, authTag } = push.push(dstu.SECRETSTREAM_TAG_MESSAGE, Buffer.from('leak-check chunk'));
    const pull = new dstu.SecretStreamPullState(key, header);
    pull.pull(dstu.SECRETSTREAM_TAG_MESSAGE, ciphertext, authTag);

    const sealed = dstu.boxSeal(boxPublic, Buffer.from('leak-check message'));
    const opened = dstu.boxOpen(boxSecret, sealed);
    assert.deepStrictEqual(opened, Buffer.from('leak-check message'));
  }

  global.gc();
  const after = process.memoryUsage().heapUsed;
  const growth = after - before;
  assert.ok(
    growth < MAX_ACCEPTABLE_GROWTH_BYTES,
    `heapUsed grew by ${growth} bytes over ${N} iterations ` +
      `(threshold ${MAX_ACCEPTABLE_GROWTH_BYTES}) - possible native handle leak`,
  );
});

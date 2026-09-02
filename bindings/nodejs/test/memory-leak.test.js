'use strict';

/**
 * T-213: FFI memory-leak smoke test. Loops `crypto_secretstream` push/pull (the most stateful,
 * longest-lived native object this binding wraps - `SecretStreamPushState`/`PullState`) and
 * `crypto_box` seal/open (a keyed one-shot primitive) with normal cleanup, then asserts the
 * managed-heap growth does NOT scale with the iteration count. Needs `--expose-gc` (see
 * `package.json`'s `test:leak` script) to force a deterministic collection point.
 *
 * Why a scaling assertion, not an absolute byte threshold: `process.memoryUsage().heapUsed` is a
 * whole-V8-heap figure, so a single measured loop also captures one-time costs (JIT tier-up of the
 * loop body, inline-cache growth, heap-page rounding) that differ per platform/runner - the same
 * identical code was measured at -65 KB on a local Windows Node 20 and +244 KB on CI Linux Node 20.
 * A real per-handle leak, by contrast, is defined by growth that is proportional to the number of
 * handles created: run the loop at N and at 4N and a leak makes the second growth ~4x the first,
 * while a one-time cost leaves the two roughly equal. That ratio is portable; an absolute number is
 * not. (Python's own T-213 test can assert an absolute delta because `tracemalloc` attributes
 * allocations and ignores interpreter machinery - Node has no equivalent.)
 *
 * Same underlying reasoning as `bindings/python/tests/test_memory_leak.py` (T-213): these wrapper
 * objects are direct napi-rs handles around a Rust struct with no separate C ABI `free()` call, so
 * once the JS wrapper is garbage-collected, Rust's own `Drop` is guaranteed to run correctly - "the
 * wrapper object never gets collected" (a held reference, an unclosed stream, D-118's cleanup-hook
 * pitfall) is the leak risk this test targets.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

const N = 1000;
// V8 tiers up a hot function after a few hundred calls; run well past that before the first
// measurement so JIT/IC growth lands in the warmup, not in either measured window.
const WARMUP = 512;
// Ratio slack: a one-time cost makes growth4N/growthN ≈ 1; a genuine per-handle leak makes it ≈ 4.
// 2.5x sits with margin on both sides. Growth below FLOOR_BYTES is treated as pure noise and the
// ratio is not evaluated (near-zero or negative denominators make the ratio meaningless).
const MAX_SCALING_RATIO = 2.5;
const FLOOR_BYTES = 64 * 1024;

function measureGrowth(iterations, iter) {
  for (let i = 0; i < WARMUP; i++) iter();
  global.gc();
  global.gc();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < iterations; i++) iter();
  global.gc();
  global.gc();
  return process.memoryUsage().heapUsed - before;
}

test('secretstream and box loop does not leak', { skip: typeof global.gc !== 'function' && 'run with node --expose-gc (see package.json test:leak script)' }, () => {
  const key = dstu.secretstreamKeygen();
  const boxSecret = dstu.boxKeygen();
  const boxPublic = dstu.boxPublicKey(boxSecret);

  const iter = () => {
    const push = new dstu.SecretStreamPushState(key);
    const header = push.header;
    const { ciphertext, authTag } = push.push(dstu.SECRETSTREAM_TAG_MESSAGE, Buffer.from('leak-check chunk'));
    const pull = new dstu.SecretStreamPullState(key, header);
    pull.pull(dstu.SECRETSTREAM_TAG_MESSAGE, ciphertext, authTag);

    const sealed = dstu.boxSeal(boxPublic, Buffer.from('leak-check message'));
    const opened = dstu.boxOpen(boxSecret, sealed);
    assert.deepStrictEqual(opened, Buffer.from('leak-check message'));
  };

  const growthN = measureGrowth(N, iter);
  const growth4N = measureGrowth(4 * N, iter);

  if (growth4N <= FLOOR_BYTES) return;

  const ratio = growth4N / Math.max(growthN, FLOOR_BYTES);
  assert.ok(
    ratio <= MAX_SCALING_RATIO,
    `managed-heap growth scaled with iteration count: ${growthN} bytes at N=${N}, ` +
      `${growth4N} bytes at N=${4 * N} (ratio ${ratio.toFixed(2)}, max ${MAX_SCALING_RATIO}) ` +
      `- possible native handle leak`,
  );
});

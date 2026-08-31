'use strict';

/**
 * T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
 * than assumed. JS itself has no real threads outside `node:worker_threads` (each Worker gets its
 * own V8 isolate and its own instance of this native addon, loaded via a resolved absolute path so
 * it works from an `eval: true` worker with no file of its own on disk) - real OS-level
 * concurrency, not just async interleaving on one thread.
 *
 * - `signKeygen`/`signVerifyingKey`/`signMessage`/`signVerify` are plain functions over immutable
 *   `Buffer` keys - no native object holds state across calls, so passing the SAME key bytes to
 *   many workers and calling `signVerify`/`signMessage` concurrently is safe by construction.
 * - `SecretStreamPushState`/`PullState` DO hold native state that advances with every
 *   `push`/`pull` call, with no locking added by this wrapper. The supported concurrency model is
 *   one stream (one Push/PullState pair) per worker - verified below with each worker driving its
 *   own independent stream, not by racing a shared instance across workers (impossible to even
 *   express here anyway: a native handle can't be transferred/cloned across a worker boundary).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { Worker } = require('node:worker_threads');
const dstu = require('../js/index.js');

const MODULE_PATH = require.resolve('../js/index.js');

const WORKER_SOURCE = `
  const { workerData, parentPort } = require('node:worker_threads');
  const dstu = require(workerData.modulePath);

  function verifyLoop() {
    const { message, signature, verifyingKey, iterations } = workerData;
    for (let i = 0; i < iterations; i++) {
      if (!dstu.signVerify(verifyingKey, message, signature)) {
        throw new Error('signVerify returned false on a valid signature');
      }
    }
  }

  function signLoop() {
    const { message, signingKey, verifyingKey, iterations } = workerData;
    for (let i = 0; i < iterations; i++) {
      const sig = dstu.signMessage(signingKey, message);
      if (!dstu.signVerify(verifyingKey, message, sig)) {
        throw new Error('a concurrently-produced signature failed to verify');
      }
    }
  }

  function secretstreamLoop() {
    const { key, workerIndex, chunkCount } = workerData;
    const chunks = [];
    for (let i = 0; i < chunkCount; i++) {
      chunks.push(Buffer.from('worker ' + workerIndex + ' chunk ' + i));
    }

    const push = new dstu.SecretStreamPushState(key);
    const header = push.header;
    const pulledInputs = chunks.map((chunk) => push.push(dstu.SECRETSTREAM_TAG_MESSAGE, chunk));

    const pull = new dstu.SecretStreamPullState(key, header);
    for (let i = 0; i < chunks.length; i++) {
      const { ciphertext, authTag } = pulledInputs[i];
      const { plaintext } = pull.pull(dstu.SECRETSTREAM_TAG_MESSAGE, ciphertext, authTag);
      if (!plaintext.equals(chunks[i])) {
        throw new Error('worker ' + workerIndex + ': round trip mismatch at chunk ' + i);
      }
    }
  }

  switch (workerData.task) {
    case 'verify':
      verifyLoop();
      break;
    case 'sign':
      signLoop();
      break;
    case 'secretstream':
      secretstreamLoop();
      break;
    default:
      throw new Error('unknown task: ' + workerData.task);
  }

  parentPort.postMessage({ ok: true });
`;

function runWorker(workerData) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_SOURCE, { eval: true, workerData });
    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`worker stopped with exit code ${code}`));
      }
    });
  });
}

test('concurrent verify on a shared key is safe (worker_threads)', async () => {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);
  const message = Buffer.from('shared-key concurrent verify');
  const signature = dstu.signMessage(signingKey, message);

  const workerCount = 8;
  const results = await Promise.all(
    Array.from({ length: workerCount }, () =>
      runWorker({ task: 'verify', modulePath: MODULE_PATH, message, signature, verifyingKey, iterations: 200 }),
    ),
  );
  assert.strictEqual(results.length, workerCount);
  for (const r of results) {
    assert.deepStrictEqual(r, { ok: true });
  }
});

test('concurrent sign on a shared key is safe (worker_threads)', async () => {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);
  const message = Buffer.from('shared-key concurrent sign');

  const workerCount = 8;
  const results = await Promise.all(
    Array.from({ length: workerCount }, () =>
      runWorker({ task: 'sign', modulePath: MODULE_PATH, message, signingKey, verifyingKey, iterations: 50 }),
    ),
  );
  assert.strictEqual(results.length, workerCount);
  for (const r of results) {
    assert.deepStrictEqual(r, { ok: true });
  }
});

test('concurrent independent secretstream loops are safe (worker_threads)', async () => {
  const workerCount = 4;
  const results = await Promise.all(
    Array.from({ length: workerCount }, (_unused, workerIndex) =>
      runWorker({
        task: 'secretstream',
        modulePath: MODULE_PATH,
        key: dstu.secretstreamKeygen(),
        workerIndex,
        chunkCount: 20,
      }),
    ),
  );
  assert.strictEqual(results.length, workerCount);
  for (const r of results) {
    assert.deepStrictEqual(r, { ok: true });
  }
});

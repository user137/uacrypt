'use strict';

/**
 * Passphrase files (D-219, moved into the core by T-269/D-240): `PassphraseEncryptor`/
 * `PassphraseDecryptor`, the same bytes `uacrypt encrypt --passphrase-file` writes. Argon2 is
 * 256 MiB, t=3 per run (synchronous, like `pwhashHashPassword`), so only the shared-vector test
 * and the `uacrypt` interop run it; every header refusal stops before Argon2. Mirrors
 * bindings/python/tests/test_passphrase_file.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const dstu = require('../js/index.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const VECTORS = path.join(REPO_ROOT, 'crates', 'dstu-core', 'tests', 'vectors', 'pwhash', 'passphrase_file.json');
const UACRYPT_CANDIDATES = [
  path.join(REPO_ROOT, 'target', 'debug', 'uacrypt.exe'),
  path.join(REPO_ROOT, 'target', 'release', 'uacrypt.exe'),
  path.join(REPO_ROOT, 'target', 'debug', 'uacrypt'),
  path.join(REPO_ROOT, 'target', 'release', 'uacrypt'),
];

function pattern(n) {
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + 7) % 256;
  return out;
}

function cases(argon2) {
  return JSON.parse(fs.readFileSync(VECTORS, 'utf8')).cases.filter((c) => c.argon2 === argon2);
}

/** Same single-consumer helper as secretstream.test.js (see its comment for why). */
async function runThrough(transform, input) {
  const chunks = [];
  const reading = (async () => {
    for await (const c of transform) chunks.push(c);
  })();
  const writing = (async () => {
    for (const piece of input) {
      if (transform.destroyed) return;
      if (!transform.write(piece)) {
        await new Promise((resolve) => {
          transform.once('drain', resolve);
          transform.once('close', resolve);
        });
      }
    }
    if (!transform.destroyed) transform.end();
  })();
  await Promise.all([reading, writing]);
  return Buffer.concat(chunks);
}

function open(passphrase, data) {
  return runThrough(new dstu.PassphraseDecryptor(passphrase), [data]);
}

test('header vectors are refused before Argon2', async () => {
  const messages = {
    not_passphrase_file: /not a passphrase file/,
    unsupported_format: /unsupported passphrase file format/,
    unsupported_params: /unsupported Argon2 parameters/,
    truncated: /too short/,
  };
  const refused = cases(false);
  assert.strictEqual(refused.length, 6);
  for (const c of refused) {
    await assert.rejects(open(Buffer.from(c.passphrase_hex, 'hex'), Buffer.from(c.sealed_hex, 'hex')), messages[c.expect], c.name);
  }
});

test('files written by uacrypt 0.6.0 give their expected outcome', async () => {
  const argon2 = cases(true);
  assert.strictEqual(argon2.length, 4);
  for (const c of argon2) {
    const result = open(Buffer.from(c.passphrase_hex, 'hex'), Buffer.from(c.sealed_hex, 'hex'));
    if (c.expect === 'ok') {
      assert.deepStrictEqual(await result, pattern(c.plaintext_len), c.name);
    } else {
      await assert.rejects(result, undefined, c.name);
    }
  }
});

test('an empty passphrase is refused on both sides', async () => {
  assert.throws(() => new dstu.PassphraseEncryptor(Buffer.alloc(0)), /empty/);
  await assert.rejects(open(Buffer.alloc(0), Buffer.from(cases(true)[0].sealed_hex, 'hex')), /empty/);
});

test('a key-encrypted stream is not a passphrase file', async () => {
  const stream = await runThrough(new dstu.SecretStreamEncryptor(dstu.secretstreamKeygen()), [Buffer.from('x')]);
  await assert.rejects(open(Buffer.from('pw'), stream), /not a passphrase file/);
});

test('interop with uacrypt both ways', async (t) => {
  const uacrypt = UACRYPT_CANDIDATES.find((p) => fs.existsSync(p));
  if (!uacrypt) {
    t.skip('uacrypt binary not built (cargo build -p uacrypt)');
    return;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstu-pf-'));
  try {
    const message = pattern(8 * 1024 + 9);
    const passphrase = Buffer.from('спільний пароль');
    const pwFile = path.join(dir, 'pw.txt');
    fs.writeFileSync(pwFile, passphrase);

    const ours = path.join(dir, 'ours.uac');
    fs.writeFileSync(ours, await runThrough(new dstu.PassphraseEncryptor(passphrase), [message]));
    const back = path.join(dir, 'ours.back');
    execFileSync(uacrypt, ['decrypt', '--passphrase-file', pwFile, '--in', ours, '--out', back]);
    assert.deepStrictEqual(fs.readFileSync(back), message);

    const plain = path.join(dir, 'plain.bin');
    fs.writeFileSync(plain, message);
    const theirs = path.join(dir, 'theirs.uac');
    execFileSync(uacrypt, ['encrypt', '--passphrase-file', pwFile, '--in', plain, '--out', theirs]);
    assert.deepStrictEqual(await open(passphrase, fs.readFileSync(theirs)), message);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

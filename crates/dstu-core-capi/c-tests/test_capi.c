/* Plain-C test harness for dstu-core-capi (docs/bindings-strategy.md T-158, step 5 of the
 * renumbered template). Covers D-64/D-65's three categories per primitive: (1) correctness
 * against a real official vector or a documented round trip, (2) rejection of tampered/wrong
 * input wherever a tag/signature exists, (3) misuse (null pointers, zero-length input, undersized
 * output buffers, double-finalize). Compiled and run by `cargo xtask capi` against the just-built
 * dstu-core-capi cdylib - see xtask/src/main.rs's capi() function. Not a C++ file: deliberately
 * plain C11, since a real C consumer (not just C++) is the whole point of this crate existing.
 */

#include "dstu_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                                     \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void test_selftest(void) {
  CHECK(dstu_selftest() == DSTU_OK, "selftest should pass on a correct build");
}

static void test_randombytes_and_memzero(void) {
  uint8_t buf[32];
  memset(buf, 0, sizeof(buf));
  CHECK(dstu_randombytes_buf(buf, sizeof(buf)) == DSTU_OK, "randombytes_buf should succeed");

  int all_zero = 1;
  for (size_t i = 0; i < sizeof(buf); i++) {
    if (buf[i] != 0) {
      all_zero = 0;
    }
  }
  CHECK(!all_zero, "randombytes_buf should not leave the buffer all-zero (astronomically unlikely)");

  /* misuse: NULL with nonzero len is rejected */
  CHECK(dstu_randombytes_buf(NULL, 32) == DSTU_ERR_NULL_POINTER, "NULL buf + nonzero len should be rejected");
  /* misuse: NULL with zero len is a no-op success */
  CHECK(dstu_randombytes_buf(NULL, 0) == DSTU_OK, "NULL buf + zero len should be a no-op success");

  uint8_t secret[16];
  memset(secret, 0xAA, sizeof(secret));
  dstu_memzero(secret, sizeof(secret));
  int all_zero2 = 1;
  for (size_t i = 0; i < sizeof(secret); i++) {
    if (secret[i] != 0) {
      all_zero2 = 0;
    }
  }
  CHECK(all_zero2, "dstu_memzero should wipe the buffer");

  /* misuse: NULL/zero-length is a documented no-op, not a crash */
  dstu_memzero(NULL, 0);
  dstu_memzero(NULL, 16);
}

static void test_auth(void) {
  DstuAuthKey *key = NULL;
  CHECK(dstu_auth_key_generate(&key) == DSTU_OK, "auth key generate should succeed");
  CHECK(key != NULL, "auth key generate should write *out");

  const char *message = "a message both parties want to confirm is unmodified";
  uint8_t tag[DSTU_AUTH_TAG_BYTES];
  dstu_auth(key, (const uint8_t *)message, strlen(message), tag);

  CHECK(dstu_auth_verify(key, (const uint8_t *)message, strlen(message), tag) == DSTU_OK,
        "auth_verify should accept its own tag");

  const char *other = "a different message";
  CHECK(dstu_auth_verify(key, (const uint8_t *)other, strlen(other), tag) == DSTU_ERR_TAG_MISMATCH,
        "auth_verify should reject a tampered message");

  uint8_t bad_tag[DSTU_AUTH_TAG_BYTES];
  memcpy(bad_tag, tag, sizeof(tag));
  bad_tag[0] ^= 1;
  CHECK(dstu_auth_verify(key, (const uint8_t *)message, strlen(message), bad_tag) == DSTU_ERR_TAG_MISMATCH,
        "auth_verify should reject a tampered tag");

  dstu_auth_key_free(key);
  dstu_auth_key_free(NULL); /* misuse: NULL free is a no-op */

  /* misuse: generate() with a NULL out pointer */
  CHECK(dstu_auth_key_generate(NULL) == DSTU_ERR_NULL_POINTER, "auth_key_generate(NULL) should be rejected");

  /* misuse: from_bytes with a NULL key pointer */
  CHECK(dstu_auth_key_from_bytes(NULL) == NULL, "auth_key_from_bytes(NULL) should return NULL");

  uint8_t bytes[DSTU_AUTH_KEY_BYTES];
  memset(bytes, 0x42, sizeof(bytes));
  DstuAuthKey *from_bytes = dstu_auth_key_from_bytes(bytes);
  CHECK(from_bytes != NULL, "auth_key_from_bytes should succeed for a valid pointer");
  uint8_t round_tripped[DSTU_AUTH_KEY_BYTES];
  dstu_auth_key_bytes(from_bytes, round_tripped);
  CHECK(memcmp(bytes, round_tripped, sizeof(bytes)) == 0, "auth_key_bytes should round-trip from_bytes");
  dstu_auth_key_free(from_bytes);
}

static void test_kdf(void) {
  DstuKdfMasterKey *key = NULL;
  CHECK(dstu_kdf_master_key_generate(&key) == DSTU_OK, "kdf master key generate should succeed");

  uint8_t ctx[DSTU_KDF_CONTEXT_BYTES] = {'e', 'n', 'c', 'r', 'y', 'p', 't', '_'};
  uint8_t sub0[DSTU_KDF_SUBKEY_BYTES];
  uint8_t sub1[DSTU_KDF_SUBKEY_BYTES];
  uint8_t sub0_again[DSTU_KDF_SUBKEY_BYTES];
  dstu_kdf_derive_subkey(key, 0, ctx, sub0);
  dstu_kdf_derive_subkey(key, 1, ctx, sub1);
  dstu_kdf_derive_subkey(key, 0, ctx, sub0_again);

  CHECK(memcmp(sub0, sub1, sizeof(sub0)) != 0, "different subkey_id should derive distinct subkeys");
  CHECK(memcmp(sub0, sub0_again, sizeof(sub0)) == 0, "the same subkey_id/context should be deterministic");

  dstu_kdf_master_key_free(key);
}

/* Official DSTU 7564:2014 Kupyna-256 test vector (docs/papers/Kupyna.pdf, Appendix B.2 - Oliynykov
 * et al., "A New Standard of Ukraine: The Kupyna Hash Function"; also
 * crates/dstu-core/tests/vectors/kupyna/kupyna-256.json). Single-byte message 0xFF, since this is
 * the simplest case to hand-transcribe as a C byte array - proves the C ABI's byte plumbing
 * (pointer/length handling in, buffer copy out) produces the right bytes, not just that
 * one-shot/streaming agree with each other (dstu_selftest() already proves the underlying Rust
 * primitive is correct; this proves the C surface over it). */
static void test_generichash_official_vector(void) {
  const uint8_t message[] = {0xFF};
  const uint8_t expected[DSTU_GENERICHASH_256_BYTES] = {
      0xEA, 0x76, 0x77, 0xCA, 0x45, 0x26, 0x55, 0x56, 0x80, 0x44, 0x1C, 0x11, 0x79, 0x82, 0xEA, 0x14,
      0x05, 0x9E, 0xA6, 0xD0, 0xD7, 0x12, 0x4D, 0x6E, 0xCD, 0xB3, 0xDE, 0xEC, 0x49, 0xE8, 0x90, 0xF4};
  uint8_t actual[DSTU_GENERICHASH_256_BYTES];
  dstu_generichash_256(message, sizeof(message), actual);
  CHECK(memcmp(expected, actual, sizeof(expected)) == 0,
        "dstu_generichash_256(0xFF) should match the official DSTU 7564:2014 Kupyna-256 vector");
}

static void test_generichash(void) {
  const char *message = "hello world";
  uint8_t whole[DSTU_GENERICHASH_256_BYTES];
  dstu_generichash_256((const uint8_t *)message, strlen(message), whole);

  DstuKupyna256Hasher *hasher = dstu_kupyna256_hasher_new();
  CHECK(hasher != NULL, "hasher_new should be infallible");
  dstu_kupyna256_hasher_update(hasher, (const uint8_t *)"hello ", 6);
  dstu_kupyna256_hasher_update(hasher, (const uint8_t *)"world", 5);
  uint8_t streamed[DSTU_GENERICHASH_256_BYTES];
  CHECK(dstu_kupyna256_hasher_finalize(hasher, streamed) == DSTU_OK, "finalize should succeed the first time");
  CHECK(memcmp(whole, streamed, sizeof(whole)) == 0, "one-shot and streaming should agree");

  /* misuse: finalize twice */
  uint8_t second[DSTU_GENERICHASH_256_BYTES];
  CHECK(dstu_kupyna256_hasher_finalize(hasher, second) == DSTU_ERR_FINALIZED,
        "a second finalize() should report DSTU_ERR_FINALIZED, not panic");
  dstu_kupyna256_hasher_free(hasher);

  uint8_t whole512[DSTU_GENERICHASH_512_BYTES];
  dstu_generichash_512((const uint8_t *)message, strlen(message), whole512);
  DstuKupyna512Hasher *hasher512 = dstu_kupyna512_hasher_new();
  dstu_kupyna512_hasher_update(hasher512, (const uint8_t *)message, strlen(message));
  uint8_t streamed512[DSTU_GENERICHASH_512_BYTES];
  CHECK(dstu_kupyna512_hasher_finalize(hasher512, streamed512) == DSTU_OK, "512 finalize should succeed");
  CHECK(memcmp(whole512, streamed512, sizeof(whole512)) == 0, "512 one-shot and streaming should agree");
  dstu_kupyna512_hasher_free(hasher512);
}

static void test_secretbox(void) {
  DstuSecretboxKey *key = NULL;
  CHECK(dstu_secretbox_key_generate(&key) == DSTU_OK, "secretbox key generate should succeed");

  const char *plaintext = "a message worth protecting";
  size_t plaintext_len = strlen(plaintext);
  size_t sealed_cap = plaintext_len + DSTU_SECRETBOX_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  CHECK(dstu_secretbox_seal(key, (const uint8_t *)plaintext, plaintext_len, sealed, sealed_cap, &sealed_len) ==
            DSTU_OK,
        "seal should succeed with an exactly-sized buffer");
  CHECK(sealed_len == sealed_cap, "sealed_len should equal plaintext_len + overhead exactly");

  uint8_t *opened = malloc(plaintext_len);
  size_t opened_len = 0;
  CHECK(dstu_secretbox_open(key, sealed, sealed_len, opened, plaintext_len, &opened_len) == DSTU_OK,
        "open should succeed on an authentic ciphertext");
  CHECK(opened_len == plaintext_len && memcmp(opened, plaintext, plaintext_len) == 0,
        "opened plaintext should match the original");

  /* rejection: tampered ciphertext */
  uint8_t *tampered = malloc(sealed_len);
  memcpy(tampered, sealed, sealed_len);
  tampered[sealed_len - 1] ^= 1;
  uint8_t *garbage = malloc(plaintext_len);
  memset(garbage, 0xFF, plaintext_len);
  size_t garbage_len = 0;
  CHECK(dstu_secretbox_open(key, tampered, sealed_len, garbage, plaintext_len, &garbage_len) ==
            DSTU_ERR_TAG_MISMATCH,
        "open should reject a tampered ciphertext");
  int garbage_all_zero = 1;
  for (size_t i = 0; i < plaintext_len; i++) {
    if (garbage[i] != 0) {
      garbage_all_zero = 0;
    }
  }
  CHECK(garbage_all_zero, "plaintext_out should be left zeroed on tag mismatch, never partially trusted");

  /* misuse: truncated input */
  uint8_t small_out[4];
  size_t small_len = 0;
  CHECK(dstu_secretbox_open(key, sealed, 4, small_out, sizeof(small_out), &small_len) == DSTU_ERR_TRUNCATED,
        "open should reject input shorter than the nonce+tag overhead");

  /* misuse: undersized output buffer on seal - checked before any crypto work runs */
  uint8_t tiny[4];
  size_t tiny_len = 0;
  CHECK(dstu_secretbox_seal(key, (const uint8_t *)plaintext, plaintext_len, tiny, sizeof(tiny), &tiny_len) ==
            DSTU_ERR_BUFFER_TOO_SMALL,
        "seal should reject an undersized output buffer");

  /* misuse: undersized output buffer on open */
  size_t tiny_open_len = 0;
  CHECK(dstu_secretbox_open(key, sealed, sealed_len, tiny, sizeof(tiny), &tiny_open_len) ==
            DSTU_ERR_BUFFER_TOO_SMALL,
        "open should reject an undersized output buffer");

  free(sealed);
  free(opened);
  free(tampered);
  free(garbage);
  dstu_secretbox_key_free(key);
}

static void test_secretstream(void) {
  DstuSecretstreamKey *key = NULL;
  CHECK(dstu_secretstream_key_generate(&key) == DSTU_OK, "secretstream key generate should succeed");

  DstuPushState *push = NULL;
  uint8_t header[DSTU_SECRETSTREAM_HEADER_BYTES];
  CHECK(dstu_secretstream_push_init(key, &push, header) == DSTU_OK, "push_init should succeed");
  CHECK(!dstu_secretstream_push_is_finalized(push), "a fresh push state should not be finalized");

  const char *plaintext = "a whole file, conceptually split into chunks";
  size_t len = strlen(plaintext);
  uint8_t *ciphertext = malloc(len);
  uint8_t tag[DSTU_SECRETSTREAM_TAG_BYTES];

  /* misuse: length mismatch, on the still-fresh (not finalized) push state so this actually
   * exercises DSTU_ERR_INVALID_LENGTH rather than being pre-empted by a finalized check. */
  uint8_t dummy_tag[DSTU_SECRETSTREAM_TAG_BYTES];
  uint8_t wrong_len_out[2];
  CHECK(dstu_secretstream_push(push, DSTU_TAG_MESSAGE, (const uint8_t *)plaintext, len, wrong_len_out,
                                sizeof(wrong_len_out), dummy_tag) == DSTU_ERR_INVALID_LENGTH,
        "push should reject ciphertext_out_len != plaintext_len");

  CHECK(dstu_secretstream_push(push, DSTU_TAG_FINAL, (const uint8_t *)plaintext, len, ciphertext, len, tag) ==
            DSTU_OK,
        "push should succeed");
  CHECK(dstu_secretstream_push_is_finalized(push), "push state should be finalized after a Final chunk");

  /* misuse: push after finalize */
  uint8_t dummy_ct[1];
  CHECK(dstu_secretstream_push(push, DSTU_TAG_MESSAGE, (const uint8_t *)"x", 1, dummy_ct, 1, dummy_tag) ==
            DSTU_ERR_FINALIZED,
        "push after Final should report DSTU_ERR_FINALIZED");

  DstuPullState *pull = dstu_secretstream_pull_init(key, header);
  CHECK(pull != NULL, "pull_init should be infallible for valid input");
  uint8_t *decrypted = malloc(len);
  DstuTag out_tag;
  CHECK(dstu_secretstream_pull(pull, (uint8_t)DSTU_TAG_FINAL, ciphertext, len, tag, decrypted, len, &out_tag) ==
            DSTU_OK,
        "pull should succeed on an authentic chunk");
  CHECK(out_tag == DSTU_TAG_FINAL, "pull should report the authenticated tag");
  CHECK(memcmp(decrypted, plaintext, len) == 0, "decrypted plaintext should match the original");
  CHECK(dstu_secretstream_pull_is_finalized(pull), "pull state should be finalized after a Final chunk");

  /* rejection: tampered ciphertext on a fresh pull state */
  uint8_t *tampered = malloc(len);
  memcpy(tampered, ciphertext, len);
  tampered[0] ^= 1;
  DstuPullState *pull2 = dstu_secretstream_pull_init(key, header);
  uint8_t *garbage = malloc(len);
  memset(garbage, 0xFF, len);
  DstuTag out_tag2;
  CHECK(dstu_secretstream_pull(pull2, (uint8_t)DSTU_TAG_FINAL, tampered, len, tag, garbage, len, &out_tag2) ==
            DSTU_ERR_TAG_MISMATCH,
        "pull should reject a tampered chunk");
  int garbage_all_zero = 1;
  for (size_t i = 0; i < len; i++) {
    if (garbage[i] != 0) {
      garbage_all_zero = 0;
    }
  }
  CHECK(garbage_all_zero, "plaintext_out should be left zeroed on tag mismatch");

  /* misuse: unknown tag byte */
  DstuPullState *pull3 = dstu_secretstream_pull_init(key, header);
  uint8_t *out3 = malloc(len);
  DstuTag out_tag3;
  CHECK(dstu_secretstream_pull(pull3, 0xFF, ciphertext, len, tag, out3, len, &out_tag3) ==
            DSTU_ERR_UNKNOWN_TAG,
        "pull should reject a tag_byte outside 0-3");

  free(ciphertext);
  free(decrypted);
  free(tampered);
  free(garbage);
  free(out3);
  dstu_secretstream_push_free(push);
  dstu_secretstream_pull_free(pull);
  dstu_secretstream_pull_free(pull2);
  dstu_secretstream_pull_free(pull3);
  dstu_secretstream_key_free(key);
}

static void test_sign(void) {
  DstuSigningKey *key = NULL;
  CHECK(dstu_sign_key_generate(&key) == DSTU_OK, "sign key generate should succeed");
  DstuVerifyingKey *verifying = dstu_sign_verifying_key(key);
  CHECK(verifying != NULL, "verifying_key should be infallible");

  const char *message = "a message whose origin and integrity matter";
  uint8_t sig[DSTU_SIGN_SIGNATURE_BYTES];
  dstu_sign(key, (const uint8_t *)message, strlen(message), sig);
  CHECK(dstu_verify(verifying, (const uint8_t *)message, strlen(message), sig),
        "verify should accept its own signature");

  const char *other = "a different message";
  CHECK(!dstu_verify(verifying, (const uint8_t *)other, strlen(other), sig),
        "verify should reject a different message");

  DstuSigningKey *other_key = NULL;
  dstu_sign_key_generate(&other_key);
  DstuVerifyingKey *other_verifying = dstu_sign_verifying_key(other_key);
  CHECK(!dstu_verify(other_verifying, (const uint8_t *)message, strlen(message), sig),
        "verify should reject a signature from a different key");

  /* misuse: zero scalar is an invalid private key */
  uint8_t zero[DSTU_SIGN_PRIVATE_KEY_BYTES];
  memset(zero, 0, sizeof(zero));
  DstuSigningKey *invalid = NULL;
  CHECK(dstu_sign_key_from_bytes(zero, &invalid) == DSTU_ERR_INVALID_KEY,
        "from_bytes should reject an all-zero scalar");
  CHECK(invalid == NULL, "an invalid key should not write *out");

  dstu_sign_key_free(key);
  dstu_sign_key_free(other_key);
  dstu_verifying_key_free(verifying);
  dstu_verifying_key_free(other_verifying);
}

static void test_stream(void) {
  DstuStreamKey *key = NULL;
  CHECK(dstu_stream_key_generate(&key) == DSTU_OK, "stream key generate should succeed");

  const char *plaintext = "message";
  size_t len = strlen(plaintext);
  size_t sealed_cap = len + DSTU_STREAM_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  CHECK(dstu_stream_encrypt(key, (const uint8_t *)plaintext, len, sealed, sealed_cap, &sealed_len) == DSTU_OK,
        "stream encrypt should succeed");

  uint8_t *opened = malloc(len);
  size_t opened_len = 0;
  CHECK(dstu_stream_decrypt(key, sealed, sealed_len, opened, len, &opened_len) == DSTU_OK,
        "stream decrypt should succeed");
  CHECK(memcmp(opened, plaintext, len) == 0, "decrypted plaintext should match the original");

  /* contrast with secretbox: tampering does NOT error, it silently changes the plaintext */
  uint8_t *tampered = malloc(sealed_len);
  memcpy(tampered, sealed, sealed_len);
  tampered[sealed_len - 1] ^= 1;
  uint8_t *garbage = malloc(len);
  size_t garbage_len = 0;
  CHECK(dstu_stream_decrypt(key, tampered, sealed_len, garbage, len, &garbage_len) == DSTU_OK,
        "stream decrypt never fails on tampered input - no tag to check");
  CHECK(memcmp(garbage, plaintext, len) != 0, "tampered decryption should produce different plaintext");

  /* misuse: truncated input */
  uint8_t trunc_out[1];
  size_t trunc_len = 0;
  CHECK(dstu_stream_decrypt(key, sealed, 4, trunc_out, sizeof(trunc_out), &trunc_len) == DSTU_ERR_TRUNCATED,
        "stream decrypt should reject input shorter than the IV");

  free(sealed);
  free(opened);
  free(tampered);
  free(garbage);
  dstu_stream_key_free(key);
}

static void test_pwhash(void) {
  const char *password = "correct horse battery staple";
  char hash[DSTU_PWHASH_STRBYTES];
  CHECK(dstu_pwhash_hash_password((const uint8_t *)password, strlen(password), DSTU_PWHASH_INTERACTIVE, hash) ==
            DSTU_OK,
        "pwhash should succeed");

  CHECK(dstu_pwhash_verify_password((const uint8_t *)password, strlen(password), hash),
        "verify_password should accept the correct password");

  const char *wrong = "wrong guess";
  CHECK(!dstu_pwhash_verify_password((const uint8_t *)wrong, strlen(wrong), hash),
        "verify_password should reject the wrong password");

  /* misuse: malformed hash string */
  CHECK(!dstu_pwhash_verify_password((const uint8_t *)password, strlen(password), "not a real phc string"),
        "verify_password should reject a malformed hash string, not crash");

  /* misuse: NULL hash */
  CHECK(!dstu_pwhash_verify_password((const uint8_t *)password, strlen(password), NULL),
        "verify_password should reject a NULL hash");
}

static void test_box(void) {
  DstuBoxSecretKey *secret = NULL;
  CHECK(dstu_box_secretkey_generate(&secret) == DSTU_OK, "box secretkey generate should succeed");
  DstuBoxPublicKey *public_key = dstu_box_secretkey_public_key(secret);
  CHECK(public_key != NULL, "box secretkey_public_key should not return NULL for a valid key");

  const char *message = "a message for the public key's holder only";
  size_t message_len = strlen(message);
  size_t sealed_cap = message_len + DSTU_BOX_SEAL_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  CHECK(dstu_box_seal(public_key, (const uint8_t *)message, message_len, sealed, sealed_cap, &sealed_len) ==
            DSTU_OK,
        "seal should succeed with an exactly-sized buffer");
  CHECK(sealed_len == sealed_cap, "sealed_len should equal message_len + DSTU_BOX_SEAL_OVERHEAD exactly");

  uint8_t *opened = malloc(message_len);
  size_t opened_len = 0;
  CHECK(dstu_box_open(secret, sealed, sealed_len, opened, message_len, &opened_len) == DSTU_OK,
        "open should succeed on an authentic ciphertext");
  CHECK(opened_len == message_len && memcmp(opened, message, message_len) == 0,
        "opened plaintext should match the original message");

  /* rejection: tampered ciphertext */
  uint8_t *tampered = malloc(sealed_len);
  memcpy(tampered, sealed, sealed_len);
  tampered[sealed_len - 1] ^= 1;
  uint8_t *garbage = malloc(message_len);
  memset(garbage, 0xFF, message_len);
  size_t garbage_len = 0;
  CHECK(dstu_box_open(secret, tampered, sealed_len, garbage, message_len, &garbage_len) ==
            DSTU_ERR_TAG_MISMATCH,
        "open should reject a tampered ciphertext");
  int garbage_all_zero = 1;
  for (size_t i = 0; i < message_len; i++) {
    if (garbage[i] != 0) {
      garbage_all_zero = 0;
    }
  }
  CHECK(garbage_all_zero, "plaintext_out should be left zeroed on tag mismatch, never partially trusted");

  /* rejection: wrong secret key */
  DstuBoxSecretKey *other_secret = NULL;
  CHECK(dstu_box_secretkey_generate(&other_secret) == DSTU_OK, "second box secretkey generate should succeed");
  uint8_t *wrong_key_out = malloc(message_len);
  size_t wrong_key_len = 0;
  CHECK(dstu_box_open(other_secret, sealed, sealed_len, wrong_key_out, message_len, &wrong_key_len) ==
            DSTU_ERR_TAG_MISMATCH,
        "open should reject the correct sealed message under the wrong secret key");
  dstu_box_secretkey_free(other_secret);
  free(wrong_key_out);

  /* misuse: truncated input */
  uint8_t small_out[4];
  size_t small_len = 0;
  CHECK(dstu_box_open(secret, sealed, 4, small_out, sizeof(small_out), &small_len) == DSTU_ERR_TRUNCATED,
        "open should reject input shorter than DSTU_BOX_SEAL_OVERHEAD");

  /* misuse: undersized output buffer on seal - checked before any crypto work runs */
  uint8_t tiny[4];
  size_t tiny_len = 0;
  CHECK(dstu_box_seal(public_key, (const uint8_t *)message, message_len, tiny, sizeof(tiny), &tiny_len) ==
            DSTU_ERR_BUFFER_TOO_SMALL,
        "seal should reject an undersized output buffer");

  /* misuse: undersized output buffer on open */
  size_t tiny_open_len = 0;
  CHECK(dstu_box_open(secret, sealed, sealed_len, tiny, sizeof(tiny), &tiny_open_len) ==
            DSTU_ERR_BUFFER_TOO_SMALL,
        "open should reject an undersized output buffer");

  /* misuse: invalid key encodings */
  uint8_t zero32[32] = {0};
  DstuBoxSecretKey *invalid_secret = NULL;
  CHECK(dstu_box_secretkey_from_bytes(zero32, &invalid_secret) == DSTU_ERR_INVALID_KEY,
        "secretkey_from_bytes should reject a zero scalar");
  CHECK(invalid_secret == NULL, "secretkey_from_bytes should not write *out on failure");
  DstuBoxPublicKey *invalid_public = NULL;
  CHECK(dstu_box_publickey_from_bytes(zero32, &invalid_public) == DSTU_ERR_INVALID_KEY,
        "publickey_from_bytes should reject x = 0");
  CHECK(invalid_public == NULL, "publickey_from_bytes should not write *out on failure");

  free(sealed);
  free(opened);
  free(tampered);
  free(garbage);
  dstu_box_publickey_free(public_key);
  dstu_box_secretkey_free(secret);
}

static void test_null_misuse(void) {
  CHECK(dstu_auth_key_generate(NULL) == DSTU_ERR_NULL_POINTER, "auth_key_generate(NULL) should be rejected");
  CHECK(dstu_sign_verifying_key(NULL) == NULL, "sign_verifying_key(NULL) should return NULL, not crash");
  CHECK(!dstu_secretstream_push_is_finalized(NULL), "push_is_finalized(NULL) should return false, not crash");
  CHECK(!dstu_secretstream_pull_is_finalized(NULL), "pull_is_finalized(NULL) should return false, not crash");
  CHECK(dstu_box_secretkey_generate(NULL) == DSTU_ERR_NULL_POINTER, "box_secretkey_generate(NULL) should be rejected");
  CHECK(dstu_box_secretkey_public_key(NULL) == NULL, "box_secretkey_public_key(NULL) should return NULL, not crash");
}

int main(void) {
  test_selftest();
  test_randombytes_and_memzero();
  test_auth();
  test_kdf();
  test_generichash_official_vector();
  test_generichash();
  test_secretbox();
  test_secretstream();
  test_sign();
  test_stream();
  test_pwhash();
  test_box();
  test_null_misuse();

  if (failures == 0) {
    printf("all dstu-core-capi C tests passed\n");
    return 0;
  }
  fprintf(stderr, "%d dstu-core-capi C test(s) failed\n", failures);
  return 1;
}

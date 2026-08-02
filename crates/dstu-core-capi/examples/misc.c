/* Smaller primitives that don't need their own dedicated example file: crypto_auth, crypto_kdf,
 * crypto_generichash, crypto_stream, randombytes, crypto_pwhash. */

#include "dstu_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what) {
  fprintf(stderr, "error: %s\n", what);
  exit(1);
}

static void demo_randombytes(void) {
  uint8_t buf[16];
  if (dstu_randombytes_buf(buf, sizeof(buf)) != DSTU_OK) {
    die("randombytes_buf failed");
  }
  printf("randombytes_buf: filled %zu random bytes\n", sizeof(buf));
}

static void demo_auth(void) {
  DstuAuthKey *key = NULL;
  if (dstu_auth_key_generate(&key) != DSTU_OK) {
    die("auth key generation failed");
  }
  const char *message = "a message both parties want to confirm is unmodified";
  uint8_t tag[DSTU_AUTH_TAG_BYTES];
  dstu_auth(key, (const uint8_t *)message, strlen(message), tag);
  int ok = dstu_auth_verify(key, (const uint8_t *)message, strlen(message), tag) == DSTU_OK;
  printf("crypto_auth: tag verified = %s\n", ok ? "true" : "false");
  dstu_auth_key_free(key);
}

static void demo_kdf(void) {
  DstuKdfMasterKey *key = NULL;
  if (dstu_kdf_master_key_generate(&key) != DSTU_OK) {
    die("kdf master key generation failed");
  }
  uint8_t encrypt_ctx[DSTU_KDF_CONTEXT_BYTES] = {'e', 'n', 'c', 'r', 'y', 'p', 't', '_'};
  uint8_t mac_ctx[DSTU_KDF_CONTEXT_BYTES] = {'m', 'a', 'c', '_', 'k', 'e', 'y', '_'};
  uint8_t encrypt_subkey[DSTU_KDF_SUBKEY_BYTES];
  uint8_t mac_subkey[DSTU_KDF_SUBKEY_BYTES];
  dstu_kdf_derive_subkey(key, 0, encrypt_ctx, encrypt_subkey);
  dstu_kdf_derive_subkey(key, 1, mac_ctx, mac_subkey);
  printf("crypto_kdf: derived two distinct %d-byte subkeys from one master key\n", DSTU_KDF_SUBKEY_BYTES);
  dstu_kdf_master_key_free(key);
}

static void demo_generichash(void) {
  uint8_t digest[DSTU_GENERICHASH_256_BYTES];
  dstu_generichash_256((const uint8_t *)"hello world", 11, digest);
  printf("crypto_generichash: Kupyna-256(\"hello world\") = ");
  for (size_t i = 0; i < sizeof(digest); i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");
}

static void demo_stream(void) {
  DstuStreamKey *key = NULL;
  if (dstu_stream_key_generate(&key) != DSTU_OK) {
    die("stream key generation failed");
  }
  const char *message = "message";
  size_t message_len = strlen(message);
  size_t sealed_cap = message_len + DSTU_STREAM_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  dstu_stream_encrypt(key, (const uint8_t *)message, message_len, sealed, sealed_cap, &sealed_len);
  uint8_t *plaintext = malloc(message_len);
  size_t plaintext_len = 0;
  dstu_stream_decrypt(key, sealed, sealed_len, plaintext, message_len, &plaintext_len);
  printf("crypto_stream: round-tripped %zu bytes (confidentiality only, no authentication)\n",
         plaintext_len);
  free(sealed);
  free(plaintext);
  dstu_stream_key_free(key);
}

static void demo_pwhash(void) {
  const char *password = "correct horse battery staple";
  char hash[DSTU_PWHASH_STRBYTES];
  if (dstu_pwhash_hash_password((const uint8_t *)password, strlen(password), DSTU_PWHASH_INTERACTIVE, hash) !=
      DSTU_OK) {
    die("pwhash failed");
  }
  int ok = dstu_pwhash_verify_password((const uint8_t *)password, strlen(password), hash);
  int rejects_wrong = !dstu_pwhash_verify_password((const uint8_t *)"wrong guess", 11, hash);
  printf("crypto_pwhash: correct password verified = %s, wrong password rejected = %s\n",
         ok ? "true" : "false", rejects_wrong ? "true" : "false");
}

int main(void) {
  demo_randombytes();
  demo_auth();
  demo_kdf();
  demo_generichash();
  demo_stream();
  demo_pwhash();
  return 0;
}

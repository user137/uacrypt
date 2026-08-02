/* crypto_secretbox: seal/open a single in-memory message with a symmetric key.
 *
 * Build+run manually (or via `cargo xtask capi`, which does this for every example):
 *   cargo build -p dstu-core-capi --release
 *   gcc -I../include secretbox.c -o secretbox -L../../../target/release -ldstu_core_capi
 *   ./secretbox
 */

#include "dstu_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what) {
  fprintf(stderr, "error: %s\n", what);
  exit(1);
}

int main(void) {
  DstuSecretboxKey *key = NULL;
  if (dstu_secretbox_key_generate(&key) != DSTU_OK) {
    die("key generation failed (OS CSPRNG unavailable)");
  }

  const char *message = "a message worth protecting";
  size_t message_len = strlen(message);
  size_t sealed_cap = message_len + DSTU_SECRETBOX_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  if (dstu_secretbox_seal(key, (const uint8_t *)message, message_len, sealed, sealed_cap, &sealed_len) !=
      DSTU_OK) {
    die("seal failed");
  }

  uint8_t *plaintext = malloc(message_len);
  size_t plaintext_len = 0;
  if (dstu_secretbox_open(key, sealed, sealed_len, plaintext, message_len, &plaintext_len) != DSTU_OK) {
    die("open failed on our own ciphertext");
  }
  printf("sealed %zu bytes -> %zu bytes, round-tripped OK\n", plaintext_len, sealed_len);

  /* Tampering with the sealed blob (ciphertext, tag, or nonce) is detected, not silently
   * "decrypted" into wrong plaintext. */
  sealed[sealed_len - 1] ^= 1;
  DstuStatus status = dstu_secretbox_open(key, sealed, sealed_len, plaintext, message_len, &plaintext_len);
  if (status == DSTU_ERR_TAG_MISMATCH) {
    printf("tampered ciphertext correctly rejected\n");
  } else {
    die("tampered ciphertext was NOT rejected");
  }

  free(sealed);
  free(plaintext);
  dstu_secretbox_key_free(key);
  return 0;
}

/* crypto_box: generate a keypair, seal a message to the public key, open it with the secret key.
 *
 * Build+run manually (or via `cargo xtask capi`, which does this for every example):
 *   cargo build -p dstu-core-capi --release
 *   gcc -I../include box.c -o box -L../../../target/release -ldstu_core_capi
 *   ./box
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
  DstuBoxSecretKey *secret_key = NULL;
  if (dstu_box_secretkey_generate(&secret_key) != DSTU_OK) {
    die("secret key generation failed (OS CSPRNG unavailable)");
  }
  DstuBoxPublicKey *public_key = dstu_box_secretkey_public_key(secret_key); /* safe to share/publish */
  if (public_key == NULL) {
    die("public key derivation failed");
  }

  const char *message = "a message for the public key's holder only";
  size_t message_len = strlen(message);
  size_t sealed_cap = message_len + DSTU_BOX_SEAL_OVERHEAD;
  uint8_t *sealed = malloc(sealed_cap);
  size_t sealed_len = 0;
  if (dstu_box_seal(public_key, (const uint8_t *)message, message_len, sealed, sealed_cap, &sealed_len) !=
      DSTU_OK) {
    die("seal failed");
  }

  uint8_t *plaintext = malloc(message_len);
  size_t plaintext_len = 0;
  if (dstu_box_open(secret_key, sealed, sealed_len, plaintext, message_len, &plaintext_len) != DSTU_OK) {
    die("open failed on our own ciphertext");
  }
  printf("sealed %zu bytes -> %zu bytes, round-tripped OK\n", plaintext_len, sealed_len);

  /* Tampering with the sealed blob (KEM prefix, header, ciphertext, or tag) is detected, not
   * silently "decrypted" into wrong plaintext. */
  sealed[sealed_len - 1] ^= 1;
  DstuStatus status = dstu_box_open(secret_key, sealed, sealed_len, plaintext, message_len, &plaintext_len);
  if (status == DSTU_ERR_TAG_MISMATCH) {
    printf("tampered ciphertext correctly rejected\n");
  } else {
    die("tampered ciphertext was NOT rejected");
  }

  free(sealed);
  free(plaintext);
  dstu_box_publickey_free(public_key);
  dstu_box_secretkey_free(secret_key);
  return 0;
}

/* crypto_sign: DSTU 4145 sign/verify - both the success path and a rejected forgery, since a
 * signature example that only shows the happy path doesn't demonstrate the primitive actually
 * does what it claims.
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
  DstuSigningKey *signing_key = NULL;
  if (dstu_sign_key_generate(&signing_key) != DSTU_OK) {
    die("key generation failed (OS CSPRNG unavailable)");
  }
  DstuVerifyingKey *verifying_key = dstu_sign_verifying_key(signing_key); /* safe to share/publish */

  const char *message = "a message whose origin and integrity matter";
  size_t message_len = strlen(message);
  uint8_t signature[DSTU_SIGN_SIGNATURE_BYTES];
  dstu_sign(signing_key, (const uint8_t *)message, message_len, signature);

  if (!dstu_verify(verifying_key, (const uint8_t *)message, message_len, signature)) {
    die("verify rejected our own signature");
  }
  printf("signature verified OK\n");

  /* A different message, or a signature from a different key, must fail to verify. */
  const char *other_message = "a different message";
  if (dstu_verify(verifying_key, (const uint8_t *)other_message, strlen(other_message), signature)) {
    die("verify incorrectly accepted a different message");
  }

  DstuSigningKey *other_key = NULL;
  dstu_sign_key_generate(&other_key);
  DstuVerifyingKey *other_verifying_key = dstu_sign_verifying_key(other_key);
  if (dstu_verify(other_verifying_key, (const uint8_t *)message, message_len, signature)) {
    die("verify incorrectly accepted a signature from a different key");
  }
  printf("forged message and wrong-key forgery both correctly rejected\n");

  dstu_sign_key_free(signing_key);
  dstu_sign_key_free(other_key);
  dstu_verifying_key_free(verifying_key);
  dstu_verifying_key_free(other_verifying_key);
  return 0;
}

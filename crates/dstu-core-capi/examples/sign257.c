/* crypto_sign257: DSTU 4145 m=257 sign/verify - the m=257 sibling of sign.c (T-199), same shape:
 * both the success path and a rejected forgery, since a signature example that only shows the
 * happy path doesn't demonstrate the primitive actually does what it claims.
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
  DstuSigningKey257 *signing_key = NULL;
  if (dstu_sign257_key_generate(&signing_key) != DSTU_OK) {
    die("key generation failed (OS CSPRNG unavailable)");
  }
  DstuVerifyingKey257 *verifying_key = dstu_sign257_verifying_key(signing_key); /* safe to share/publish */

  const char *message = "a message whose origin and integrity matter";
  size_t message_len = strlen(message);
  uint8_t signature[DSTU_SIGN257_SIGNATURE_BYTES];
  dstu_sign257(signing_key, (const uint8_t *)message, message_len, signature);

  if (!dstu_verify257(verifying_key, (const uint8_t *)message, message_len, signature)) {
    die("verify257 rejected our own signature");
  }
  printf("signature257 verified OK\n");

  /* A different message, or a signature from a different key, must fail to verify. */
  const char *other_message = "a different message";
  if (dstu_verify257(verifying_key, (const uint8_t *)other_message, strlen(other_message), signature)) {
    die("verify257 incorrectly accepted a different message");
  }

  DstuSigningKey257 *other_key = NULL;
  dstu_sign257_key_generate(&other_key);
  DstuVerifyingKey257 *other_verifying_key = dstu_sign257_verifying_key(other_key);
  if (dstu_verify257(other_verifying_key, (const uint8_t *)message, message_len, signature)) {
    die("verify257 incorrectly accepted a signature from a different key");
  }
  printf("forged message and wrong-key forgery both correctly rejected\n");

  dstu_sign257_key_free(signing_key);
  dstu_sign257_key_free(other_key);
  dstu_verifying_key257_free(verifying_key);
  dstu_verifying_key257_free(other_verifying_key);
  return 0;
}

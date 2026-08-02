/* crypto_secretstream: a real file, encrypted and decrypted one bounded-size chunk at a time -
 * this is the shape a caller needs for a large file that must not be held whole in memory
 * (unlike crypto_secretbox, whose AEAD tag needs the whole plaintext/ciphertext up front).
 *
 * This is the *raw* push/pull API (dstu-core-capi has no idiomatic-C stream wrapper of its own -
 * that's a later consumer's job, e.g. a future C++ binding built on top of this header) - a real
 * wire format (chunk framing, length prefixes) is this example's own choice, not dictated by the
 * library.
 */

#include "dstu_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE 8192

static void die(const char *what) {
  fprintf(stderr, "error: %s\n", what);
  exit(1);
}

/* Writes a `uint32_t` length prefix, then `len` bytes, then the fixed-size auth tag - our own
 * simple per-chunk record format for this example, not a format the library itself defines. */
static void write_chunk(FILE *out, DstuTag tag, const uint8_t *ciphertext, uint32_t len,
                         const uint8_t tag_bytes[DSTU_SECRETSTREAM_TAG_BYTES]) {
  uint8_t tag_byte = (uint8_t)tag;
  fwrite(&tag_byte, 1, 1, out);
  fwrite(&len, sizeof(len), 1, out);
  fwrite(ciphertext, 1, len, out);
  fwrite(tag_bytes, 1, DSTU_SECRETSTREAM_TAG_BYTES, out);
}

static int read_chunk(FILE *in, uint8_t *tag_byte, uint8_t *buf, uint32_t buf_cap, uint32_t *len,
                       uint8_t tag_bytes[DSTU_SECRETSTREAM_TAG_BYTES]) {
  if (fread(tag_byte, 1, 1, in) != 1) {
    return 0; /* end of file */
  }
  if (fread(len, sizeof(*len), 1, in) != 1) {
    die("truncated chunk length");
  }
  if (*len > buf_cap) {
    die("chunk length exceeds our fixed-size read buffer");
  }
  if (fread(buf, 1, *len, in) != *len) {
    die("truncated chunk ciphertext");
  }
  if (fread(tag_bytes, 1, DSTU_SECRETSTREAM_TAG_BYTES, in) != DSTU_SECRETSTREAM_TAG_BYTES) {
    die("truncated chunk tag");
  }
  return 1;
}

int main(void) {
  const char *plain_path = "dstu_capi_example_plain.tmp";
  const char *encrypted_path = "dstu_capi_example_encrypted.tmp";
  const char *decrypted_path = "dstu_capi_example_decrypted.tmp";

  /* Create a source file a bit larger than one chunk, so the loop below runs more than once. */
  FILE *src = fopen(plain_path, "wb");
  if (!src) {
    die("could not create the example source file");
  }
  for (int i = 0; i < CHUNK_SIZE + 1000; i++) {
    fputc('A' + (i % 26), src);
  }
  fclose(src);

  DstuSecretstreamKey *key = NULL;
  if (dstu_secretstream_key_generate(&key) != DSTU_OK) {
    die("key generation failed");
  }

  /* --- encrypt --- */
  DstuPushState *push = NULL;
  uint8_t header[DSTU_SECRETSTREAM_HEADER_BYTES];
  if (dstu_secretstream_push_init(key, &push, header) != DSTU_OK) {
    die("push_init failed");
  }

  FILE *in = fopen(plain_path, "rb");
  FILE *out = fopen(encrypted_path, "wb");
  if (!in || !out) {
    die("could not open example files for encryption");
  }
  fwrite(header, 1, DSTU_SECRETSTREAM_HEADER_BYTES, out);

  uint8_t plain_buf[CHUNK_SIZE];
  uint8_t cipher_buf[CHUNK_SIZE];
  /* Read up to CHUNK_SIZE bytes at a time; the last (short, or EOF-terminated) read is Final. */
  size_t total_read = 0;
  for (;;) {
    size_t n = fread(plain_buf, 1, sizeof(plain_buf), in);
    total_read += n;
    int is_final = feof(in) || n < sizeof(plain_buf);
    uint8_t tag_out[DSTU_SECRETSTREAM_TAG_BYTES];
    DstuTag tag = is_final ? DSTU_TAG_FINAL : DSTU_TAG_MESSAGE;
    if (dstu_secretstream_push(push, tag, plain_buf, n, cipher_buf, n, tag_out) != DSTU_OK) {
      die("push failed");
    }
    write_chunk(out, tag, cipher_buf, (uint32_t)n, tag_out);
    if (is_final) {
      break;
    }
  }
  fclose(in);
  fclose(out);
  dstu_secretstream_push_free(push);
  printf("encrypted %zu bytes into %s\n", total_read, encrypted_path);

  /* --- decrypt --- */
  FILE *enc = fopen(encrypted_path, "rb");
  if (!enc) {
    die("could not reopen the encrypted file");
  }
  uint8_t read_header[DSTU_SECRETSTREAM_HEADER_BYTES];
  if (fread(read_header, 1, sizeof(read_header), enc) != sizeof(read_header)) {
    die("could not read the stream header");
  }
  DstuPullState *pull = dstu_secretstream_pull_init(key, read_header);

  FILE *dec = fopen(decrypted_path, "wb");
  if (!dec) {
    die("could not create the decrypted output file");
  }
  size_t total_written = 0;
  for (;;) {
    uint8_t tag_byte;
    uint32_t len;
    uint8_t tag_bytes[DSTU_SECRETSTREAM_TAG_BYTES];
    if (!read_chunk(enc, &tag_byte, cipher_buf, sizeof(cipher_buf), &len, tag_bytes)) {
      if (!dstu_secretstream_pull_is_finalized(pull)) {
        die("input ended before a Final chunk was seen - truncated stream");
      }
      break;
    }
    DstuTag out_tag;
    if (dstu_secretstream_pull(pull, tag_byte, cipher_buf, len, tag_bytes, plain_buf, len, &out_tag) !=
        DSTU_OK) {
      die("pull failed - tampered or out-of-order chunk");
    }
    fwrite(plain_buf, 1, len, dec);
    total_written += len;
    if (out_tag == DSTU_TAG_FINAL) {
      break;
    }
  }
  fclose(enc);
  fclose(dec);
  dstu_secretstream_pull_free(pull);
  printf("decrypted %zu bytes into %s\n", total_written, decrypted_path);

  /* Verify the round trip actually reproduced the original file byte-for-byte. */
  FILE *a = fopen(plain_path, "rb");
  FILE *b = fopen(decrypted_path, "rb");
  if (!a || !b) {
    die("could not reopen files for comparison");
  }
  int ca, cb;
  int mismatch = 0;
  do {
    ca = fgetc(a);
    cb = fgetc(b);
    if (ca != cb) {
      mismatch = 1;
      break;
    }
  } while (ca != EOF);
  fclose(a);
  fclose(b);
  if (mismatch) {
    die("round trip did not reproduce the original file");
  }
  printf("round trip verified byte-for-byte OK\n");

  remove(plain_path);
  remove(encrypted_path);
  remove(decrypted_path);
  dstu_secretstream_key_free(key);
  return 0;
}

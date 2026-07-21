/*
 * One-time offline generator for Strumok "gray" test vectors - NOT a CI harness, NOT run
 * automatically. Compiles directly against the pinned oracles/strumok-dstu8845/ source (see
 * ORACLES.md/DECISIONS.md for the pinned commit and why these vectors are labeled "gray" rather
 * than official). Re-run only if the gray-vector set needs to be regenerated/extended:
 *
 *   gcc -O2 -I ../../../oracles/strumok-dstu8845 generate_gray_vectors.c \
 *       ../../../oracles/strumok-dstu8845/strumok.c -o generate_gray_vectors
 *   ./generate_gray_vectors
 *
 * Output feeds crates/dstu-core/tests/vectors/strumok/gray/*.json by hand (small, fixed set of
 * cases - not worth a second script to auto-format JSON for six lines of output).
 *
 * Prints one line per case: name key_size_bytes key_hex iv_hex output_len keystream_hex
 * The keystream is the raw output of dstu8845_crypt() over an all-zero input buffer, i.e. the
 * keystream itself (crypt XORs with the input, so zero-in yields keystream-out directly).
 */

#include "strumok.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
}

static void run_case(const char *name, const uint64_t *key, uint8_t key_size, const uint64_t *iv, size_t out_len)
{
    Dstu8845Ctx *ctx = dstu8845_alloc();
    dstu8845_init(ctx, key, key_size, iv);

    uint8_t zero[512] = { 0 };
    uint8_t out[512] = { 0 };
    dstu8845_crypt(ctx, zero, out_len, out);

    printf("%s %u ", name, (unsigned)key_size);
    print_hex((const uint8_t *)key, key_size);
    printf(" ");
    print_hex((const uint8_t *)iv, 32);
    printf(" %u ", (unsigned)out_len);
    print_hex(out, out_len);
    printf("\n");

    dstu8845_free(ctx);
}

int main(void)
{
    uint64_t iv_a[4] = { 1, 2, 3, 4 };
    uint64_t iv_b[4] = { 0x1122334455667788ULL, 0, 0, 0 };

    uint64_t key256_zero[4] = { 0, 0, 0, 0 };
    uint64_t key256_a[4] = { 0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL,
                              0x1011121314151617ULL, 0x18191A1B1C1D1E1FULL };

    uint64_t key512_zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint64_t key512_a[8] = { 0x0001020304050607ULL, 0x08090A0B0C0D0E0FULL,
                             0x1011121314151617ULL, 0x18191A1B1C1D1E1FULL,
                             0x2021222324252627ULL, 0x28292A2B2C2D2E2FULL,
                             0x3031323334353637ULL, 0x38393A3B3C3D3E3FULL };

    run_case("256_zero_key_ivA_len8", key256_zero, 32, iv_a, 8);
    run_case("256_zero_key_ivA_len64", key256_zero, 32, iv_a, 64);
    run_case("256_a_key_ivB_len137", key256_a, 32, iv_b, 137);
    run_case("512_zero_key_ivA_len8", key512_zero, 64, iv_a, 8);
    run_case("512_zero_key_ivA_len64", key512_zero, 64, iv_a, 64);
    run_case("512_a_key_ivB_len137", key512_a, 64, iv_b, 137);

    return 0;
}

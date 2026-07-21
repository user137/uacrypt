/*
 * Reproduces oracles/strumok-dstu8845/'s (outspace, BSD-2-Clause) keystream output for the exact
 * key/IV inputs used by oracles/uapki/library/uapkic/src/dstu8845.c's dstu8845_self_test()
 * (commit c64181c3b1cd437139119d83bffb5ab090b1cdd6, comment-attributed to "ДСТУ 8845:2019" in that
 * source) - the same inputs behind crates/dstu-core/tests/vectors/strumok/keystream-{256,512}.json.
 *
 * This is a consistency bonus, NOT independent-oracle confirmation: outspace and UAPKI's
 * dstu8845.c share identical internal function/table names (dstu8845_init, dstu8845_crypt,
 * T0..T7), a strong signal of shared lineage rather than two people implementing from the
 * standard independently - see ORACLES.md/DECISIONS.md D-15 for the full reasoning. Not a CI
 * harness, not run automatically - a one-time check, kept for reproducibility.
 *
 *   gcc -O2 -I ../../../oracles/strumok-dstu8845 cross_check_against_uapki.c \
 *       ../../../oracles/strumok-dstu8845/strumok.c -o cross_check_against_uapki
 *   ./cross_check_against_uapki
 *
 * Prints one line per case: name keystream_hex - compare by eye (or diff) against the
 * "keystream_hex" fields in the sibling vectors/strumok/keystream-{256,512}.json files.
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

static void run_case(const char *name, const uint64_t *key, uint8_t key_size, const uint64_t *iv)
{
    Dstu8845Ctx *ctx = dstu8845_alloc();
    dstu8845_init(ctx, key, key_size, iv);

    uint8_t zero[64] = { 0 };
    uint8_t out[64] = { 0 };
    dstu8845_crypt(ctx, zero, 64, out);

    printf("%s ", name);
    print_hex(out, 64);
    printf("\n");

    dstu8845_free(ctx);
}

int main(void)
{
    /* Byte layout matches dstu8845_init()'s raw memcpy from a ByteArray - see UAPKI's
     * uint8_to_uint64() (byte-utils-internal.c): no big-endian reinterpretation, so UAPKI's
     * iv_2 = {0x01,0,...,0, 0x02,0,...,0, 0x03,0,...,0, 0x04,0,...,0} is the uint64_t[4]{1,2,3,4}
     * below, and k*_1's trailing 0x80 byte is the top word's 0x8000000000000000. */
    uint64_t iv_1[4] = { 0, 0, 0, 0 };
    uint64_t iv_2[4] = { 1, 2, 3, 4 };

    uint64_t k256_1[4] = { 0, 0, 0, 0x8000000000000000ULL };
    uint64_t k256_2[4] = { 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
                            0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL };
    uint64_t k512_1[8] = { 0, 0, 0, 0, 0, 0, 0, 0x8000000000000000ULL };
    uint64_t k512_2[8] = { 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
                            0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
                            0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
                            0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL };

    run_case("256_k1_iv1", k256_1, 32, iv_1);
    run_case("256_k2_iv1", k256_2, 32, iv_1);
    run_case("256_k1_iv2", k256_1, 32, iv_2);
    run_case("256_k2_iv2", k256_2, 32, iv_2);
    run_case("512_k1_iv1", k512_1, 64, iv_1);
    run_case("512_k2_iv1", k512_2, 64, iv_1);
    run_case("512_k1_iv2", k512_1, 64, iv_2);
    run_case("512_k2_iv2", k512_2, 64, iv_2);

    return 0;
}

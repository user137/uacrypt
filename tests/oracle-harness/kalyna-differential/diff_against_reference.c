/*
 * Differential test: reads random Kalyna cases (variant, key, block, and this project's own
 * Rust ciphertext for each) from stdin - produced by
 * `cargo run --example kalyna_diff_cases -p dstu-core` - recomputes the ciphertext independently
 * via oracles/kalyna-reference/ (Roman Oliynykov et al., the algorithm's own author, verify-only,
 * no license - see ORACLES.md), and reports any mismatch. See DECISIONS.md D-24 for why this
 * exists: same pattern as the Strumok differential harness (D-22), added for parity so Kalyna
 * and Kupyna get the same random-input scrutiny Strumok got, not less.
 *
 * Build and run (from this directory):
 *   gcc -O2 -I ../../../oracles/kalyna-reference diff_against_reference.c \
 *       ../../../oracles/kalyna-reference/kalyna.c \
 *       ../../../oracles/kalyna-reference/tables.c -o diff_against_reference
 *   cargo run --example kalyna_diff_cases -p dstu-core --release -- 500 | ./diff_against_reference
 *
 * Not a CI harness (no C toolchain dependency wired into `cargo test`) - a manually-run
 * cross-check, same category as the Strumok/UAPKI harnesses.
 */

#include "kalyna.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static long hex_decode(const char *hex, uint8_t *out)
{
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (long)(len / 2);
}

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
}

/* variant is "<block_bits>-<key_bits>", e.g. "128-128" - matches KalynaInit's own parameter
 * order/units, and this project's own Rust variant names read the same way. */
static int parse_variant(const char *variant, size_t *block_bits, size_t *key_bits)
{
    return sscanf(variant, "%zu-%zu", block_bits, key_bits) == 2;
}

int main(void)
{
    char line[512];
    long case_no = 0;
    long mismatches = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char variant_str[16];
        char key_hex[256];
        char block_hex[256];
        char expected_hex[256];

        int matched = sscanf(line, "%15s %255s %255s %255s", variant_str, key_hex, block_hex,
                              expected_hex);
        if (matched != 4) {
            if (line[0] == '\n' || line[0] == '\0') continue;
            fprintf(stderr, "skipping malformed line: %s", line);
            continue;
        }
        case_no++;

        size_t block_bits, key_bits;
        if (!parse_variant(variant_str, &block_bits, &key_bits)) {
            fprintf(stderr, "case %ld: unrecognized variant %s, skipping\n", case_no,
                    variant_str);
            continue;
        }

        uint8_t key_bytes[64];
        uint8_t block_bytes[64];
        uint8_t expected[64];
        long key_len = hex_decode(key_hex, key_bytes);
        long block_len = hex_decode(block_hex, block_bytes);
        long ct_len = hex_decode(expected_hex, expected);
        if (key_len < 0 || block_len < 0 || ct_len < 0) {
            fprintf(stderr, "case %ld: malformed hex, skipping\n", case_no);
            continue;
        }

        /* Raw little-endian word packing - see kalyna-reference/main.c's own print()/vector
         * layout and this project's DECISIONS.md D-13: byte i of the input maps to word i/8,
         * byte i%8 of that word. A plain memcpy onto uint64_t[] does this on a little-endian
         * host (x86_64), same convention as the Strumok harness. */
        uint64_t key_words[8] = { 0 };
        uint64_t block_words[8] = { 0 };
        memcpy(key_words, key_bytes, (size_t)key_len);
        memcpy(block_words, block_bytes, (size_t)block_len);

        kalyna_t *ctx = KalynaInit(block_bits, key_bits);
        if (ctx == NULL) {
            fprintf(stderr, "case %ld: KalynaInit(%zu, %zu) failed, skipping\n", case_no,
                    block_bits, key_bits);
            continue;
        }
        KalynaKeyExpand(key_words, ctx);

        uint64_t ciphertext_words[8] = { 0 };
        KalynaEncipher(block_words, ctx, ciphertext_words);
        KalynaDelete(ctx);

        uint8_t ciphertext_bytes[64] = { 0 };
        memcpy(ciphertext_bytes, ciphertext_words, (size_t)ct_len);

        if (memcmp(ciphertext_bytes, expected, (size_t)ct_len) != 0) {
            mismatches++;
            printf("[MISMATCH] case %ld (%s): rust=", case_no, variant_str);
            print_hex(expected, (size_t)ct_len);
            printf(" reference=");
            print_hex(ciphertext_bytes, (size_t)ct_len);
            printf("\n");
        }
    }

    printf("%ld cases checked, %ld mismatches\n", case_no, mismatches);
    return mismatches == 0 ? 0 : 1;
}

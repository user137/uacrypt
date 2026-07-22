/*
 * Differential test: reads random Strumok cases (variant, key, IV, and this project's own Rust
 * keystream output for each) from stdin - produced by
 * `cargo run --example strumok_diff_cases -p dstu-core` - recomputes the keystream independently
 * via oracles/strumok-dstu8845/ (outspace, BSD-2-Clause), and reports any mismatch.
 *
 * Why this matters specifically for Strumok (see TASKS.md "Testing & hardening",
 * DECISIONS.md D-15/D-18): no official DSTU 8845:2019 test vectors exist anywhere in this
 * project's holdings, and the 8 UAPKI-attributed fixed vectors already adopted cover a narrow
 * slice of the key/IV/length space. This does not fix that provenance gap (outspace shares
 * lineage with UAPKI - not independent confirmation, see D-15) but it does exercise far more of
 * the state space against a real second implementation than 8 fixed points can.
 *
 * Build and run (from this directory):
 *   gcc -O2 -I ../../../oracles/strumok-dstu8845 diff_against_outspace.c \
 *       ../../../oracles/strumok-dstu8845/strumok.c -o diff_against_outspace
 *   cargo run --example strumok_diff_cases -p dstu-core --release -- 500 | ./diff_against_outspace
 *
 * Not a CI harness (no C toolchain dependency wired into `cargo test`) - a manually-run
 * cross-check, same category as the sibling strumok-cross-check/ harness.
 */

#include "strumok.h"
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

/* Decodes `hex` (even-length, no separators) into `out`, returns the byte count, or -1 on a
 * malformed string. `out` must have room for strlen(hex)/2 bytes. */
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

int main(void)
{
    /* variant(3-4) key_hex(<=129) iv_hex(65) keystream_hex(<=601), plus separators/newline */
    char line[2048];
    long case_no = 0;
    long mismatches = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char variant_str[8];
        char key_hex[256];
        char iv_hex[128];
        char expected_hex[1024];

        int matched = sscanf(line, "%7s %255s %127s %1023s", variant_str, key_hex, iv_hex,
                              expected_hex);
        if (matched != 4) {
            if (line[0] == '\n' || line[0] == '\0') continue;
            fprintf(stderr, "skipping malformed line: %s", line);
            continue;
        }
        case_no++;

        uint8_t key_bytes[64];
        uint8_t iv_bytes[32];
        uint8_t expected[512];

        long key_len = hex_decode(key_hex, key_bytes);
        long iv_len = hex_decode(iv_hex, iv_bytes);
        long ks_len = hex_decode(expected_hex, expected);
        if (key_len < 0 || iv_len != 32 || ks_len < 0) {
            fprintf(stderr, "case %ld: malformed hex, skipping\n", case_no);
            continue;
        }

        /* uint8_to_uint64 in both oracles is a raw memcpy on a little-endian host (x86_64) - see
         * DECISIONS.md D-15/the sibling harness's comment for the established convention. */
        uint64_t key_words[8] = { 0 };
        uint64_t iv_words[4] = { 0 };
        memcpy(key_words, key_bytes, (size_t)key_len);
        memcpy(iv_words, iv_bytes, (size_t)iv_len);

        uint8_t buf[512] = { 0 };
        Dstu8845Ctx *ctx = dstu8845_alloc();
        dstu8845_init(ctx, key_words, (uint8_t)key_len, iv_words);
        dstu8845_crypt(ctx, buf, (size_t)ks_len, buf);
        dstu8845_free(ctx);

        if (memcmp(buf, expected, (size_t)ks_len) != 0) {
            mismatches++;
            printf("[MISMATCH] case %ld (%s): rust=", case_no, variant_str);
            print_hex(expected, (size_t)ks_len);
            printf(" outspace=");
            print_hex(buf, (size_t)ks_len);
            printf("\n");
        }
    }

    printf("%ld cases checked, %ld mismatches\n", case_no, mismatches);
    return mismatches == 0 ? 0 : 1;
}

/*
 * Differential test: reads random Kupyna cases (variant, message, and this project's own Rust
 * digest for each) from stdin - produced by
 * `cargo run --example kupyna_diff_cases -p dstu-core` - recomputes the digest independently via
 * oracles/kupyna-reference/ (Roman Oliynykov et al., the algorithm's own author, verify-only, no
 * license - see ORACLES.md), and reports any mismatch. See DECISIONS.md D-24 for why this exists:
 * same pattern as the Strumok/Kalyna differential harnesses (D-22), added for parity.
 *
 * Build and run (from this directory):
 *   gcc -O2 -I ../../../oracles/kupyna-reference diff_against_reference.c \
 *       ../../../oracles/kupyna-reference/kupyna.c \
 *       ../../../oracles/kupyna-reference/tables.c -o diff_against_reference
 *   cargo run --example kupyna_diff_cases -p dstu-core --release -- 1000 | ./diff_against_reference
 *
 * Not a CI harness (no C toolchain dependency wired into `cargo test`) - a manually-run
 * cross-check, same category as the other oracle-harness/*-differential directories.
 */

#include "kupyna.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGE_BYTES 500
#define MAX_HASH_BYTES 64

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static long hex_decode(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > out_cap) return -1;
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
    static char line[MAX_MESSAGE_BYTES * 2 + MAX_HASH_BYTES * 2 + 64];
    static char message_hex[MAX_MESSAGE_BYTES * 2 + 8];
    long case_no = 0;
    long mismatches = 0;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        char variant_str[8];
        char hash_hex[160];

        int matched =
            sscanf(line, "%7s %1007[0-9A-Fa-f] %159s", variant_str, message_hex, hash_hex);
        if (matched != 3) {
            if (line[0] == '\n' || line[0] == '\0') continue;
            fprintf(stderr, "skipping malformed line\n");
            continue;
        }
        case_no++;

        size_t hash_nbits = (size_t)atoi(variant_str);
        if (hash_nbits != 256 && hash_nbits != 512) {
            fprintf(stderr, "case %ld: unrecognized variant %s, skipping\n", case_no,
                    variant_str);
            continue;
        }

        static uint8_t message[MAX_MESSAGE_BYTES];
        uint8_t expected[MAX_HASH_BYTES];
        long msg_len = hex_decode(message_hex, message, sizeof(message));
        long hash_len = hex_decode(hash_hex, expected, sizeof(expected));
        if (msg_len < 0 || hash_len < 0) {
            fprintf(stderr, "case %ld: malformed hex, skipping\n", case_no);
            continue;
        }

        kupyna_t ctx;
        if (KupynaInit(hash_nbits, &ctx) != 0) {
            fprintf(stderr, "case %ld: KupynaInit(%zu) failed, skipping\n", case_no, hash_nbits);
            continue;
        }

        uint8_t computed[MAX_HASH_BYTES] = { 0 };
        KupynaHash(&ctx, message, (size_t)msg_len * 8, computed);

        if (memcmp(computed, expected, (size_t)hash_len) != 0) {
            mismatches++;
            printf("[MISMATCH] case %ld (Kupyna-%s): rust=", case_no, variant_str);
            print_hex(expected, (size_t)hash_len);
            printf(" reference=");
            print_hex(computed, (size_t)hash_len);
            printf("\n");
        }
    }

    printf("%ld cases checked, %ld mismatches\n", case_no, mismatches);
    return mismatches == 0 ? 0 : 1;
}

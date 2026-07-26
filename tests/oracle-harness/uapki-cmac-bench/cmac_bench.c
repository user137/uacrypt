/*
 * Byte-for-byte and timing comparison of DSTU 7624 CMAC (Kalyna-CMAC) between this project's own
 * `uacrypt kalyna-cmac compute`/`verify` and UAPKI's prebuilt `uapkic.dll`, for all 5 Kalyna
 * variants - `TASKS.md` T-133/T-138, `DECISIONS.md` D-78/D-80/D-82 have the full narrative behind
 * why this exists and what it already found (a real UAPKI CMAC-context-reuse quirk, D-82).
 *
 * Unlike this directory's siblings (kalyna-differential/, strumok-cross-check/, which link
 * directly against vendored oracle *source*), UAPKI is compared against its official prebuilt
 * Windows DLL, not a from-source build - `oracles/uapki/` (gitignored, see ORACLES.md for how to
 * fetch it) only vendors the source tree for reading/citation, not a ready-to-link Windows import
 * library.
 *
 * Build (Windows/MinGW - `gendef`/`dlltool`/`gcc` via the WinLibs toolchain, see
 * `.claude.local.md`'s "UAPKI comparison-wrapper build recipe"):
 *   gh release download v2.0.12 --repo specinfo-ua/UAPKI --pattern "*win-amd64-signed.zip"
 *   unzip -o uapki-v2.0.12-win-amd64-signed.zip -d extracted
 *   cp extracted/uapki-v2.0.12-win-amd64-signed/uapkic.dll .
 *   gendef uapkic.dll
 *   dlltool -d uapkic.def -l libuapkic.a -D uapkic.dll
 *   gcc -O2 -o cmac_bench cmac_bench.c \
 *       -I ../../../oracles/uapki/library/uapkic/include -L. -luapkic
 *
 * Usage: cmac_bench <variant> <key_path> <in_path> <out_path> <iterations>
 *   <variant> is one of 128-128/128-256/256-256/256-512/512-512 (block-bits-key-bits, matching
 *   `uacrypt`'s own `--variant` naming). Writes the first iteration's 16-byte tag to <out_path> -
 *   compare it byte-for-byte against `uacrypt kalyna-cmac compute`'s own `--out` file before
 *   trusting any timing from a fresh run. Prints `iterations=.. total_ns=.. per_op_ns=..` to
 *   stderr, matching `uacrypt`'s own `--iterations` convention exactly so the two numbers are
 *   directly comparable.
 *
 * IMPORTANT, found and confirmed by direct experiment (D-82), not assumed: `dstu7624_final_mac`
 * never resets its CMAC chaining state (`ctx->state`) or buffered-tail length -
 * `dstu7624_init_cmac`'s call to `dstu7624_init` is the only code path that zeroes them. Calling
 * `dstu7624_update_mac`/`dstu7624_final_mac` repeatedly on the same `ctx` without re-initializing
 * therefore produces a DIFFERENT tag on every call past the first, even for the identical message
 * - confirmed directly with a throwaway probe (4 repeated calls, 4 distinct tags). This does NOT
 * invalidate a multi-iteration throughput measurement: Kalyna's block cipher
 * (`crypt_basic_transform`) has no secret- or length-dependent branching, so every iteration still
 * performs the identical amount of work regardless of what garbage is in `ctx->state` - only the
 * *value* past iteration 0 is not independently meaningful. That is exactly why this program only
 * writes out iteration 0's tag: correctness is established by that single fresh-`ctx` byte
 * comparison, not by anything computed later in the timed loop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "byte-array.h"
#include "dstu7624.h"

typedef struct {
    const char *name;
    size_t key_len;
    size_t block_len;
} Variant;

static const Variant VARIANTS[] = {
    {"128-128", 16, 16},
    {"128-256", 32, 16},
    {"256-256", 32, 32},
    {"256-512", 64, 32},
    {"512-512", 64, 64},
};

static uint64_t now_ns(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint8_t *read_file(const char *path, size_t expected_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    uint8_t *buf = malloc(expected_len);
    size_t got = fread(buf, 1, expected_len, f);
    if (got != expected_len) {
        fprintf(stderr, "short read on %s (%zu != %zu)\n", path, got, expected_len);
        exit(1);
    }
    fclose(f);
    return buf;
}

static void write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "cannot open %s for write\n", path);
        exit(1);
    }
    fwrite(buf, 1, len, f);
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: cmac_bench <variant> <key_path> <in_path> <out_path> <iterations>\n");
        return 1;
    }
    const char *variant_name = argv[1];
    const char *key_path = argv[2];
    const char *in_path = argv[3];
    const char *out_path = argv[4];
    long iterations = atol(argv[5]);
    if (iterations < 1) {
        iterations = 1;
    }

    const Variant *v = NULL;
    for (size_t i = 0; i < sizeof(VARIANTS) / sizeof(VARIANTS[0]); i++) {
        if (strcmp(VARIANTS[i].name, variant_name) == 0) {
            v = &VARIANTS[i];
            break;
        }
    }
    if (!v) {
        fprintf(stderr, "unknown variant %s\n", variant_name);
        return 1;
    }

    uint8_t *key_buf = read_file(key_path, v->key_len);
    FILE *fin = fopen(in_path, "rb");
    if (!fin) {
        fprintf(stderr, "cannot open %s\n", in_path);
        return 1;
    }
    fseek(fin, 0, SEEK_END);
    long msg_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    uint8_t *msg_buf = malloc((size_t)msg_len);
    if (fread(msg_buf, 1, (size_t)msg_len, fin) != (size_t)msg_len) {
        fprintf(stderr, "short read on %s\n", in_path);
        return 1;
    }
    fclose(fin);

    ByteArray *key = ba_alloc_from_uint8(key_buf, v->key_len);
    ByteArray *msg = ba_alloc_from_uint8(msg_buf, (size_t)msg_len);

    /* One-time setup - alloc + init_cmac (full Kalyna key-schedule expansion) - excluded from the
       timed window, matching uacrypt's own cached-ExpandedKey convention and D-80's fix. */
    Dstu7624Ctx *ctx = dstu7624_alloc(DSTU7624_SBOX_1);
    if (!ctx) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    int ret = dstu7624_init_cmac(ctx, key, v->block_len, 16);
    if (ret != 0) {
        fprintf(stderr, "init_cmac failed: %d\n", ret);
        return 1;
    }

    uint8_t first_tag[16];
    uint64_t t0 = now_ns();
    for (long i = 0; i < iterations; i++) {
        ByteArray *mac = NULL;
        ret = dstu7624_update_mac(ctx, msg);
        if (ret != 0) {
            fprintf(stderr, "update_mac failed: %d\n", ret);
            return 1;
        }
        ret = dstu7624_final_mac(ctx, &mac);
        if (ret != 0) {
            fprintf(stderr, "final_mac failed: %d\n", ret);
            return 1;
        }
        if (i == 0) {
            memcpy(first_tag, ba_get_buf_const(mac), 16);
        }
        ba_free(mac);
    }
    uint64_t t1 = now_ns();

    write_file(out_path, first_tag, 16);

    uint64_t total_ns = t1 - t0;
    uint64_t per_op_ns = (uint64_t)(total_ns / (uint64_t)iterations);
    fprintf(stderr, "iterations=%ld total_ns=%llu per_op_ns=%llu\n", iterations,
            (unsigned long long)total_ns, (unsigned long long)per_op_ns);

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(msg);
    free(key_buf);
    free(msg_buf);
    return 0;
}

/*
 * Runs dstu-core's Kalyna GCM/GMAC/CCM/CMAC vectors through UAPKI's uapkic 2.0.3 (D-231). Driven by
 * run_oracle.py; not a CI harness. Pinned to specinfo-ua/UAPKI main 0bf2b68 (2026-09-30), which
 * carries the 2.0.3 mode rewrite (deffe4a); uapkic 2.0.2 and older use the pre-standard modes.
 *
 *   git clone https://github.com/specinfo-ua/UAPKI && git -C UAPKI checkout 0bf2b68
 *   cd UAPKI/library/uapkic
 *   gcc -O1 -DUAPKIC_STATIC '-DUAPKIC_VERSION_STRING="3.0.0"' -I include -I src \
 *       <this dir>/uapki_oracle.c src/*.c -o uapki_oracle.exe -lbcrypt     (-lbcrypt: Windows only)
 *   python <this dir>/run_oracle.py <path to uapki_oracle.exe>
 *
 * stdin: one case per line, "<mode> <block_bytes> <q> <n_max> <key> <iv> <aad> <data>", hex, "-" = empty.
 * stdout: "OK <out_hex> <tag_hex>" (ccm: <tag_hex> is the masked tail of cipher_data) or "ERR <rc>".
 */
#include <stdio.h>
#include <string.h>
#include "dstu7624.h"
#include "byte-array.h"

static ByteArray *from_hex(const char *h) {
    return strcmp(h, "-") == 0 ? ba_alloc() : ba_alloc_from_hex(h);
}

static void hex(const ByteArray *ba, size_t off, size_t n) {
    if (n == 0) printf("-");
    for (size_t i = 0; i < n; i++) printf("%02X", ba_get_buf_const(ba)[off + i]);
}

int main(void) {
    static char mode[16], k[300], iv[300], aad[20000], data[20000];
    size_t bl, q, nmax;
    while (scanf("%15s %zu %zu %zu %299s %299s %19999s %19999s", mode, &bl, &q, &nmax, k, iv, aad, data) == 8) {
        ByteArray *key = from_hex(k), *ivb = from_hex(iv), *a = from_hex(aad), *d = from_hex(data);
        ByteArray *tag = NULL, *out = NULL;
        Dstu7624Ctx *c = dstu7624_alloc(DSTU7624_SBOX_1);
        int rc;
        if (strcmp(mode, "gcm") == 0) {
            rc = dstu7624_init_gcm(c, key, ivb, q);
            if (!rc) rc = dstu7624_encrypt_mac(c, a, d, &tag, &out);
        } else if (strcmp(mode, "ccm") == 0) {
            rc = dstu7624_init_ccm(c, key, ivb, q, nmax);
            if (!rc) rc = dstu7624_encrypt_mac(c, a, d, &tag, &out);
        } else {
            rc = strcmp(mode, "gmac") == 0 ? dstu7624_init_gmac(c, key, bl, q) : dstu7624_init_cmac(c, key, bl, q);
            if (!rc) rc = dstu7624_update_mac(c, d);
            if (!rc) rc = dstu7624_final_mac(c, &tag);
        }
        if (rc) {
            printf("ERR %d\n", rc);
        } else if (strcmp(mode, "ccm") == 0) {
            size_t p = ba_get_len(d);
            printf("OK "); hex(out, 0, p); printf(" "); hex(out, p, ba_get_len(out) - p); printf("\n");
        } else {
            printf("OK "); hex(out, 0, out ? ba_get_len(out) : 0); printf(" "); hex(tag, 0, ba_get_len(tag)); printf("\n");
        }
        fflush(stdout);
        dstu7624_free(c);
        ba_free(tag); ba_free(out); ba_free(key); ba_free(ivb); ba_free(a); ba_free(d);
    }
    return 0;
}

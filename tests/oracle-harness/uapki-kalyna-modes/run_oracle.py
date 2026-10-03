"""Feeds every kalyna-{gcm,gmac,ccm,cmac} vector to uapki_oracle.exe and compares (D-231).

Usage: python run_oracle.py <path to uapki_oracle.exe> [-v]
Expected against UAPKI 0bf2b68: 78/93 identical; the 15 differences are all CCM with an empty
AAD (UAPKI reads section 13.2's "B = G1" literally, dstu-core reads it as T(G1), D-205 (b)).
"""
import glob
import json
import os
import subprocess
import sys

VEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                   "crates", "dstu-core", "tests", "vectors")


def h(x):
    return x if x else "-"


def main():
    exe = sys.argv[1]
    rows = []
    for path in sorted(glob.glob(os.path.join(VEC, "kalyna-*", "*.json"))):
        mode = os.path.basename(os.path.dirname(path)).split("-")[1]
        if mode not in ("gcm", "gmac", "ccm", "cmac"):
            continue
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        bl = d["block_bits"] // 8
        for i, c in enumerate(d["cases"]):
            if mode == "ccm":
                line = (mode, bl, d["tag_bytes"], 8 * d["ccm_nb"], c["key_hex"], c["nonce_hex"],
                        h(c["aad_hex"]), h(c["plaintext_hex"]))
                exp = (c["ciphertext_hex"], c["tag_hex"])
            elif mode == "gcm":
                line = (mode, bl, len(c["tag_hex"]) // 2, 0, c["key_hex"], c["iv_hex"],
                        h(c["aad_hex"]), h(c["plaintext_hex"]))
                exp = (c["ciphertext_hex"], c["tag_hex"])
            else:
                t = c.get("tag_hex") or c.get("mac_hex")
                line = (mode, bl, len(t) // 2, 0, c["key_hex"], "-", "-", h(c["message_hex"]))
                exp = ("", t)
            rows.append((os.path.relpath(path, VEC), i, c.get("aad_hex"), line, exp))

    inp = "".join(" ".join(str(x) for x in r[3]) + "\n" for r in rows)
    out = subprocess.run([exe], input=inp, capture_output=True, text=True, check=True).stdout.splitlines()
    if len(out) != len(rows):
        sys.exit(f"harness printed {len(out)} lines for {len(rows)} cases")
    same = 0
    for (f, i, aad, _, exp), got in zip(rows, out):
        parts = got.split()
        ok = (parts[0] == "OK"
              and ("" if parts[1] == "-" else parts[1]).upper() == exp[0].upper()
              and parts[2].upper() == exp[1].upper())
        same += ok
        if not ok or "-v" in sys.argv:
            note = " (CCM, empty AAD)" if f.startswith("kalyna-ccm") and aad == "" else ""
            print("SAME" if ok else "DIFF", f, i, got[:60] + note)
    print(f"{same}/{len(rows)} cases identical")


if __name__ == "__main__":
    main()

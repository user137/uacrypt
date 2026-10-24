# Ecosystem integration: OpenSSL, PKCS#11, CMS/CAdES and key formats, browser

Research of 2026-10-24 (owner request: "which PKCS do we need, to plug into OpenSSL or others, and
through them reach browsers and other consumers?"). It covers four paths in the order the owner
asked, then the topic as a whole.

**Method.** Four read-only research agents read the governing standards and code directly. Claude
then re-checked every claim that drives a recommendation, plus the repo itself. Six role reviews
followed: senior developer, architect, QA, project manager, AI engineer and security engineer.

**Status.** This is analysis, not a decision. Every verdict and the never-do list are
recommendations until the owner confirms them (T-320). The owner's decisions are tracked as T-320/T-321;
the verdicts are recorded in `docs/DECISIONS.md` D-265.

**Tags.**
- [V]: verified from a primary source or artefact.
- [V✔]: re-checked by Claude in this session.
- [I]: inferred.
- [S]: secondary source only (news, search snippet).

**Legal caveat.** Every legal point below is an AI reading of Ukrainian acts. It is input for a
lawyer, not legal advice.

**Scope.** This document does not change `docs/DECISIONS.md` D-17 (this repo is primitives only;
ASN.1, X.509, CMS, PKCS#11/12 and browser signing are "not this project's job"), D-118 (browser/WASM
deferred) or T-201 (PKCS#11 as a sibling project). Where a recommendation would change one of them,
it is listed as an owner decision.

## 0. The facts that frame every path

1. **The national combination changed on 2026-09-01.** [V✔]
   - CMU resolution No. 920 of 15.07.2026 (https://zakon.rada.gov.ua/laws/show/920-2026-%D0%BF),
     items 2-4, in force from 1 September 2026. DSTU 4145 in qualified-signature tools is used
     "із застосуванням ДСТУ 7564:2014 … та ДСТУ 7624:2014", and GOST 34.311-95 is removed from the
     list.
   - Other signature algorithms are allowed "у спосіб, визначений ДСТУ ETSI TS 119 312:2022", so
     DSTU 4145 is the national option, not the only one.
   - Qualified certificates with ECDSA/RSA are reported for ДПС and ЗСУ. [S]
2. **Real artefacts confirm the switch.** [V✔] `openssl asn1parse` of the public czo.gov.ua TEST
   samples (https://czo.gov.ua/testexamples) shows:
   - **Kupyna-era CMS.** Digest `1.2.804.2.1.1.1.1.2.2.1` (Kupyna-256), signature
     `1.2.804.2.1.1.1.1.3.6.1.1`.
   - **The key OID is unchanged:** `1.2.804.2.1.1.1.1.3.1.1`, "DSTU 4145-2002 little endian".
   - **The GOST-era sample** uses GOST 34.311.
   - **The Kupyna-era sample still embeds GOST-era CA certificates.** They sit in its CAdES-X-Long
     `certValues` unsigned attribute, not in `SignedData.certificates`: the outer signature OID
     `…1.3.1.1` directly precedes each certificate's signature BIT STRING (`openssl asn1parse`).
     UAPKI maps `…1.3.1.x` signatures to GOST 34.311. Verifying a chain therefore needs GOST
     34.311 for a transition period. No primary act was found that says
     how long; "systems must support both" comes from news only. [S]
3. **Bouncy Castle has no combined "DSTU 4145 with Kupyna" algorithm or OID.**
   - It registers only `GOST3411WITHDSTU4145(LE)`. [V]
   - `UAObjectIdentifiers` has only `1.3.1.1` and `1.3.1.1.1.1`, with no `1.3.6.x`. [V✔]
   - Its `DSTU4145Signer` does accept any hash: `hash2FieldElement` starts with
     `Arrays.reverse(hash)` (`oracles/bouncycastle-java/core/src/main/java/org/bouncycastle/crypto/signers/DSTU4145Signer.java`).
     [V✔]
   - So composing `DSTU7564Digest` with `DSTU4145Signer` is a candidate second oracle for new
     signatures. Whether real artefacts use that byte convention is exactly what T-318 must settle.
4. **UAPKI is the only public implementation of the full layer.** [V]
   - Repo: https://github.com/specinfo-ua/UAPKI. BSD-2, C, a cryptonite fork.
   - Coverage:
     - CAdES BES/T/C/XL/A and B-LT/B-LTA;
     - PKCS#12, JKS, Key-6.dat, a PKCS#11 client;
     - an Emscripten WASM build and a Native Messaging host.
   - It holds a 2021 state-expertise conclusion. That certificate covers that build; forks and
     rebuilds do not inherit it, and nothing this project builds would carry one either. [I]
   - This repo vendors only `uapkic` (primitives), not UAPKI's CMS layer.
5. **dstu-core cannot yet verify one real Ukrainian DSTU 4145 signature end to end.** [V✔]
   - `hazmat::dstu4145` m=257 has no point decompression. Real certificates carry a 33-byte
     little-endian compressed point.
   - Real certificates carry explicit curve parameters; dstu-core has the m=257 curve built in.
   - `crypto_sign257` uses its own wire format: a 66-byte uncompressed big-endian key and a 66-byte
     (33+33) big-endian signature. The UA CMS signature is 64 bytes,
     little-endian (= reverse(s‖r)).
   - So "we already implement what the 2026-09 rules mandate" holds at the primitive level only.
     It is unproven against real artefacts until T-318 passes.
6. **Signing and verifying differ in kind.** Verification handles only public data. The
   constant-time, key-custody, WASM and "qualified signature device" objections below apply to
   signing, decryption and key generation, not to verification.

## 1. OpenSSL provider

**Standards and sources**
- OpenSSL 4.1.0 man pages: provider(7), provider-base/-cipher/-digest/-mac/-signature/-keymgmt/
  -encoder/-decoder(7), property(7).
- Source: `crypto/x509/x_pubkey.c`, `crypto/asn1/a_verify.c`, `crypto/cms/cms_sd.c`,
  `ssl/s3_lib.c`, `ssl/t1_lib.c`.
- IANA TLS registries (2026-10-21), RFC 8446.

**Facts**
- **Engines are gone.** [V] OpenSSL 4.1.0 is current (2026-10-23), and 4.0 removed engines, so on
  4.x a provider is the only extension path.
- **LTS distributions ship 3.0.** [V] Ubuntu 22.04/24.04 and Debian 12 are on 3.0. Provider-based
  CMS signatures and TLS sigalgs need 3.2+. Debian 13 ships 3.5 and Ubuntu 26.04 ships 3.5.
- **OIDs.** [V]
  - OpenSSL already knows `dstu4145le` (`1.2.804.2.1.1.1.1.3.1.1`) and `uacurve0..9`.
  - It has no Kupyna/Kalyna OIDs and no DSTU sigid.
  - A provider must:
    - register OIDs and sigids (`core_obj_create`, `core_obj_add_sigid`);
    - name its keymgmt exactly `dstu4145le`;
    - ship DER/SubjectPublicKeyInfo/PKCS#8 encoders.
- **TLS.** [V]
  - Groups have been pluggable since 3.0 and sigalgs since 3.2 (TLS 1.3 only). Cipher suites are
    hard-coded.
  - IANA has no DSTU entries.
  - gost-engine carries a 793-line libssl patch for its own (IANA-registered) suites.
  - **Earlier I said "groups and sigalgs from 3.2"; groups date from 3.0.**
- **No DSTU provider exists anywhere.** dstucrypt/dstu-engine is an engine, so it is dead on 4.x.
  This is a negative search, so the claim is weaker than a positive finding.

**Pitfalls, ranked**
1. **Wide-block Kalyna versus EVP.** `EVP_MAX_IV_LENGTH` is 16. CMS and `enc` size stack buffers by
   that constant without checking the provider's IV length. Expose only 128-bit-block Kalyna.
   - This is a scope limit; the overflow itself is inferred, not reproduced. [I]
2. **AEAD streaming.** EVP decryption releases plaintext before the tag is checked. That
   contradicts dstu-core's "never unverified plaintext" (D-63/D-65), so no Kalyna GCM/CCM through
   EVP.
3. **Real UA artefacts need GOST 34.311 for chains**, and the sigid table is one-to-one.
4. **Key material crosses into OpenSSL** through OSSL_PARAM import/export and PKCS#8 encoding. A
   provider can keep keys in its own zeroizing objects; the export paths are the leak.
5. **Version spread:** 3.0/3.5/3.6/4.x, plus LibreSSL on macOS (no provider API) and no system
   OpenSSL on Windows.
6. **Exposing hazmat through a generic API** undoes D-47's misuse resistance.

**Sizes** [I] (excluding test infrastructure, which roughly doubles them):

| Scope | Size |
|---|---|
| Kupyna digest and Kalyna-128 cipher | S-M |
| DSTU 4145 signature, keymgmt and encoders | L |
| Real UA CMS/X.509 | L, or XL with GOST |
| TLS with private sigalgs, which works only between our own peers | M on top |
| Real DSTU TLS | not viable |

**Recommended verdict: defer.** A Kupyna and Kalyna-128 slice only on a named consumer's request. Never
wide-block Kalyna, never streaming AEAD through EVP, never libssl patches.
- Role scores (realism/niche/return, 1-5): about 2/4/2 across all six roles.

## 2. PKCS#11 (Cryptoki)

**Standards and sources**
- OASIS PKCS#11 3.1 base spec and profiles.
- 3.2 is an OASIS Standard (directory dated 2026-06-03). [V]
- NSS source, the Java SunPKCS11 guide (JDK 25), latchset/pkcs11-provider, GnuTLS, p11-kit, MS CNG.

**Facts**
- **Mechanisms.** [V]
  - Binary-field curves are expressible (`CKF_EC_F_2M`).
  - The DSTU 4145 signature equation is not ECDSA, so honest support needs vendor-defined
    CKK/CKM.
  - GOST R 34.10 is a registered precedent: `CKM_GOSTR3410` is a raw 32-byte prehash mechanism.
- **No mainstream consumer would use a DSTU key without code changes.** [V]
  - NSS has a closed `KeyType` enum.
  - SunPKCS11 has a fixed algorithm table.
  - pkcs11-provider covers ec/rsa/ml-dsa/... only.
  - GnuTLS does not handle even GOST.
  - p11-kit RPC drops vendor mechanisms through a whitelist.
  - Windows CNG has no PKCS#11 path.
  - **Earlier I said "NSS uses only mechanisms it knows"; confirmed** for its high-level layers.
    NSS's low-level `PK11_SignWithMechanism` passes anything through, but only from an
    application's own code.
- **Real consumers are Ukrainian PKI stacks**: UAPKI cm-pkcs11, IIT and Avtor, used for CMS document
  signing.
- **The constant set is de facto only.** [V] It is `VENDOR_DEFINED + 0x0042xxxx`, and two public
  client headers agree on it (UAPKI `pkcs11t-ua.h`, edenlab `uacryptoki.h`). There is no vendor or
  official specification. Both headers `#undef`/redefine the OASIS GOST names, which is a collision
  hazard.
- **Certified hardware tokens already exist** (Алмаз-1К, SecureToken-337, Гряда, Diamond HSM).
- **A soft token makes advanced, not qualified, signatures.** [V; I applied]
  - A qualified signature needs a certified qualified signature-creation device (Law 2155-VIII
    art. 19(5)).
  - A soft token can give at most an advanced signature based on a qualified certificate (art. 1
    item 59).
- **T-201 correction.** capi has the right prehash shape: `dstu_sign257_digest`/`_verify257_digest`,
  32 bytes. The real gaps are elsewhere:
  - only the 66-byte uncompressed big-endian key crosses the ABI;
  - the curve is hard-coded;
  - there is no 48/64-byte prehash.

**Pitfalls, ranked**
1. Byte layout versus UAPKI/IIT: little-endian, compressed point, `DSTU4145Params` in
   `CKA_EC_PARAMS`.
2. Vendor constant collisions.
3. Consumers silently ignore the mechanisms.
4. Soft-token custody: offline PIN brute force, rollback, keys in process memory. Also the
   openCryptoki CVE classes:
   - CVE-2021-3798, invalid-curve key extraction via `C_CreateObject`;
   - CVE-2026-40253, BER length trust;
   - symlink and timing attacks.
5. Windows 1-byte struct packing.

**Implementation.** kryoptic (Rust, Apache-2.0) depends on OpenSSL and has no Windows support, so it
is a design reference, not a base.

**Sizes** [I]:
- a minimal m=257 soft token: L (realistically XL with an interop harness);
- the full UA constant set: XL.

**Recommended verdict: do not do.** T-201 stays parked, with its "no new work needed" claim corrected.
- Role scores: about 2/2/1.
- What would change it: an integrator with an HSM they already own who needs a thin bridge, not
  custody.

## 3. CMS/CAdES, key formats and OIDs

**Standards and sources**
- RFC 5652 (CMS), RFC 5280 (X.509), RFC 5958 (PKCS#8), RFC 7292 (PKCS#12).
- ДСТУ ETSI EN 319 122/132/142/162, ДСТУ ETSI TS 119 182-1.
- Law 2155-VIII; CMU 1298 (2023), 764 (2024), 920 (2026), 991 (2020); Law 80/94 art. 8.
- BC `UAObjectIdentifiers.java`; UAPKI `oids.h`.

**Formats.** [V]
- CMU 1298 covers electronic public services. Signatures in XML, CMS, PDF, ASN.1 or JSON at
  B-B/B-T/B-LT/B-LTA, or in containers, per the ДСТУ ETSI adoptions.
- czo still generates legacy CAdES-C/X-Long, so a validator must accept both.
- The older formats order (140/614 of 2020) was repealed on 2024-03-26.

**OIDs** [V]. Arc `1.2.804.2.1.1.1`.

| Object | OID |
|---|---|
| DSTU 4145 LE key and GOST-era signature | `.1.3.1.1` |
| DSTU 4145 with Kupyna-256/384/512 | `.1.3.6.1.1` / `.1.3.6.2.1` / `.1.3.6.3.1` |
| Named curves (m=257 is `.6`) | `.1.3.1.1.2.{0..9}` |
| GOST 34.311 | `.1.2.1` |
| Kupyna-256/384/512 | `.1.2.2.{1,2,3}` |
| Kupyna-KMAC | `.1.2.2.{4,5,6}` |
| Kalyna | `.1.1.3.{mode}.{block}` |

- The UAPKI GCM/WRAP numbers are marked non-standard by UAPKI itself.
- No OIDs were found for DSTU 9041 or Strumok (negative search). Inventing them is not this
  project's role.

**Encoding** [V]
- Signature, little-endian: reverse(s‖r).
- In X.509 it is a BIT STRING wrapping a 64-byte OCTET STRING. In CMS it is a bare 64-byte OCTET
  STRING.
- The public key is a BIT STRING wrapping an OCTET STRING with the 33-byte little-endian compressed
  point.
- Curve b and the base point are little-endian OCTET STRINGs; n is an INTEGER.
- GOST-era keys also carry a 64-byte DKE (an S-box).

**Key containers** [V]
- Key-6.dat is IIT-proprietary. UAPKI reverse-engineered it: GOST 28147-ECB plus iterated 34.311.
- UA PKCS#12 uses HMAC-GOST or a non-standard Kupyna-PBKDF2.
- PrivatBank JKS uses SHA-1 XOR.
- No container profile is in force: the 2013 and 2020 orders were repealed.

**Legal frame** [V text; I application; needs a lawyer]
- A file key gives an *advanced* signature based on a qualified certificate, not a qualified one
  (Law art. 1 item 59).
- Qualified signature devices need certification (art. 19(5)).
- **CMU 1298 item 6:** "Перевірку та підтвердження удосконалених електронних підписів, які
  базуються на кваліфікованих сертифікатах … здійснюють лише кваліфіковані надавачі". **Open:**
  does this restrict a relying party's own local check, or only verification offered as a
  service? This gates the recommended path (T-321).
- **State information systems:** for службова інформація, only cryptographic tools with a
  state-expertise conclusion count (Law 80/94 art. 8).
- **CMU 991** (the technical regulation for cryptographic tools): whether it covers open-source
  libraries is unknown. Its transition cliff is 2027-01-01.

**Pitfalls, ranked**
1. Signature OID versus key OID: the hash must come from the signature OID.
2. Byte order and wrapping.
3. Explicit curve parameters in the SPKI: a CurveBall-class risk. Accept only an exact byte match to
   a known curve.
4. The GOST cut-off must never rest on the attacker-written `signingTime`. Use a trusted timestamp
   or the certificate validity window, and allow GOST only in a verify-only legacy feature.
5. Untrusted DER/CMS parsing: strict DER, bounded depth, an OID allow-list, fuzzing.
6. "Qualified" wording, or a library's "valid" standing in for a qualified verification service.
7. Frequently changing acts: watch the "Редакція від" of 2155-19, 764-2024-п, 1298-2023-п and
   991-2020-п.
8. Unclear licences on jkurwa/dstucrypt (no LICENSE file).

**Recommended verdict: the one recommended direction, verify-only first.**
- **Niche.** A memory-safe (Rust) parser of untrusted DER/CMS against UAPKI's C one; a `no_std`
  primitive layer underneath; reach into eight languages through the existing bindings; and DSTU
  4145 with Kupyna, which BC lacks as a combined algorithm.
- **Out of scope.** Signing CAdES, LT/LTA, TSP/OCSP clients and key containers duplicate UAPKI
  (XL) and stay out.
- **Role scores:** about 3-4/4/4 for verify-only and about 1-2/1/1 for full CAdES with containers.

## 4. Browser

**Standards and sources**
- IANA TLS registries.
- NSS `sslt.h`; Chromium `net/ssl/ssl_private_key.cc`.
- Chrome, Firefox (MDN) and Edge Native Messaging docs; Apple Safari web-extension docs.
- W3C Web Cryptography Level 2 (FPWD 2025-04-22).
- WebAssembly proposals; CT-Wasm (POPL 2019, doi:10.1145/3290390); getrandom 0.3.4 docs.

**Facts**
- **DSTU TLS in mainstream browsers is impossible.** [V] There are no IANA codepoints.
  Registration alone would not help either: GOST and SM are registered and still absent from NSS
  and Chromium. The only shipped route is a forked browser (Chromium-Gost).
  - **Earlier I said this; confirmed.**
- **No algorithm plugins.** [V; Safari I] Chrome, Edge and Safari accept none. Firefox's PKCS#11
  modules act as key stores for algorithms NSS already knows.
  - **Earlier I said this; confirmed.**
- **How Ukrainian government signing actually works.** [V]
  - The id.gov.ua/czo widget signs **file keys in-page** with a 16.7 MB Emscripten **asm.js**
    build of IIT's library (not WASM).
  - **Tokens** go through IIT's Chrome MV3 extension plus a native host. It has 800,000 users per
    its Chrome Web Store listing.
  - **Diia.Підпис** is a smartphone flow.
  - **Earlier I said "IIT and Diia sign through Native Messaging"; that is only one of three
    channels.**
- **WASM.**
  - wasm32 has no 64×64→128 multiply, so `__multi3` may appear in the field arithmetic. That is
    unbuilt and probably branchless. [I]
  - The real issue is that WASM engines give no constant-time guarantee (CT-Wasm), and the
    constant-time proposal is inactive. [V]
  - getrandom needs `wasm_js` and must be confined to a binding crate. [V]
  - Web Crypto cannot hold DSTU keys, so they would sit as bytes in JS/WASM/IndexedDB. [V]
  - A local wasm32 build was not run because the target is not installed.
- **Native Messaging.** [V]
  - Host-to-browser messages are capped at 1 MB.
  - Hosts are registered per OS and per browser, and Edge and Chrome store IDs differ.
  - Safari needs an Xcode containing app plus an app extension.
  - It is a confused-deputy risk: `allowed_origins` gates the extension, not the web page.

**Recommended verdict.**
- **Never** browser signing or a Native Messaging host.
- **A verify-only WASM package** avoids the constant-time and custody objections. It is a possible
  later spin-off of §3, but no demand has been shown.
- **Role scores:** about 2/2/2 for verify-only and about 1/2/1 for signing.

## 5. The topic as a whole

**What the panel agreed on.** All six roles ranked the same way:
1. Verify-only DSTU 4145 + Kupyna CMS is the one direction with a real niche and a real external
   oracle: a producer's signature either verifies or it does not.
2. OpenSSL is deferred.
3. PKCS#11 and browser signing are not to be done.

**How much weight the agreement carries.** The roles are one model reading one synthesis, so their
agreement is a consistency check, not six independent opinions. Their corrections, folded in
above, are the valuable part.

**Dependency order**
```
T-318 spike (verify ≥3 public czo Kupyna-era samples)    <- gates every SIGNATURE path
  -> T-319 primitives in dstu-core (decompression, UA codec)   [inside D-17]
       -> T-322 verify-only CMS verifier (separate workspace or sibling repo)  [gated by T-320/T-321]
            -> later, only on demand: verify-only WASM; OpenSSL Kupyna/Kalyna-128 slice
```

Not gated by T-318: an OpenSSL digest/cipher slice and a WASM feasibility probe.

**Target layering** (architect, for the owner to decide in T-320):
- **L0 `dstu-core`.** Primitives plus the standard wire encodings of their own objects: compressed
  point, little-endian signature, exact explicit-parameter match. No ASN.1.
  - GOST 34.311, if ever, is a feature-gated, verify-only legacy primitive.
- **L1 a verify-only CMS/X.509 crate.** It depends on `dstu-core` (never on capi) and uses audited
  DER crates after a registry check. It starts as a separate workspace in this repo (the D-119
  pattern) or as a sibling repo.
- **L2 adapters**: CLI, capi, bindings and a verify-only WASM package.

**Recommended never-do list** (owner to confirm in T-320):
- call anything "qualified", "certified", "КЕП-compliant", "CMU 920-compliant" or
  side-channel-resistant;
- treat a library's "valid" as a qualified verification service;
- ship a soft PKCS#11 token as a security product;
- run a Native Messaging host, or sign in the browser with keys in IndexedDB;
- put wide-block Kalyna or streaming AEAD through EVP, or patch libssl;
- sign with GOST, or accept caller-supplied DKE or explicit curves on a signing path;
- reverse-engineer Key-6.dat;
- invent OIDs;
- put ASN.1 into `dstu-core`, or change `crypto_*` wire formats instead of adding codecs beside
  them;
- accept a byte-order "fix" without a citation (D-25);
- hand-transcribe constants (D-163);
- commit third-party or private signatures (the D-185 `.p7s` files are private and can never be
  fixtures; only the czo public TEST artefacts can be).

**Still unknown**
- Whether CMU 1298 item 6 restricts local relying-party verification.
- Whether CMU 991 covers open-source libraries.
- Whether qualified signature device certification covers signing software or only devices.
- How long GOST 34.311 verification must continue.
- Whether real production Kupyna certificates match the czo TEST ones.
- The exact hash→field convention in Kupyna-era artefacts. T-318 settles it; BC reverses the hash
  bytes.
- Whether OpenSSL's IV overflow is real (needs an ASan run).
- Whether `__multi3` appears on wasm32.
- Whether the 0x0042xxxx PKCS#11 set is vendor-confirmed.

## 6. Sources

All accessed 2026-10-24. The four research reports' full quote lists were not committed; these are
the sources each recommendation rests on.

**OpenSSL (§1)**
- Release list: https://api.github.com/repos/openssl/openssl/releases
- Engine removal: https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/NEWS.md and `CHANGES.md` in the same tree.
- Man pages: https://raw.githubusercontent.com/openssl/openssl/openssl-4.1.0/doc/man7/provider.pod, plus `provider-base.pod`, `provider-signature.pod` and `provider-keymgmt.pod`. Also `doc/man5/config.pod` and `doc/man7/openssl-env.pod`.
- Source files in the openssl-4.1.0 tree:
  - `crypto/objects/objects.txt`
  - `crypto/x509/x_pubkey.c`
  - `crypto/asn1/a_verify.c`
  - `crypto/cms/cms_sd.c`
  - `crypto/cms/cms_enc.c`
  - `include/openssl/evp.h`
  - `ssl/s3_lib.c`
  - `ssl/t1_lib.c`
- Distribution versions: https://qa.debian.org/madison.php?package=openssl and https://people.canonical.com/~ubuntu-archive/madison.cgi?package=openssl
- IANA registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
- gost-engine: https://github.com/gost-engine/engine (PR #482, `patches/openssl-tls1.3.patch`)
- oqs-provider: https://github.com/open-quantum-safe/oqs-provider
- dstu-engine: https://github.com/dstucrypt/dstu-engine

**PKCS#11 (§2)**
- Spec v3.1: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html
- Profiles: https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html
- v3.2 directory: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/
- NSS: https://github.com/nss-dev/nss (`cryptohi/keythi.h`, `pk11wrap/pk11akey.c`, `pk11wrap/pk11obj.c`)
- SunPKCS11: https://docs.oracle.com/en/java/javase/25/security/pkcs11-reference-guide1.html
- pkcs11-provider: https://github.com/latchset/pkcs11-provider
- GnuTLS: https://gitlab.com/gnutls/gnutls (`lib/pkcs11_privkey.c`)
- p11-kit: https://github.com/p11-glue/p11-kit (`rpc-client.c`, `rpc-message.c`)
- Windows: https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
- UA constant headers:
  - https://github.com/specinfo-ua/UAPKI (`library/common/cryptoki/pkcs11t-ua.h`, `cm-pkcs11/src/storage/cryptoki-storage.cpp`)
  - https://github.com/edenlabllc/digital_signature.lib (`c_src/h/uacryptoki.h`)
- Avtor SecureToken-337 datasheet: https://fbp.com.ua/docs/software/eTrade/SecureToken337.pdf
- kryoptic: https://github.com/latchset/kryoptic (issue #250)
- native-pkcs11: https://github.com/google/native-pkcs11
- NVD CVE entries: CVE-2021-3798, CVE-2026-40253, CVE-2026-23893, CVE-2024-0914

**CMS, formats, legal (§3)**
- Law 2155-VIII: https://zakon.rada.gov.ua/laws/show/2155-19
- CMU 1298 (2023): https://zakon.rada.gov.ua/laws/show/1298-2023-%D0%BF
- CMU 920 (2026): https://zakon.rada.gov.ua/laws/show/920-2026-%D0%BF
- CMU 764 (2024): https://zakon.rada.gov.ua/laws/show/764-2024-%D0%BF
- CMU 991 (2020): https://zakon.rada.gov.ua/laws/show/991-2020-%D0%BF
- Law 80/94-ВР: https://zakon.rada.gov.ua/laws/show/80/94-%D0%B2%D1%80
- Repealed orders: https://zakon.rada.gov.ua/laws/show/z1039-20 (repealed by z0375-24) and https://zakon.rada.gov.ua/laws/show/z2227-13
- czo.gov.ua: https://czo.gov.ua/testexamples (public TEST artefacts) and https://czo.gov.ua/faq
- UAPKI expertise record: https://data.gov.ua/dataset/7b0d45fe-75eb-4d14-9792-59e440305678
- Bouncy Castle: https://github.com/bcgit/bc-java (`core/src/main/java/org/bouncycastle/asn1/ua/UAObjectIdentifiers.java`, `DSTU4145NamedCurves.java`). The local `oracles/bouncycastle-java` copy has `crypto/signers/DSTU4145Signer.java`.
- UAPKI: https://github.com/specinfo-ua/UAPKI (`library/common/pkix/oids.h`, `cm-pkcs12/src/crypto/pkcs5.c`)
- jkurwa: https://github.com/dstucrypt/jkurwa
- RFCs: 5652, 5280, 5958 and 7292 (https://www.rfc-editor.org/)
- News, secondary only [S]: dtkt.ua, 2026-08-07, on the Kupyna switch dates

**Browser (§4)**
- IANA CSVs: https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv and `tls-signaturescheme.csv`
- NSS: https://raw.githubusercontent.com/nss-dev/nss/master/lib/ssl/sslt.h
- Chromium: https://chromium.googlesource.com/chromium/src/+/main/net/ssl/ssl_private_key.cc
- Chromium-Gost: https://github.com/deemru/Chromium-Gost
- Native messaging:
  - Chrome: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
  - Firefox: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests
  - Edge: https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging
- Chrome MV3 policy: https://developer.chrome.com/docs/webstore/program-policies/mv3-requirements
- Safari extension messaging: https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension
- id.gov.ua: https://id.gov.ua/sign (widget `/js/sign-widget/eusign.js`, worker `sign-widget/v20260209/js/euscp.worker.ex.js`)
- IIT extension: Chrome Web Store listing "ІІТ Користувач ЦСК-1. Бібл. підп. (web-р.)", ID `jffafkigfgmjafhpkoibhfefeaebmccg`, 800,000 users
- IIT downloads: https://iit.com.ua/downloads
- Web Crypto: https://www.w3.org/TR/WebCryptoAPI/ (Level 2 FPWD, 2025-04-22)
- WebAssembly proposals: https://github.com/WebAssembly/proposals (README.md, inactive-proposals.md) and https://github.com/WebAssembly/wide-arithmetic
- CT-Wasm: https://doi.org/10.1145/3290390
- getrandom: https://docs.rs/getrandom/0.3.4/getrandom/
- wasm org sunset: https://blog.rust-lang.org/inside-rust/2025/07/21/sunsetting-the-rustwasm-github-org/

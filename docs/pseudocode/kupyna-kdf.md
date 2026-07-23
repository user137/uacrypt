# Kupyna-based KDF (`crypto_kdf` equivalent)

**Not a DSTU-specified construction, and not oracle-verified - different posture from every other
primitive in this project, stated precisely rather than reusing another entry's wording.**
`docs/dstu-crypto-project.md`'s own libsodium API mapping says `crypto_kdf` "needs to be constructed
from existing primitives" since "there's no separate national KDF standard" - unlike Kupyna-KMAC
(`docs/pseudocode/kupyna-kmac.md`), which DSTU 7564:2014 itself defines (even though this project
hasn't read that definition directly), there is no DSTU text, UAPKI code, or Bouncy Castle code that
specifies "a KDF using Kupyna" - because nobody has built one before this. There is therefore no
byte-for-byte oracle vector to verify against, anywhere. What follows is a design decision, not a
transcription, and its testing is limited to what property tests (determinism, distinctness) can
confirm - it cannot catch a construction mistake a fixed vector would have caught, because no fixed
vector exists to write.

## Design choice: libsodium's `crypto_kdf` shape, not full RFC 5869 HKDF

Two established international patterns were considered:

1. **RFC 5869 HKDF** (Extract-then-Expand): `PRK = HMAC-Hash(salt, IKM)`, then
   `OKM = HMAC-Hash(PRK, T(i-1) || info || i)` repeated and concatenated. HKDF's own security proof
   is stated in terms of **HMAC** specifically. `hazmat::kupyna_kmac`'s construction
   (`H(PAD(K) || PAD(M) || ~K)`) is not HMAC - whether it has HMAC's specific PRF properties is
   unanalyzed here, and assuming HKDF's proof transfers to a different keyed construction without
   justification would be exactly the kind of unexamined assumption this project's "no homegrown
   primitives" discipline exists to avoid. HKDF's Expand stage also introduces a chaining counter
   (`T(i-1) || info || i`) whose off-by-one correctness would be invisible to testing without a KAT
   - a real risk with nothing to catch it.
2. **libsodium's `crypto_kdf_derive_from_key`** (recalled from libsodium's public documentation -
   not vendored in this repo, no source file to cite a line number against): a single keyed-hash
   call per subkey, `subkey = KeyedHash(key, subkey_id, context)`, with no separate Extract stage -
   because it explicitly assumes the master key is already uniformly random (normally produced by
   `crypto_kdf_keygen`, i.e. straight from the OS CSPRNG), which is exactly this project's own
   `getrandom`-based key generation story (`DECISIONS.md` D-04). Skipping Extract sidesteps HKDF's
   proof-transfer question entirely - the assumption being made is simply "Kupyna-KMAC is a
   reasonable keyed PRF," the *same* assumption already implicitly made by using it as a MAC in
   T-38, not a new, additional one.

**Chosen: pattern 2.** Not a byte-for-byte port of libsodium's internals (which use BLAKE2b's native
`salt`/`personal` parameters to embed `subkey_id`/`context` - a hash-specific feature Kupyna
doesn't have), but the same *shape*: one master key, an 8-byte little-endian `subkey_id`, an 8-byte
`context`, and a single keyed-hash call producing the subkey directly.

## Construction

Given a master key `K` (exactly `mac_len` bytes for the chosen Kupyna-KMAC variant - `[u8; N]`,
statically guaranteed, not runtime-checked, since callers control both sides of this call unlike
`kupyna_kmac`'s more general `&[u8]` API), a `subkey_id: u64`, and an 8-byte `context`:

```
message = context (8 bytes) || subkey_id as little-endian bytes (8 bytes)   [16 bytes total]
subkey  = KupynaNKmac::mac(K, message)                                      [N bytes, N = 32/48/64]
```

Subkey length is **fixed** at the chosen variant's MAC size (32/48/64 bytes) - Kupyna has no
BLAKE2b-style variable-output-length feature, unlike libsodium's `crypto_kdf` (which allows 16-64
arbitrary bytes per subkey). A real, sourced constraint from the underlying primitive, not an
arbitrary restriction.

## What testing here can and cannot show

No oracle vector exists (see above), so tests are limited to:

- **Determinism**: identical `(K, subkey_id, context)` always produces the identical subkey.
- **Distinctness**: different `subkey_id` values (holding `K`/`context` fixed) produce different
  subkeys, and different `context` values (holding `K`/`subkey_id` fixed) do too - this is the
  actual security property being claimed ("id/context differentiate derived keys"), checked via
  `proptest` over random inputs, not a fixed case.
- **Exact byte-layout pin**: `derive_subkey`'s output matches a manual, direct
  `KupynaNKmac::mac(K, context || subkey_id_le_bytes)` call - pins the documented message layout
  precisely, so a future refactor can't silently reorder `context`/`subkey_id` without a test
  catching it.

None of this can catch "the construction itself is wrong" the way a KAT would - there is no KAT to
write, because no reference implementation of this construction exists anywhere to have generated
one from.

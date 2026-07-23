# Kupyna-based KMAC (DSTU 7564:2014's MAC mode)

**Provenance note (read before trusting this as settled):** `docs/papers/Kupyna.pdf` (the
designers' own paper, otherwise this project's highest-trust Kupyna source) states in its
introduction that "the new standard defines both the hash function and its additional mode for
message authentication code generation" but does not itself describe that mode anywhere in its
536 lines (checked directly, not assumed - `grep`-scanned for "authentication"/"PAD(K)"/"invert",
one hit, the sentence just quoted). This pseudocode is therefore transcribed from two independent
reference implementations, not the primary standard text - see `DECISIONS.md` D-44 for the full
provenance discussion, including why the dual-oracle agreement here is stronger evidence than
Strumok's or Kalyna-CCM's equivalent caveats.

## Sources

- `oracles/uapki/library/uapkic/src/dstu7564.c`, `dstu7564_init_kmac`/`dstu7564_update_kmac`/
  `dstu7564_final_kmac` (~line 731) - the C reference, whose own comment states the construction
  directly: `HMAC(M,K) = H(PAD(K) || PAD(M) || (~K))`.
- `oracles/bouncycastle-java/core/src/main/java/org/bouncycastle/crypto/macs/DSTU7564Mac.java` - an
  independent Java implementation of the same construction (not a port of the C above - different
  vendor, different language, structured differently). Read directly, not just vector-matched.
- Cross-check: both implementations' self-test/unit-test vectors (`dstu7564_self_test_kmac`;
  `DSTU7564Test.java`'s `macTests()`) use byte-identical key/message/expected-MAC triples for all
  three MAC sizes (256/384/512-bit) and agree on the output — see `crates/dstu-core/tests/vectors/
  kupyna-kmac/kmac-{256,384,512}.json`.

## Construction

Given a key `K` (exactly `mac_len` bytes - **enforced, not merely conventional**: both oracles'
test data uses `len(K) == mac_len` in every case, and the UAPKI C source has a hard
`CHECK_PARAM(key_buf_len == mac_len)`; Bouncy Castle's `DSTU7564Mac` is more permissive in its own
code but no vector anywhere exercises a different key length, so this project deliberately matches
the *stricter* of the two rather than building an untested code path) and a message `M`:

1. Let `~K` be the bitwise complement of every byte of `K` (same length as `K`).
2. Let `PAD(K)` be `K` followed by Kupyna's own message-padding scheme (`0x80`, zero bytes, then a
   96-bit little-endian bit-length field - the same padding `hazmat::kupyna`'s own `finalize`
   already implements, see `docs/pseudocode/kupyna.md`), using `len(K)` (in bits) as the length
   field, sized up to a whole number of Kupyna blocks. For all three MAC sizes this is always
   exactly **one** block (`len(K) + 13 <= block_bytes` holds for 32+13≤64, 48+13≤128, 64+13≤128).
3. Let `PAD(M)` be `M` followed by the same padding scheme, using `len(M)` (in bits, `M`'s own
   length - **not** `len(K) + len(M)`) as the length field.
4. The MAC is: `H(PAD(K) || PAD(M) || ~K)`, where `H` is Kupyna's **own, completely standard**
   compression-and-finalize (its own length field in this outermost finalize is the *true* total
   byte count of everything just fed to it: `PAD(K)`'s one block + `M`'s raw bytes + `PAD(M)`'s own
   padding suffix + `~K`'s raw bytes).
5. Truncate `H`'s output to `mac_len` bytes from the **tail** (least-significant end) of the full
   internal-state-sized digest, exactly as `hazmat::kupyna`'s own `KupynaCore::finalize` already
   does for any `output_bytes < block_bytes` (`flat[block_bytes - output_bytes .. block_bytes]`) -
   this is the one place a truncation-direction mistake would silently produce a wrong-but-
   plausible-looking value, which is why the 384-bit vector (the only one of the three where
   `mac_len` is smaller than the underlying 512-bit/1024-bit-block digest size) is load-bearing,
   not redundant with the other two.

**Block-size selection** (same rule as the standalone hash, `docs/pseudocode/kupyna.md`): `mac_len
<= 32` bytes uses the 512-bit/8-column internal state (Kupyna-256's structure); `mac_len > 32`
(both 384 and 512-bit MAC) uses the 1024-bit/16-column state (Kupyna-512's structure) - KMAC-384 is
**not** a separate "Kupyna-384" hash, it's Kupyna-512's own compression truncated further.

## Implementation note (this project's specific realization, not part of the construction itself)

`PAD(M)`'s suffix can be fed through the *existing* `KupynaCore::update` exactly like ordinary
streamed message bytes - the only subtlety is that the *already-buffered* tail of `M` (whatever
didn't fill a complete block) must not be duplicated: only the *new* padding suffix bytes (`0x80`
onward) get passed to `update`, since the buffered `M` bytes are already sitting in `KupynaCore`'s
internal buffer from the preceding `update(M)` call. `PAD(K)`'s padding is computed the same way but
with an empty "already buffered" prefix (a fresh `KupynaCore`), so its full padded block is fed in
directly. Both padding computations reuse the exact same tail-formula `KupynaCore::finalize` already
has - factored out so there is one implementation of "Kupyna's own padding formula," not three.

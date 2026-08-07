//! Black-box test for `dstu_core::hazmat::dstu4145::signature::verify` against
//! `tests/vectors/dstu4145/gf2m163.json` - the standard's own Annex B.1 worked example, dual-
//! sourced against Bouncy Castle's `test163()` (`docs/DECISIONS.md` D-14). This is the first
//! genuinely dual-sourced (not single-BC-oracle) check for anything built on the field/point
//! arithmetic landed so far - see `docs/DECISIONS.md` D-25's follow-up entry.

use dstu_core::hazmat::dstu4145::curve163::Point;
use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
use dstu_core::hazmat::dstu4145::scalar::Scalar;
use dstu_core::hazmat::dstu4145::signature::{sign, verify};
use proptest::prelude::*;

fn decode_hex(s: &str) -> Vec<u8> {
    let padded;
    let s = if s.len().is_multiple_of(2) {
        s
    } else {
        padded = format!("0{s}");
        &padded
    };
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn field(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&decode_hex(s))
}

fn scalar(s: &str) -> [u8; 21] {
    let bytes = decode_hex(s);
    let mut out = [0u8; 21];
    out[21 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Pulls every value of `"key": "..."` out of the vector JSON, in file order. `gf2m163.json` has
/// both `base_point.x/y` and `public_key_q.x/y` under the bare keys `"x"`/`"y"` - callers must
/// pick the right index (`base_point` comes first in the file).
fn extract_all<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = json;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

fn extract<'a>(json: &'a str, key: &str) -> &'a str {
    extract_all(json, key)[0]
}

/// `gf2m163.json`'s `hash_h_of_t` is used directly, no byte reversal - `hash_to_field` implements
/// the official text's §5.9 algorithm on the hash as given (see that function's doc comment for
/// why an earlier version of this test/function pair needed a reversal that turned out to be
/// compensating for a bug, not a real API requirement).
fn hash(json: &str) -> Vec<u8> {
    decode_hex(extract(json, "hash_h_of_t"))
}

// Every #[test] below calls `sign`/`verify`, which each run `Point::scalar_multiply`'s
// 163-iteration constant-time ladder at least once - interpreting that under Miri takes minutes
// per call (docs/TASKS.md T-100/T-85/D-46), not seconds, so these are excluded from CI's required
// Miri gate specifically (not `cargo test`, which stays required and fast). Property/vector
// coverage of this file is unaffected outside Miri; only UB-checking under Miri's interpreter is
// skipped here, for cost reasons, not correctness ones.
#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_worked_example_verifies() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let hash = hash(json);
    let r = scalar(extract(json, "r"));
    let s = scalar(extract(json, "s"));

    assert!(
        verify(&hash, &r, &s, q, g),
        "official DSTU 4145 Annex B.1 worked example failed to verify"
    );
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_tampered_signature_is_rejected() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let hash = hash(json);
    let r = scalar(extract(json, "r"));
    let mut s = scalar(extract(json, "s"));

    assert!(verify(&hash, &r, &s, q, g));
    s[20] ^= 1; // flip the low bit of s
    assert!(
        !verify(&hash, &r, &s, q, g),
        "tampered signature must not verify"
    );
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_worked_example_signs_with_pinned_ephemeral() {
    // Reproduces the official Annex B.1 worked example's (r, s) exactly, using the vector's
    // pinned ephemeral `e` - the seam `gf2m163.json`'s own note calls for (KAT reproduction only,
    // never real signing - see `signature::sign`'s doc comment).
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let g = Point::generator();
    let hash = hash(json);
    let d = Scalar::from_be_bytes(&decode_hex(extract(json, "private_key_d")));
    let e = Scalar::from_be_bytes(&decode_hex(extract(json, "ephemeral_e")));
    let expected_r = scalar(extract(json, "r"));
    let expected_s = scalar(extract(json, "s"));

    let (r, s) = sign(&hash, d, e, g).expect("official worked example must not be degenerate");
    assert_eq!(r, expected_r, "r mismatch");
    assert_eq!(s, expected_s, "s mismatch");
}

#[cfg_attr(
    miri,
    ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100"
)]
#[test]
fn gf2m163_wrong_hash_is_rejected() {
    let json = include_str!("vectors/dstu4145/gf2m163.json");
    let qx = field(extract_all(json, "x")[1]); // index 0 is base_point.x
    let qy = field(extract_all(json, "y")[1]); // index 0 is base_point.y
    let q = Point::Affine(qx, qy);
    let g = Point::generator();
    let mut hash = hash(json);
    let r = scalar(extract(json, "r"));
    let s = scalar(extract(json, "s"));

    // Flip the *last* byte - `hash_to_field` only looks at the hash's last 21 bytes (see its doc
    // comment), so a change outside that window (e.g. byte 0 of this 32-byte hash) would be
    // invisible to it and wrongly still verify.
    let last = hash.len() - 1;
    hash[last] ^= 1;
    assert!(
        !verify(&hash, &r, &s, q, g),
        "signature must not verify against a different hash"
    );
}

// The single official worked example only exercises one d/e/hash combination. Property-test the
// full round trip (sign(hash, d, e) verifies against Q = -d*G - see signature.rs's module doc)
// over random 160-bit d/e (comfortably below the curve order n, so Scalar's
// single-conditional-subtract reduction is exercised without needing an explicit mod-n rejection
// step in the test itself) and random 32-byte hashes - see docs/TASKS.md "Testing & hardening" for why
// this project property-tests round trips broadly rather than trusting a single fixed vector
// alone. (This exact property test is what caught the Q = -d*G vs d*G discrepancy above - the
// fixed vector uses a pre-computed Q and never exercised key derivation itself.)
proptest! {
    #[cfg_attr(miri, ignore = "Point::scalar_multiply's 163-iteration ladder is too slow to interpret under Miri - see docs/TASKS.md T-100")]
    #[test]
    fn dstu4145_sign_verify_roundtrip(
        d_bytes in prop::collection::vec(any::<u8>(), 20),
        e_bytes in prop::collection::vec(any::<u8>(), 20),
        hash_bytes in prop::collection::vec(any::<u8>(), 32),
    ) {
        let g = Point::generator();
        let mut d_arr = [0u8; 21];
        d_arr[1..].copy_from_slice(&d_bytes);
        let mut e_arr = [0u8; 21];
        e_arr[1..].copy_from_slice(&e_bytes);
        prop_assume!(d_arr != [0u8; 21]);
        prop_assume!(e_arr != [0u8; 21]);

        let d = Scalar::from_be_bytes(&d_arr);
        let e = Scalar::from_be_bytes(&e_arr);

        // Q = -d*G, not d*G - see signature.rs's module doc / docs/DECISIONS.md D-25's follow-up entry.
        let q = match g.scalar_multiply(&d_arr) {
            Point::Affine(x, y) => Point::Affine(x, y).negate(),
            Point::Infinity => return Ok(()), // d = 0 mod n - not reachable with a nonzero 160-bit d
        };

        if let Some((r, s)) = sign(&hash_bytes, d, e, g) {
            prop_assert!(verify(&hash_bytes, &r, &s, q, g));
        }
        // A `None` here is one of the pseudocode's ~2^-163-probability degenerate cases - nothing
        // to assert, just don't fail the property (see `signature::sign`'s doc comment).
    }
}

/// `sign`'s three `None`-returning degenerate rejections (`docs/DECISIONS.md` D-111, prompted by a
/// T-152-style "is this branch even reachable, and can we deliberately construct it" review of
/// every other DSTU 4145 boundary condition after D-110's fix) split three ways, not one:
///
/// - `Point::Infinity` (from `g.scalar_multiply(e) == O`): provably unreachable for `g =
///   generator()` and any `Scalar` `e` (`Scalar` already rejects `e == 0`, and `G` has prime order
///   `n`, so `e*G == O` only for `e ≡ 0 mod n`) - not tested here, see D-111 for why.
/// - `fe_x == ZERO`: also provably unreachable for `g = generator()` - `docs/DECISIONS.md` D-111's
///   order-theoretic argument (the curve's one order-2 point, at x=0, can't be a multiple of a
///   point of odd prime order `n`) - not tested here either.
/// - `is_zero(r)` and `s.is_zero()`: genuinely reachable at ~2^-163 for honest inputs, **not**
///   foreclosed by any type - and, unlike the two above, deliberately constructible by solving
///   backward (not brute force): `hash`/`e` freely chosen (any hash byte string decodes to a
///   `FieldElement` via `hash_to_field`, and any `Scalar` in `[1, n)` is a valid `e`), so a target
///   `h` or `d` can be computed directly from the field/scalar arithmetic this crate already
///   exposes. Values below found via a scratch probe (deleted after use, not shipped) computing
///   `h = (2^162) * fe_x^-1` (forces `r`'s low-162-bit truncation to zero) and `d = -e * r^-1 mod
///   n` (forces `s = r*d + e ≡ 0`) respectively.
#[test]
fn sign_rejects_when_r_would_be_zero() {
    let g = Point::generator();
    let e = Scalar::from_be_bytes(&scalar("1"));
    let d = Scalar::from_be_bytes(&scalar("DEADBEEF"));
    let hash = decode_hex("07F38B897CC5283B48378FB8FC315EF562838F5F18");
    assert_eq!(sign(&hash, d, e, g), None, "expected the r == 0 rejection");
}

#[test]
fn sign_rejects_when_s_would_be_zero() {
    let g = Point::generator();
    let e = Scalar::from_be_bytes(&scalar("7"));
    let d = Scalar::from_be_bytes(&scalar("01006EBD7358BA3A2923A236B345FAD0945781A1A9"));
    let hash = [0x42u8; 21];
    assert_eq!(sign(&hash, d, e, g), None, "expected the s == 0 rejection");
}

/// `docs/TASKS.md` T-189: `verify` took its `q` parameter on faith with no validation at all -
/// found auditing T-183. A naive "swap in a bogus `q`, reuse the real `(r, s)`, assert `verify`
/// now returns false" test would pass **today, before any fix** - not because anything rejects
/// `q`, but because reusing a signature computed against a *different* `q` fails the final
/// equality check by sheer numeric coincidence (confirmed empirically: all three such tests
/// passed against the unfixed code). That's exactly the D-21/D-25 trap `CLAUDE.md` already
/// documents (a test that passes without exercising what it claims to) - applied here to the key
/// input rather than the derivation step where it was first found. So these three tests instead
/// *actively forge* a `(r, s)` pair `verify` currently accepts for each bad `q`, via
/// `find_forgery` below - a real, working universal-forgery exploit, not a coincidental pass.
///
/// The exploit: `q`'s order divides 2 for every `q` used below (the real order-2 point, and any
/// `x = 0` point regardless of `y` - `curve163::Point::double`'s `if x1 == 0 { return Infinity }`
/// branches on `x` alone, never checks the curve equation, so a fake `(0, y)` behaves identically
/// to the genuine order-2 point for this purpose; `Infinity` itself has order 1, an even easier
/// case of the same idea). `r*q` then only depends on `r`'s parity (or not at all, for
/// `Infinity`), collapsing `s*G + r*q` to at most two possible values per trial `s` - cheap to
/// search, and once a hit's `x`-coordinate is found, `truncate_162(h * x)` **is** a valid forged
/// `r` by construction, with no private key involved anywhere.
///
/// The existing `gf2m163_worked_example_verifies` above is this trio's regression guard in the
/// other direction (a genuine on-curve, full-order key must still verify) - not duplicated here.
mod t189_public_key_validation {
    use super::{decode_hex, extract, field};
    use dstu_core::hazmat::dstu4145::curve163::{self, Point};
    use dstu_core::hazmat::dstu4145::gf2m163::FieldElement;
    use dstu_core::hazmat::dstu4145::signature::{hash_to_field, verify};

    /// Mirrors `signature::truncate_162` (private to that module) exactly - see its doc comment:
    /// keeps the low 162 bits of a field element's big-endian integer value.
    fn truncate_162(y: FieldElement) -> [u8; 21] {
        let mut bytes = y.to_be_bytes();
        bytes[0] &= 0x03;
        bytes
    }

    fn encode_u32(v: u32) -> [u8; 21] {
        let mut out = [0u8; 21];
        out[17..].copy_from_slice(&v.to_be_bytes());
        out
    }

    /// Searches trial `s` values for a forged `(r, s)` that `curve163::verify_combine` (the same
    /// public-data combine `signature::verify` itself calls) makes self-consistent for the given
    /// `q` - see the module doc above for why this works whenever `q`'s order divides 2. At most
    /// ~200 trials, each one `verify_combine` call (cheap, non-constant-time public-data
    /// arithmetic even under `small-tables` - see `curve163.rs`'s own module doc); a match is
    /// found on the very first trial in practice (~75% per trial, see the module doc's odds).
    fn find_forgery(q: Point, hash: &[u8]) -> Option<([u8; 21], [u8; 21])> {
        let g = Point::generator();
        let mut h = hash_to_field(hash);
        if h == FieldElement::ZERO {
            h = FieldElement::ONE;
        }
        let r_even = encode_u32(2); // any nonzero even r: r*q == Infinity when ord(q) | 2
        let r_odd = encode_u32(1); // any odd r: r*q == q when ord(q) | 2

        for s_val in 1..=200u32 {
            let s = encode_u32(s_val);
            for (r_probe, want_even) in [(r_even, true), (r_odd, false)] {
                if let Point::Affine(rx, _) = curve163::verify_combine(g, &s, q, &r_probe) {
                    let candidate_r = truncate_162(h.multiply(rx));
                    let is_even = candidate_r[20] & 1 == 0;
                    if candidate_r != [0u8; 21] && is_even == want_even {
                        return Some((candidate_r, s));
                    }
                }
            }
        }
        None
    }

    const ARBITRARY_HASH: &str = "00112233445566778899AABBCCDDEEFF0011223344";

    #[cfg_attr(
        miri,
        ignore = "verify_combine's search loop is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn order_two_public_key_forgery_is_rejected() {
        // x = 0 is the curve's one non-identity order-2 point (cofactor 2, confirmed T-189):
        // `y^2 + 0*y = 0 + 0 + b`, i.e. `y = sqrt(b)`. Squaring is a bijection over GF(2^163) (the
        // Frobenius automorphism has order 163), so `sqrt(b) = b^(2^162)` - 162 repeated
        // squarings, independent of whatever `is_on_curve` the fix itself adds.
        let json = include_str!("vectors/dstu4145/gf2m163.json");
        let b = field(extract(json, "b"));
        let mut y = b;
        for _ in 0..162 {
            y = y.square();
        }
        assert_eq!(
            y.square(),
            b,
            "constructed y must independently satisfy y^2 = b (order-2 point sanity check)"
        );
        let q = Point::Affine(FieldElement::ZERO, y);

        let hash = decode_hex(ARBITRARY_HASH);
        let (r, s) = find_forgery(q, &hash).expect("forgery search found no hit in 200 trials");
        assert!(
            !verify(&hash, &r, &s, q, Point::generator()),
            "a forged signature under the order-2 (small-subgroup) public key must not verify"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "verify_combine's search loop is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn off_curve_x_zero_public_key_forgery_is_rejected() {
        // y = ONE deliberately does NOT satisfy y^2 = b (checked below) - this point is off the
        // real curve entirely, but `double`'s group law only branches on `x == 0` (see the module
        // doc above), so it exhibits the same order-dividing-2 exploit as the genuine order-2
        // point - proving the missing on-curve check is independently exploitable from the
        // missing small-subgroup check, not the same gap twice.
        let json = include_str!("vectors/dstu4145/gf2m163.json");
        let b = field(extract(json, "b"));
        let y = FieldElement::ONE;
        assert_ne!(
            y.square(),
            b,
            "test setup: y must NOT satisfy the curve equation"
        );
        let q = Point::Affine(FieldElement::ZERO, y);

        let hash = decode_hex(ARBITRARY_HASH);
        let (r, s) = find_forgery(q, &hash).expect("forgery search found no hit in 200 trials");
        assert!(
            !verify(&hash, &r, &s, q, Point::generator()),
            "a forged signature under an off-curve public key must not verify"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "verify_combine's search loop is too slow to interpret under Miri - see docs/TASKS.md T-100"
    )]
    #[test]
    fn infinity_public_key_forgery_is_rejected() {
        // Infinity has order 1: r*Infinity == Infinity for *every* r (not just even r), so this
        // is an easier case of the same exploit - find_forgery's parity split still applies
        // (harmlessly; both branches converge to the same q*r == Infinity result).
        let hash = decode_hex(ARBITRARY_HASH);
        let (r, s) = find_forgery(Point::Infinity, &hash)
            .expect("forgery search found no hit in 200 trials");
        assert!(
            !verify(&hash, &r, &s, Point::Infinity, Point::generator()),
            "a forged signature under the point-at-infinity public key must not verify"
        );
    }
}

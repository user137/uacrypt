//! Black-box test for `dstu_core::hazmat::dstu4145::signature257` against
//! `tests/vectors/dstu4145/gf2m257_arith.json`'s `signature_cases` - independently computed by
//! Bouncy Castle's own field/point arithmetic directly (not `DSTU4145Signer`, sidestepping its
//! `hash2FieldElement` pre-reversed-input convention entirely - see the generator's own comment
//! and `docs/DECISIONS.md` D-185/D-186). `h` is a random field element fed as the "hash" input
//! directly: `signature257::hash_to_field(h.to_be_bytes()) == h` for any already-valid field
//! element, so this exercises the full `sign`/`verify` pipeline downstream of hashing.

use dstu_core::hazmat::dstu4145::curve257::Point;
use dstu_core::hazmat::dstu4145::gf2m257::FieldElement;
use dstu_core::hazmat::dstu4145::scalar257::Scalar;
use dstu_core::hazmat::dstu4145::signature257::{self, sign, verify};

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex string in test vector: {s}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit in test vector"))
        .collect()
}

fn bytes33(s: &str) -> [u8; 33] {
    let v = decode_hex(s);
    let mut out = [0u8; 33];
    out[33 - v.len()..].copy_from_slice(&v);
    out
}

fn field(s: &str) -> FieldElement {
    FieldElement::from_be_bytes(&bytes33(s))
}

fn scalar(s: &str) -> Scalar {
    Scalar::from_be_bytes(&bytes33(s))
}

fn extract_all<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let mut results = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(pattern.as_str()) {
        let after = &rest[start + pattern.len()..];
        let end = after.find('"').expect("well-formed test-vector JSON");
        results.push(&after[..end]);
        rest = &after[end + 1..];
    }
    results
}

fn extract_objects<'a>(json: &'a str, array_key: &str) -> Vec<&'a str> {
    let key_pos = json
        .find(&format!("\"{array_key}\""))
        .unwrap_or_else(|| panic!("missing \"{array_key}\" array in test vector JSON"));
    let array_start = json[key_pos..].find('[').unwrap() + key_pos;
    let mut objects = Vec::new();
    let mut depth = 0i32;
    let mut object_start = 0usize;
    for (i, c) in json[array_start..].char_indices() {
        let pos = array_start + i;
        match c {
            '{' => {
                if depth == 0 {
                    object_start = pos;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    objects.push(&json[object_start..=pos]);
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }
    objects
}

fn field_val<'a>(obj: &'a str, key: &str) -> &'a str {
    extract_all(obj, key)[0]
}

// `sign`/`verify` each scalar-multiply on the 257-bit curve internally - as slow to interpret
// under Miri as `dstu4145_curve257.rs`'s own directly-annotated tests (docs/TASKS.md T-206, the
// m=257 sibling gap T-100/D-59's original fix predates). `cargo test` (required, fast) still
// covers every test in this file on every push.
#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_sign_matches_bouncy_castle() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let cases = extract_objects(json, "signature_cases");
    assert!(
        !cases.is_empty(),
        "no signature_cases found - extractor or fixture is broken"
    );

    let g = Point::generator();
    let mut checked = 0;
    for case in cases {
        let d = scalar(field_val(case, "d"));
        let e = scalar(field_val(case, "e"));
        let h = field(field_val(case, "h"));
        let expected_r = bytes33(field_val(case, "r"));
        let expected_s = bytes33(field_val(case, "s"));

        let hash = h.to_be_bytes();
        let (r, s) = sign(&hash, d, e, g).expect("BC-generated case is never degenerate");
        assert_eq!(r, expected_r, "r mismatch: {case}");
        assert_eq!(s, expected_s, "s mismatch: {case}");
        checked += 1;
    }
    assert_eq!(
        checked, 20,
        "expected 20 signature_cases from the generator"
    );
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_accepts_bouncy_castle_signatures() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let cases = extract_objects(json, "signature_cases");

    let g = Point::generator();
    for case in cases {
        let h = field(field_val(case, "h"));
        let qx = field(field_val(case, "qx"));
        let qy = field(field_val(case, "qy"));
        let r = bytes33(field_val(case, "r"));
        let s = bytes33(field_val(case, "s"));
        let q = Point::Affine(qx, qy);

        let hash = h.to_be_bytes();
        assert!(
            verify(&hash, &r, &s, q, g),
            "verify rejected valid case: {case}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_tampered_signature() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let case = extract_objects(json, "signature_cases")[0];

    let h = field(field_val(case, "h"));
    let qx = field(field_val(case, "qx"));
    let qy = field(field_val(case, "qy"));
    let mut r = bytes33(field_val(case, "r"));
    let s = bytes33(field_val(case, "s"));
    let q = Point::Affine(qx, qy);
    let g = Point::generator();

    r[32] ^= 1; // flip one bit of r
    let hash = h.to_be_bytes();
    assert!(!verify(&hash, &r, &s, q, g));
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_wrong_key() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let cases = extract_objects(json, "signature_cases");
    let case0 = cases[0];
    let case1 = cases[1];

    let h = field(field_val(case0, "h"));
    // Use case1's public key against case0's signature - a genuine key mismatch.
    let qx = field(field_val(case1, "qx"));
    let qy = field(field_val(case1, "qy"));
    let r = bytes33(field_val(case0, "r"));
    let s = bytes33(field_val(case0, "s"));
    let q = Point::Affine(qx, qy);
    let g = Point::generator();

    let hash = h.to_be_bytes();
    assert!(!verify(&hash, &r, &s, q, g));
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_sign_then_verify_round_trip_for_random_keys() {
    // Independent of the BC vectors: derive Q = -d*G from a locally-chosen d (mirroring
    // crypto_sign's own convention, docs/pseudocode/dstu4145.md), sign, then verify.
    for seed in 1u8..=5 {
        let mut d_bytes = [0u8; 33];
        d_bytes[32] = seed;
        d_bytes[10] = seed.wrapping_mul(7).wrapping_add(1); // avoid a trivially small d
        let mut e_bytes = [0u8; 33];
        e_bytes[32] = seed.wrapping_add(100);
        e_bytes[5] = seed.wrapping_mul(13);

        let d = Scalar::from_be_bytes(&d_bytes);
        let e = Scalar::from_be_bytes(&e_bytes);
        let g = Point::generator();
        let q = g.scalar_multiply(&d.to_be_bytes()).negate();

        let hash = [0x42u8; 32]; // arbitrary fixed "digest"
        let (r, s) = sign(&hash, d, e, g).expect("non-degenerate by construction");
        assert!(verify(&hash, &r, &s, q, g), "seed {seed}");
    }
}

/// `docs/DECISIONS.md` D-186's implementation addendum / `signature257`'s own module doc: proves
/// the general `q.scalar_multiply(&order()) == Infinity` subgroup check actually rejects a real
/// small-subgroup point, not just an on-curve check. `x = 0` is this curve's own order-2 point
/// too (`y^2 + 0*y = 0 + b`, i.e. `y = sqrt(b)`, the same char-2 identity `signature.rs`'s own
/// `t189_public_key_validation::order_two_public_key_forgery_is_rejected` uses for `m=163`) -
/// `sqrt(b) = b^(2^256)` via 256 repeated squarings (Frobenius has order 257 over `GF(2^257)`).
/// Since `curve257::order()` is odd (a prime group order), `n * (order-2 point) == the point
/// itself`, never `Infinity` - so the general check must reject it. The signature below is a
/// forgery that satisfies the unvalidated verify equation (T-278), so this test fails if the
/// subgroup check is removed.
#[cfg_attr(
    miri,
    ignore = "verify's general subgroup check scalar-multiplies the constructed key by curve257::order() - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_order_two_small_subgroup_key() {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    // The top-level "curve": { "a": "0", "b": "..." } object appears before any field/point/
    // signature case in the file, so this is the curve's own `b`, not a multiply-case operand.
    let b = field(extract_all(json, "b")[0]);

    let mut y = b;
    for _ in 0..256 {
        y = y.square();
    }
    assert_eq!(
        y.square(),
        b,
        "constructed y must independently satisfy y^2 = b (order-2 point sanity check)"
    );
    let q = Point::Affine(FieldElement::ZERO, y);
    assert!(
        q.is_on_curve(),
        "constructed order-2 point must itself be on-curve"
    );

    // T-278: a forged even-`r` signature (r*Q == Infinity), not arbitrary r/s - arbitrary r/s
    // would be rejected by the verify equation itself even with the subgroup check removed.
    let hash = [0x11u8; 32];
    let (r, s) = forge_with_s_times_g(&hash, true);
    assert!(
        passes_verify_equation(&hash, &r, &s, q),
        "test setup: the forgery must satisfy the unvalidated verify equation"
    );
    assert!(
        !verify(&hash, &r, &s, q, Point::generator()),
        "an order-2 (small-subgroup) public key must be rejected"
    );
}

// T-278: the m=163 T-189/T-245b attack tests, ported to m=257. Each builds a forgery that would
// verify if `verify` skipped its public-key validation (asserted as a precondition via the public
// `scalar_multiply`/`+` API), then checks that `verify` rejects it.

/// This curve's order-2 point `(0, sqrt(b))` - see `signature257_verify_rejects_order_two_small_subgroup_key`.
fn order_two_point() -> Point {
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let b = field(extract_all(json, "b")[0]);
    let mut y = b;
    for _ in 0..256 {
        y = y.square();
    }
    Point::Affine(FieldElement::ZERO, y)
}

/// `signature257::truncate_255` (private there): the low 255 bits of `y`.
fn truncate_255(y: FieldElement) -> [u8; 33] {
    let mut bytes = y.to_be_bytes();
    bytes[0] = 0;
    bytes[1] &= 0x7F;
    bytes
}

/// Picks `s` so that `r = truncate(h * (s*G).x)` is nonzero and, if `want_even`, even. Then
/// `s*G + r*Q == s*G` whenever `r*Q == Infinity`, so `(r, s)` verifies under `Q` unless `Q` is
/// validated first.
fn forge_with_s_times_g(hash: &[u8], want_even: bool) -> ([u8; 33], [u8; 33]) {
    let g = Point::generator();
    let h = signature257::hash_to_field(hash);
    (1..200u8)
        .find_map(|k| {
            let mut s = [0u8; 33];
            s[32] = k;
            s[20] = k.wrapping_mul(29);
            let Point::Affine(x, _) = g.scalar_multiply(&s) else {
                return None;
            };
            let r = truncate_255(h.multiply(x));
            let usable = r != [0u8; 33] && (!want_even || r[32] & 1 == 0);
            usable.then_some((r, s))
        })
        .expect("about half of all candidates give a nonzero even r")
}

/// The unvalidated verify equation: does `(r, s)` satisfy `r == truncate(h * (s*G + r*Q).x)`?
fn passes_verify_equation(hash: &[u8], r: &[u8; 33], s: &[u8; 33], q: Point) -> bool {
    let h = signature257::hash_to_field(hash);
    match Point::generator().scalar_multiply(s) + q.scalar_multiply(r) {
        Point::Affine(x, _) => &truncate_255(h.multiply(x)) == r,
        Point::Infinity => false,
    }
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_infinity_public_key_forgery() {
    // Infinity has order 1: r*Infinity == Infinity for every r. `n*Infinity == Infinity` passes
    // the subgroup check, so only `is_on_curve` rejects it.
    let hash = [0x22u8; 32];
    let (r, s) = forge_with_s_times_g(&hash, false);
    assert!(
        passes_verify_equation(&hash, &r, &s, Point::Infinity),
        "test setup: the forgery must satisfy the unvalidated verify equation"
    );
    assert!(
        !verify(&hash, &r, &s, Point::Infinity, Point::generator()),
        "a forged signature under the point-at-infinity public key must not verify"
    );
}

#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_off_curve_x_zero_public_key_forgery() {
    // y = ONE does not satisfy y^2 = b, so the point is off the curve, but the ladder still maps
    // it to Infinity for an even r. Either half of the validation rejects it on its own (T-278's
    // split mutation run: `n*(0, 1)` is not Infinity), so this pins "at least one check", not the
    // on-curve check specifically - the Infinity test above is the one that pins that.
    let json = include_str!("vectors/dstu4145/gf2m257_arith.json");
    let b = field(extract_all(json, "b")[0]);
    assert_ne!(
        FieldElement::ONE.square(),
        b,
        "test setup: y must NOT satisfy the curve equation"
    );
    let q = Point::Affine(FieldElement::ZERO, FieldElement::ONE);
    assert!(!q.is_on_curve());

    let hash = [0x33u8; 32];
    let (r, s) = forge_with_s_times_g(&hash, true);
    assert!(
        passes_verify_equation(&hash, &r, &s, q),
        "test setup: the forgery must satisfy the unvalidated verify equation"
    );
    assert!(
        !verify(&hash, &r, &s, q, Point::generator()),
        "a forged signature under an off-curve public key must not verify"
    );
}

// T-245b's m=257 twin: `Q' = Q + T2` is on the curve with x != 0 but has order 2n, so only full
// validation (`n*Q' == O`) rejects it. A genuine signature with an even `r` also verifies under
// `Q'`, since `r*T2 == O`.
#[cfg_attr(
    miri,
    ignore = "sign/verify's 257-iteration scalar_multiply ladder is too slow to interpret under Miri - see docs/TASKS.md T-206"
)]
#[test]
fn signature257_verify_rejects_order_2n_public_key() {
    let g = Point::generator();
    let mut d_bytes = [0u8; 33];
    d_bytes[29..].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    let d = Scalar::from_be_bytes(&d_bytes);
    let q = g.scalar_multiply(&d_bytes).negate();
    let q_2n = q + order_two_point();
    assert!(q_2n.is_on_curve(), "Q + T2 must be a valid curve point");
    assert!(!matches!(q_2n, Point::Affine(x, _) if x == FieldElement::ZERO));

    let hash = [0x44u8; 32];
    let (r, s) = (2..200u8)
        .filter_map(|k| {
            let mut e = [0u8; 33];
            e[32] = k;
            e[12] = k.wrapping_mul(17);
            sign(&hash, d, Scalar::from_be_bytes(&e), g)
        })
        .find(|(r, _)| r[32] & 1 == 0)
        .expect("about half of all signatures have an even r");
    assert!(
        verify(&hash, &r, &s, q, g),
        "the genuine key must still verify"
    );
    assert!(
        passes_verify_equation(&hash, &r, &s, q_2n),
        "test setup: the genuine signature must satisfy the unvalidated equation under Q + T2"
    );
    assert!(
        !verify(&hash, &r, &s, q_2n, g),
        "a public key of order 2n must be rejected"
    );
}

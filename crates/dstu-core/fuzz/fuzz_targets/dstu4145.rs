#![no_main]

use dstu_core::hazmat::dstu4145::{
    curve163, curve257, gf2m163, gf2m257, scalar, scalar257, signature, signature257,
};
use libfuzzer_sys::fuzz_target;

// T-225: `verify` takes q, r, s and the hash from outside and must never panic (invalid points,
// out-of-range r/s, any hash length). Second arm, both curves: a fixed key signs a fuzz-chosen
// hash with a fuzz-chosen ephemeral `e` (two bytes shorter than the field encoding, so below n on
// both curves; zero is skipped), and every signature `sign` returns must verify under `Q = -d*G`.
macro_rules! fuzz_curve {
    ($data:expr, $curve:ident, $field:ident, $scalar:ident, $sig:ident, $len:literal) => {
        if $data.len() >= 4 * $len {
            let (x, rest) = $data.split_at($len);
            let (y, rest) = rest.split_at($len);
            let (r, rest) = rest.split_at($len);
            let (s, hash) = rest.split_at($len);
            let q = $curve::Point::Affine(
                $field::FieldElement::from_be_bytes(x),
                $field::FieldElement::from_be_bytes(y),
            );
            let _ = $sig::verify(
                hash,
                r.try_into().expect("r slice"),
                s.try_into().expect("s slice"),
                q,
                $curve::Point::generator(),
            );
        }

        if $data.len() >= $len - 2 {
            let (e, hash) = $data.split_at($len - 2);
            if e.iter().any(|&b| b != 0) {
                let mut d = [0u8; $len];
                d[$len - 1] = 7;
                let g = $curve::Point::generator();
                let q = g.scalar_multiply(&d).negate();
                if let Some((r, s)) = $sig::sign(
                    hash,
                    $scalar::Scalar::from_be_bytes(&d),
                    $scalar::Scalar::from_be_bytes(e),
                    g,
                ) {
                    assert!($sig::verify(hash, &r, &s, q, g), "own signature rejected");
                }
            }
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_curve!(data, curve163, gf2m163, scalar, signature, 21);
    fuzz_curve!(data, curve257, gf2m257, scalar257, signature257, 33);
});

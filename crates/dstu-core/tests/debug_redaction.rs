//! T-242: the math types that can hold a secret (a DSTU 4145 scalar is the signing key `d` or the
//! nonce `e`; a field element can be `kappa`'s source) never print their value through `Debug`.

use dstu_core::hazmat::dstu4145::{gf2m163, gf2m257, scalar, scalar257};
use dstu_core::hazmat::dstu9041::{fp256, fp512};

#[test]
fn secret_carrying_types_do_not_print_their_value() {
    let bytes = [0x9au8; 21];
    assert_eq!(
        format!("{:?}", scalar::Scalar::from_be_bytes(&bytes)),
        "Scalar(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", scalar257::Scalar::from_be_bytes(&[0x9au8; 33])),
        "Scalar(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", gf2m163::FieldElement::from_be_bytes(&bytes)),
        "FieldElement(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", gf2m257::FieldElement::ONE),
        "FieldElement(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", fp256::FieldElement::from_be_bytes(&[0x09u8; 32])),
        "FieldElement(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", fp512::FieldElement::ONE),
        "FieldElement(<redacted>)"
    );
}

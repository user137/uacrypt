package dstu

import (
	"bytes"
	"testing"
)

// SigningKey257/VerifyingKey257 (crypto_sign257, DSTU 4145 m=257) - m=257 sibling of
// SigningKey/VerifyingKey (T-199/T-204). Correctness (round trip, determinism of the nonce
// derivation), rejection (wrong message/wrong key), misuse (invalid signing key -
// zero/out-of-range, wrong-length key/signature).

func TestSign257VerifyRoundTrips(t *testing.T) {
	signingKey, _ := GenerateSigningKey257()
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()
	message := []byte("a message whose origin and integrity matter")
	sig := signingKey.Sign(message)
	ok, err := verifyingKey.Verify(message, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected the signature to verify")
	}
}

func TestSign257IsDeterministic(t *testing.T) {
	signingKey, _ := GenerateSigningKey257()
	defer signingKey.Close()
	message := []byte("same message every time")
	a := signingKey.Sign(message)
	b := signingKey.Sign(message)
	if !bytes.Equal(a, b) {
		t.Fatal("expected the same signature twice")
	}
}

func TestSign257WrongMessageIsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey257()
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()
	sig := signingKey.Sign([]byte("original message"))
	ok, err := verifyingKey.Verify([]byte("a different message"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}

func TestSign257WrongKeyIsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey257()
	defer signingKey.Close()
	otherSigningKey, _ := GenerateSigningKey257()
	defer otherSigningKey.Close()
	otherVerifyingKey := otherSigningKey.VerifyingKey()
	defer otherVerifyingKey.Close()
	message := []byte("message")
	sig := signingKey.Sign(message)
	ok, err := otherVerifyingKey.Verify(message, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}

func TestZeroSigningKey257IsRejected(t *testing.T) {
	if _, err := SigningKey257FromBytes(make([]byte, Sign257PrivateKeyBytes)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthSigningKey257IsRejected(t *testing.T) {
	if _, err := SigningKey257FromBytes(make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthVerifyingKey257IsRejected(t *testing.T) {
	if _, err := VerifyingKey257FromBytes(make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthSignature257IsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey257()
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()
	if _, err := verifyingKey.Verify([]byte("message"), make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

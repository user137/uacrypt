package dstu

import (
	"bytes"
	"testing"
)

// SigningKey/VerifyingKey (crypto_sign, DSTU 4145) - the official Annex B.1 verify vector is
// already covered by Selftest (TestSelftest); this file covers what that single vector doesn't
// reach: correctness (round trip, determinism of the nonce derivation), rejection (wrong
// message/wrong key), misuse (invalid signing key - zero/out-of-range, wrong-length key/
// signature).

func TestSignVerifyRoundTrips(t *testing.T) {
	signingKey, _ := GenerateSigningKey()
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

func TestSigningIsDeterministic(t *testing.T) {
	signingKey, _ := GenerateSigningKey()
	defer signingKey.Close()
	message := []byte("same message every time")
	a := signingKey.Sign(message)
	b := signingKey.Sign(message)
	if !bytes.Equal(a, b) {
		t.Fatal("expected the same signature twice")
	}
}

func TestSignWrongMessageIsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey()
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

func TestSignWrongKeyIsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey()
	defer signingKey.Close()
	otherSigningKey, _ := GenerateSigningKey()
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

func TestZeroSigningKeyIsRejected(t *testing.T) {
	if _, err := SigningKeyFromBytes(make([]byte, SignPrivateKeyBytes)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthSigningKeyIsRejected(t *testing.T) {
	if _, err := SigningKeyFromBytes(make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthVerifyingKeyIsRejected(t *testing.T) {
	if _, err := VerifyingKeyFromBytes(make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWrongLengthSignatureIsRejected(t *testing.T) {
	signingKey, _ := GenerateSigningKey()
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()
	if _, err := verifyingKey.Verify([]byte("message"), make([]byte, 5)); err == nil {
		t.Fatal("expected an error")
	}
}

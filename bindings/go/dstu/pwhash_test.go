package dstu

import (
	"errors"
	"testing"
)

// Pwhash (crypto_pwhash, Argon2id). Correctness: round trip. Rejection: wrong password, malformed
// hash string. PwhashInteractive throughout so this file stays fast - Sensitive alone takes real
// seconds.

func TestHashVerifyRoundTrips(t *testing.T) {
	password := []byte("correct horse battery staple")
	stored, err := HashPassword(password, PwhashInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(password, stored) {
		t.Fatal("expected the correct password to verify")
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	stored, err := HashPassword([]byte("correct horse battery staple"), PwhashInteractive)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword([]byte("wrong guess"), stored) {
		t.Fatal("expected the wrong password to be rejected")
	}
}

// T-240: the C ABI takes strength as a uint32_t and rejects values outside DSTU_PWHASH_*.
func TestUnknownStrengthIsAnArgumentError(t *testing.T) {
	_, err := HashPassword([]byte("anything"), PwhashStrength(7))
	var argErr *ArgumentError
	if !errors.As(err, &argErr) {
		t.Fatalf("expected *ArgumentError, got %T: %v", err, err)
	}
}

func TestMalformedHashStringIsRejected(t *testing.T) {
	if VerifyPassword([]byte("anything"), "not a real PHC string") {
		t.Fatal("expected a malformed hash to be rejected")
	}
}

package dstu

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// TestPwhashSharedVerifyVectors (T-272/D-222): a crafted hash string returns false instead of
// aborting the process.
func TestPwhashSharedVerifyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "crates", "dstu-core", "tests", "vectors", "pwhash", "verify.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Hash     string `json:"hash"`
			Expect   string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := VerifyPassword([]byte(c.Password), c.Hash); got != (c.Expect == "accept") {
				t.Fatalf("VerifyPassword = %v, want %v", got, c.Expect == "accept")
			}
			if VerifyPassword([]byte(c.Password+"x"), c.Hash) {
				t.Fatal("a wrong password verified")
			}
		})
	}
}

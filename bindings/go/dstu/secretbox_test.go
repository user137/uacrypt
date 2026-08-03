package dstu

import (
	"bytes"
	"testing"
)

// SecretboxKey (crypto_secretbox) - correctness (round trip - no official vector exists for this
// construction, D-51), rejection (tamper/wrong key), misuse (wrong-length key, truncated input).

func TestSecretboxSealOpenRoundTrips(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	plaintext := []byte("a message worth protecting")
	sealed, err := key.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := key.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestSecretboxSealHandlesEmptyMessage(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	sealed, err := key.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := key.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}

func TestSecretboxTamperedCiphertextIsRejected(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	sealed, _ := key.Seal([]byte("message"))
	sealed[len(sealed)-1] ^= 1
	if _, err := key.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretboxTamperedNonceIsRejected(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	sealed, _ := key.Seal([]byte("message"))
	sealed[0] ^= 1
	if _, err := key.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretboxWrongKeyIsRejected(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	otherKey, _ := GenerateSecretboxKey()
	defer otherKey.Close()
	sealed, _ := key.Seal([]byte("message"))
	if _, err := otherKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretboxWrongLengthKeyIsRejected(t *testing.T) {
	if _, err := SecretboxKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretboxTruncatedSealedInputIsRejected(t *testing.T) {
	key, _ := GenerateSecretboxKey()
	defer key.Close()
	if _, err := key.Open([]byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}

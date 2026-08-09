package dstu

import (
	"bytes"
	"testing"
)

// Box512SecretKey/Box512PublicKey (crypto_box512) - l(p)=512 sibling of BoxSecretKey/BoxPublicKey
// (T-193/T-204). No official vector exists for this composite construction (same posture as
// crypto_box) - correctness (round trip), rejection (tampered wire segments, wrong key), misuse
// (wrong-length/invalid key encodings, truncated input).

func TestBox512SealOpenRoundTrips(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	message := []byte("a message for the public key's holder only")
	sealed, err := publicKey.Seal(message)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secretKey.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) {
		t.Fatalf("got %q, want %q", got, message)
	}
}

func TestBox512SealHandlesEmptyMessage(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	sealed, err := publicKey.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secretKey.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}

func TestBox512TwoSealsUseDifferentEphemeralMaterial(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	message := []byte("same message twice")
	a, _ := publicKey.Seal(message)
	b, _ := publicKey.Seal(message)
	if bytes.Equal(a, b) {
		t.Fatal("two seals produced identical output")
	}
}

func TestBox512TamperedCiphertextIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	sealed[len(sealed)-1] ^= 1
	if _, err := secretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox512WrongSecretKeyIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	otherSecretKey, _ := GenerateBox512SecretKey()
	defer otherSecretKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	if _, err := otherSecretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox512WrongLengthSecretKeyIsRejected(t *testing.T) {
	if _, err := Box512SecretKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox512ZeroSecretKeyIsRejected(t *testing.T) {
	if _, err := Box512SecretKeyFromBytes(make([]byte, Box512SecretKeyBytes)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox512WrongLengthPublicKeyIsRejected(t *testing.T) {
	if _, err := Box512PublicKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox512DegeneratePublicKeyXIsRejected(t *testing.T) {
	if _, err := Box512PublicKeyFromBytes(make([]byte, Box512PublicKeyBytes)); err == nil { // x = 0
		t.Fatal("expected an error")
	}
}

func TestBox512TruncatedSealedInputIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox512SecretKey()
	defer secretKey.Close()
	if _, err := secretKey.Open([]byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}

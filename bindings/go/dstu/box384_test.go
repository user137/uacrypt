package dstu

import (
	"bytes"
	"testing"
)

// Box384SecretKey/Box384PublicKey (crypto_box384) - l(p)=384 sibling of BoxSecretKey/BoxPublicKey
// (T-297). No official vector exists for this composite construction (same posture as
// crypto_box) - correctness (round trip), rejection (tampered wire segments, wrong key), misuse
// (wrong-length/invalid key encodings, truncated input).

func TestBox384SealOpenRoundTrips(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
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

func TestBox384SealHandlesEmptyMessage(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
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

// T-265: a multi-record message opens to exactly its own bytes, no trailing padding.
func TestBox384SealHandlesAMultiRecordMessage(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	message := bytes.Repeat([]byte("x"), 20_000)
	sealed, err := publicKey.Seal(message)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secretKey.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("round trip mismatch for a multi-record message")
	}
}

func TestBox384TwoSealsUseDifferentEphemeralMaterial(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
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

func TestBox384TamperedCiphertextIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	sealed[len(sealed)-1] ^= 1
	if _, err := secretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox384WrongSecretKeyIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	otherSecretKey, _ := GenerateBox384SecretKey()
	defer otherSecretKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	if _, err := otherSecretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox384WrongLengthSecretKeyIsRejected(t *testing.T) {
	if _, err := Box384SecretKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox384ZeroSecretKeyIsRejected(t *testing.T) {
	if _, err := Box384SecretKeyFromBytes(make([]byte, Box384SecretKeyBytes)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox384WrongLengthPublicKeyIsRejected(t *testing.T) {
	if _, err := Box384PublicKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBox384DegeneratePublicKeyXIsRejected(t *testing.T) {
	if _, err := Box384PublicKeyFromBytes(make([]byte, Box384PublicKeyBytes)); err == nil { // x = 0
		t.Fatal("expected an error")
	}
}

func TestBox384TruncatedSealedInputIsRejected(t *testing.T) {
	secretKey, _ := GenerateBox384SecretKey()
	defer secretKey.Close()
	if _, err := secretKey.Open([]byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}

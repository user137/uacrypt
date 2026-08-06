package dstu

import (
	"bytes"
	"testing"
)

// BoxSecretKey/BoxPublicKey (crypto_box) - no official vector exists for this composite
// construction (same posture as SecretboxKey, D-51/D-169's own "Provenance" section) -
// correctness (round trip, including a message larger than the 25-byte KEM payload), rejection
// (tampered wire segments, wrong key), misuse (wrong-length/invalid key encodings, truncated
// input).

func TestBoxSealOpenRoundTrips(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
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

func TestBoxSealHandlesEmptyMessage(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
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

func TestBoxSealHandlesMessageLargerThanTheKemPayload(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	message := bytes.Repeat([]byte("x"), 10_000)
	sealed, err := publicKey.Seal(message)
	if err != nil {
		t.Fatal(err)
	}
	got, err := secretKey.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("round trip mismatch for a message larger than the KEM payload")
	}
}

func TestBoxTwoSealsUseDifferentEphemeralMaterial(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
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

func TestBoxTamperedKemPrefixIsRejected(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	sealed[0] ^= 1
	if _, err := secretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxTamperedCiphertextIsRejected(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	sealed[len(sealed)-1] ^= 1
	if _, err := secretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxWrongSecretKeyIsRejected(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
	defer secretKey.Close()
	publicKey := secretKey.PublicKey()
	defer publicKey.Close()
	otherSecretKey, _ := GenerateBoxSecretKey()
	defer otherSecretKey.Close()
	sealed, _ := publicKey.Seal([]byte("message"))
	if _, err := otherSecretKey.Open(sealed); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxWrongLengthSecretKeyIsRejected(t *testing.T) {
	if _, err := BoxSecretKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxZeroSecretKeyIsRejected(t *testing.T) {
	if _, err := BoxSecretKeyFromBytes(make([]byte, BoxSecretKeyBytes)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxWrongLengthPublicKeyIsRejected(t *testing.T) {
	if _, err := BoxPublicKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBoxDegeneratePublicKeyXIsRejected(t *testing.T) {
	if _, err := BoxPublicKeyFromBytes(make([]byte, BoxPublicKeyBytes)); err == nil { // x = 0
		t.Fatal("expected an error")
	}
}

func TestBoxTruncatedSealedInputIsRejected(t *testing.T) {
	secretKey, _ := GenerateBoxSecretKey()
	defer secretKey.Close()
	if _, err := secretKey.Open([]byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}

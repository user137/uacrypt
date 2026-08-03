package dstu

import (
	"bytes"
	"testing"
)

// Auth (crypto_auth) - correctness (round trip), rejection (tampered message, wrong key), misuse
// (wrong-length key/tag).

func TestAuthVerifyRoundTrips(t *testing.T) {
	key, err := GenerateAuthKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	message := []byte("a message both parties want to confirm is unmodified")
	tag := key.Compute(message)
	if err := key.Verify(message, tag); err != nil {
		t.Fatal(err)
	}
}

func TestAuthTamperedMessageIsRejected(t *testing.T) {
	key, err := GenerateAuthKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	tag := key.Compute([]byte("original message"))
	if err := key.Verify([]byte("a different message"), tag); err == nil {
		t.Fatal("expected an error")
	}
}

func TestAuthWrongKeyIsRejected(t *testing.T) {
	key, _ := GenerateAuthKey()
	defer key.Close()
	otherKey, _ := GenerateAuthKey()
	defer otherKey.Close()
	message := []byte("message")
	tag := key.Compute(message)
	if err := otherKey.Verify(message, tag); err == nil {
		t.Fatal("expected an error")
	}
}

func TestAuthWrongLengthKeyIsRejected(t *testing.T) {
	if _, err := AuthKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestAuthWrongLengthTagIsRejected(t *testing.T) {
	key, _ := GenerateAuthKey()
	defer key.Close()
	if err := key.Verify([]byte("message"), make([]byte, 4)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestAuthBytesRoundTrip(t *testing.T) {
	key, _ := GenerateAuthKey()
	defer key.Close()
	restored, err := AuthKeyFromBytes(key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if !bytes.Equal(restored.Bytes(), key.Bytes()) {
		t.Fatal("round-tripped key bytes differ")
	}
}

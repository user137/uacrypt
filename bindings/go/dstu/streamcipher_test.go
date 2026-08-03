package dstu

import (
	"bytes"
	"testing"
)

// StreamCipherKey (crypto_stream, Strumok-256 keystream) - no authentication: no rejection
// category, since Decrypt never fails on tampered input, it silently returns different, wrong
// plaintext instead. Correctness: round trip. Misuse: wrong-length key, truncated input.

func TestStreamCipherEncryptDecryptRoundTrips(t *testing.T) {
	key, _ := GenerateStreamCipherKey()
	defer key.Close()
	sealed, err := key.Encrypt([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := key.Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("message")) {
		t.Fatalf("got %q, want %q", got, "message")
	}
}

func TestStreamCipherTamperingIsNotDetectedButProducesWrongPlaintext(t *testing.T) {
	key, _ := GenerateStreamCipherKey()
	defer key.Close()
	sealed, _ := key.Encrypt([]byte("message"))
	sealed[len(sealed)-1] ^= 1
	garbage, err := key.Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(garbage, []byte("message")) {
		t.Fatal("expected tampered decryption to differ from the original plaintext")
	}
}

func TestStreamCipherWrongLengthKeyIsRejected(t *testing.T) {
	if _, err := StreamCipherKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestStreamCipherTruncatedSealedInputIsRejected(t *testing.T) {
	key, _ := GenerateStreamCipherKey()
	defer key.Close()
	if _, err := key.Decrypt([]byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}

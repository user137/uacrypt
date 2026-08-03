package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// The remaining crypto_* modules, each small enough to share one file: crypto_auth
// (Kupyna-KMAC), crypto_kdf, crypto_generichash (Kupyna-256/512), crypto_stream (Strumok-256,
// unauthenticated), RandomBytes.
func runMisc() error {
	if err := authExample(); err != nil {
		return err
	}
	if err := kdfExample(); err != nil {
		return err
	}
	if err := genericHashExample(); err != nil {
		return err
	}
	if err := streamExample(); err != nil {
		return err
	}
	return randomBytesExample()
}

func authExample() error {
	key, err := dstu.GenerateAuthKey()
	if err != nil {
		return err
	}
	defer key.Close()
	message := []byte("a message both parties want to confirm is unmodified")
	tag := key.Compute(message)
	if err := key.Verify(message, tag); err != nil {
		return err
	}
	fmt.Println("auth: tag verified")
	return nil
}

func kdfExample() error {
	masterKey, err := dstu.GenerateKdfMasterKey()
	if err != nil {
		return err
	}
	defer masterKey.Close()
	context := []byte("encrypt_")
	subkeyA, err := masterKey.DeriveSubkey(0, context)
	if err != nil {
		return err
	}
	subkeyB, err := masterKey.DeriveSubkey(1, context)
	if err != nil {
		return err
	}
	if bytes.Equal(subkeyA, subkeyB) {
		return fmt.Errorf("subkeys should differ")
	}
	fmt.Println("kdf: subkey 0 and subkey 1 differ, as expected")
	return nil
}

func genericHashExample() error {
	message := []byte("hello world")
	oneShot := dstu.GenericHash256(message)
	hasher := dstu.NewKupyna256Hasher()
	defer hasher.Close()
	if err := hasher.Update([]byte("hello ")); err != nil {
		return err
	}
	if err := hasher.Update([]byte("world")); err != nil {
		return err
	}
	streamed, err := hasher.Finalize()
	if err != nil {
		return err
	}
	if !bytes.Equal(streamed, oneShot) {
		return fmt.Errorf("streaming/one-shot mismatch")
	}
	fmt.Printf("generichash: kupyna256(\"hello world\") = %s\n", hex.EncodeToString(oneShot))
	return nil
}

func streamExample() error {
	key, err := dstu.GenerateStreamCipherKey()
	if err != nil {
		return err
	}
	defer key.Close()
	sealed, err := key.Encrypt([]byte("a message"))
	if err != nil {
		return err
	}
	plaintext, err := key.Decrypt(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(plaintext, []byte("a message")) {
		return fmt.Errorf("round trip failed")
	}
	fmt.Println("stream: round-tripped (note: unauthenticated, no tamper detection)")
	return nil
}

func randomBytesExample() error {
	a, err := dstu.RandomBytes(16)
	if err != nil {
		return err
	}
	b, err := dstu.RandomBytes(16)
	if err != nil {
		return err
	}
	if bytes.Equal(a, b) {
		return fmt.Errorf("two independent draws should differ")
	}
	fmt.Printf("randombytes: two independent 16-byte draws, e.g. %s\n", hex.EncodeToString(a))
	return nil
}

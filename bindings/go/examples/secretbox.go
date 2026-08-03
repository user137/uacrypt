package main

import (
	"bytes"
	"fmt"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// crypto_secretbox: seal/open a single message with a symmetric key.
func runSecretbox() error {
	key, err := dstu.GenerateSecretboxKey()
	if err != nil {
		return err
	}
	defer key.Close()

	plaintext := []byte("a message worth protecting")
	sealed, err := key.Seal(plaintext)
	if err != nil {
		return err
	}
	opened, err := key.Open(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(opened, plaintext) {
		return fmt.Errorf("round trip failed")
	}
	fmt.Printf("sealed %d bytes -> %d bytes, round-tripped OK\n", len(opened), len(sealed))

	sealed[len(sealed)-1] ^= 1
	if _, err := key.Open(sealed); err != nil {
		fmt.Println("tampered ciphertext correctly rejected")
	}
	return nil
}

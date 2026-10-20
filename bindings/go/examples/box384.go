package main

import (
	"bytes"
	"fmt"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// crypto_box384 (l(p)=384 sibling of crypto_box, T-297): generate a keypair, seal a message
// to the public key, open it with the secret key.
func runBox384() error {
	secretKey, err := dstu.GenerateBox384SecretKey()
	if err != nil {
		return err
	}
	defer secretKey.Close()
	publicKey := secretKey.PublicKey() // safe to share/publish
	defer publicKey.Close()

	message := []byte("a message for the public key's holder only")
	sealed, err := publicKey.Seal(message)
	if err != nil {
		return err
	}
	opened, err := secretKey.Open(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(opened, message) {
		return fmt.Errorf("round trip failed")
	}
	fmt.Printf("sealed %d bytes -> %d bytes, round-tripped OK\n", len(opened), len(sealed))

	sealed[len(sealed)-1] ^= 1
	if _, err := secretKey.Open(sealed); err != nil {
		fmt.Println("tampered ciphertext correctly rejected")
	}
	return nil
}
